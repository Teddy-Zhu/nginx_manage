package launcher

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	"nginxpanel/internal/panelruntime"
	"nginxpanel/internal/secure"
)

// This is a local, bounded deployment journal contract, not a launcher wire
// codec. Only the program authenticated by the selected image speaks its IPC.
const bridgeSchema = 1

var ErrUnavailable = errors.New("launcher 尚未就绪")

type bridgeRequest struct {
	Schema        int      `json:"schema"`
	RequestID     string   `json:"request_id"`
	BindingSHA256 string   `json:"binding_sha256"`
	Action        string   `json:"action"`
	OperationID   string   `json:"operation_id"`
	Request       *Request `json:"request"`
}
type bridgeResult struct {
	Schema        int        `json:"schema"`
	BindingSHA256 string     `json:"binding_sha256"`
	Protocol      int        `json:"protocol"`
	PeerPID       int        `json:"peer_pid"`
	Status        *Status    `json:"status"`
	Operation     *Operation `json:"operation"`
}
type bridgeEnvelope struct {
	Code      string       `json:"code"`
	Message   string       `json:"message"`
	Data      bridgeResult `json:"data"`
	RequestID string       `json:"request_id"`
}
type bridgeOutput struct{ raw []byte }
type bridgeCapability struct {
	Schema       int    `json:"schema"`
	Protocol     int    `json:"protocol"`
	BinarySHA256 string `json:"binary_sha256"`
}

func DescribeBridge(output io.Writer) error {
	if os.Geteuid() != 0 {
		return errors.New("launcher 桥接能力查询需要 root")
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	hash, err := secure.HashRootFile(self, panelruntime.BinaryLimit)
	if err != nil {
		return err
	}
	return json.NewEncoder(output).Encode(bridgeCapability{Schema: bridgeSchema, Protocol: Protocol, BinarySHA256: hash})
}

// CheckBridgeProgram executes only an already staged, signed root-owned binary.
// It confirms the stable bridge contract before replacing the running image.
func CheckBridgeProgram(ctx context.Context, s panelruntime.StagedRelease) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	binary := filepath.Join(s.Directory, "nginxpanel")
	hash, err := secure.HashRootFile(binary, panelruntime.BinaryLimit)
	if err != nil || hash != s.Release.BinarySHA256 {
		return errors.Join(err, errors.New("launcher 桥接目标程序变化"))
	}
	cmd := exec.CommandContext(ctx, binary, "launcher-bridge", "--describe")
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C"}
	var out, diagnostic bridgeOutput
	cmd.Stdout, cmd.Stderr = &out, &diagnostic
	if err = cmd.Run(); err != nil {
		return errors.Join(ctx.Err(), errors.New("目标程序未提供所需 launcher 桥接契约"), err)
	}
	var capability bridgeCapability
	if err = bridgeDecode(out.raw, &capability); err != nil {
		return err
	}
	if capability.Schema != bridgeSchema || capability.Protocol != s.Release.LauncherVersion || capability.BinarySHA256 != s.Release.BinarySHA256 {
		return errors.New("目标 launcher 桥接能力与签名程序不一致")
	}
	after, err := secure.HashRootFile(binary, panelruntime.BinaryLimit)
	if err != nil || after != hash {
		return errors.Join(err, errors.New("launcher 桥接目标在检查期间变化"))
	}
	return nil
}
func (b *bridgeOutput) Write(p []byte) (int, error) {
	if len(b.raw)+len(p) > 16<<10 {
		return 0, errors.New("launcher 桥接输出超过限制")
	}
	b.raw = append(b.raw, p...)
	return len(p), nil
}
func bridgeDecode(raw []byte, out any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(out); err != nil {
		return err
	}
	if d.Decode(new(any)) != io.EOF {
		return errors.New("launcher 桥接包含额外数据")
	}
	return nil
}
func bindingHash(d panelruntime.Deployment) string {
	raw, _ := json.Marshal(d)
	return secure.Hash(raw)
}
func (c Client) bridgeProgram() (panelruntime.Snapshot, bool, error) {
	if os.Geteuid() != 0 {
		return panelruntime.Snapshot{}, false, errors.New("launcher 控制仅允许宿主机 root")
	}
	s, err := panelruntime.LauncherRelease(c.DataDir)
	return s, err == nil && s.Release.LauncherVersion != Protocol, err
}
func bridgeStatusValid(s Status, version int) bool {
	if s.Protocol != version || !idValue.MatchString(s.BootID) || s.ReleaseID != "" && !releaseValue.MatchString(s.ReleaseID) || s.PID < 0 || s.PID == 1 || s.PID > 0 && !idValue.MatchString(s.InstanceID) || s.PID == 0 && s.InstanceID != "" || s.Operation != nil && (!validOperationAt(*s.Operation, version) || s.Operation.Request.BootID != s.BootID) {
		return false
	}
	switch s.State {
	case "running", "stopped", "starting", "stopping", "failed":
		return true
	}
	return false
}
func (c Client) bridge(ctx context.Context, s panelruntime.Snapshot, in bridgeRequest) (bridgeResult, error) {
	var zero bridgeResult
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	in.Schema, in.RequestID, in.BindingSHA256 = bridgeSchema, secure.ID(), bindingHash(s.Deployment)
	raw, err := json.Marshal(in)
	if err != nil {
		return zero, err
	}
	cmd := exec.CommandContext(ctx, filepath.Join(s.Directory, "nginxpanel"), "launcher-bridge", "--data-dir", c.DataDir)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C"}
	cmd.Stdin = bytes.NewReader(raw)
	var out, diagnostic bridgeOutput
	cmd.Stdout, cmd.Stderr = &out, &diagnostic
	if err = cmd.Run(); err != nil {
		return zero, errors.Join(ctx.Err(), errors.New("已批准的 launcher 桥接程序执行失败"), err)
	}
	after, err := panelruntime.LauncherRelease(c.DataDir)
	if err != nil {
		return zero, err
	}
	if after.Deployment != s.Deployment || after.Release.ID != s.Release.ID {
		return zero, errors.New("launcher 桥接期间部署绑定变化")
	}
	var response bridgeEnvelope
	if err = bridgeDecode(out.raw, &response); err != nil {
		return zero, err
	}
	r := response.Data
	if response.RequestID != in.RequestID || r.Schema != bridgeSchema || r.BindingSHA256 != in.BindingSHA256 || r.Protocol != s.Release.LauncherVersion || len(response.Message) > 1024 {
		return zero, errors.New("launcher 桥接回执身份无效")
	}
	if response.Code != "OK" {
		switch response.Code {
		case "NOT_FOUND":
			return zero, ErrOperationNotFound
		case "UNAVAILABLE":
			return zero, ErrUnavailable
		}
		return zero, errors.New("launcher 桥接拒绝请求：" + response.Message)
	}
	if in.Action == "status" {
		if r.Status == nil || r.Operation != nil || r.PeerPID <= 1 || !bridgeStatusValid(*r.Status, r.Protocol) {
			return zero, errors.New("launcher 桥接状态无效")
		}
		peer, err := panelruntime.InspectDocker(ctx, s.Deployment, r.PeerPID)
		if err != nil || peer.PID != r.PeerPID {
			return zero, errors.Join(err, errors.New("launcher 桥接进程与实际容器不一致"))
		}
	} else if r.Status != nil || r.PeerPID != 0 || r.Operation == nil || !validOperationAt(*r.Operation, r.Protocol) || in.Action == "control" && r.Operation.Request != *in.Request || in.Action == "operation" && r.Operation.Request.OperationID != in.OperationID {
		return zero, errors.New("launcher 桥接操作回执无效")
	}
	return r, nil
}

// RunBridge neither opens the application database nor mutates a deployment. Control is
// limited to the same root-only, generation-bound launcher operations as IPC.
func RunBridge(ctx context.Context, data string, input io.Reader, output io.Writer) error {
	s, err := panelruntime.LauncherRelease(data)
	if err != nil {
		return err
	}
	if os.Geteuid() != 0 || s.Release.LauncherVersion != Protocol {
		return errors.New("launcher 桥接程序协议与绑定不一致")
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	hash, err := secure.HashRootFile(self, panelruntime.BinaryLimit)
	if err != nil || hash != s.Deployment.LauncherSHA256 {
		return errors.Join(err, errors.New("launcher 桥接执行程序与批准镜像不一致"))
	}
	raw, err := io.ReadAll(io.LimitReader(input, 4097))
	if err != nil || len(raw) > 4096 {
		return errors.Join(err, errors.New("launcher 桥接请求超过限制"))
	}
	var in bridgeRequest
	if err = bridgeDecode(raw, &in); err != nil {
		return err
	}
	if in.Schema != bridgeSchema || !idValue.MatchString(in.RequestID) || in.BindingSHA256 != bindingHash(s.Deployment) {
		return errors.New("launcher 桥接请求绑定无效")
	}
	out := bridgeEnvelope{Code: "OK", RequestID: in.RequestID, Data: bridgeResult{Schema: bridgeSchema, BindingSHA256: in.BindingSHA256, Protocol: Protocol}}
	c := Client{DataDir: data, direct: true}
	switch in.Action {
	case "status":
		if in.Request != nil || in.OperationID != "" {
			return errors.New("launcher 状态请求包含额外操作")
		}
		var status Status
		status, out.Data.PeerPID, err = c.StatusPeer(ctx)
		out.Data.Status = &status
	case "control":
		if in.Request == nil || in.OperationID != "" || !validRequest(*in.Request) {
			return errors.New("launcher 控制桥接请求无效")
		}
		var op Operation
		op, err = c.Control(ctx, *in.Request)
		out.Data.Operation = &op
	case "operation":
		if in.Request != nil || !idValue.MatchString(in.OperationID) {
			return errors.New("launcher 操作查询桥接请求无效")
		}
		var op Operation
		op, err = c.Operation(ctx, in.OperationID)
		out.Data.Operation = &op
	default:
		return errors.New("launcher 桥接不支持此动作")
	}
	if err != nil {
		out.Code, out.Message = "REJECTED", "launcher 操作核对失败"
		if len(err.Error()) <= 1024 {
			out.Message = err.Error()
		}
		if errors.Is(err, ErrOperationNotFound) {
			out.Code = "NOT_FOUND"
		}
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, context.DeadlineExceeded) {
			out.Code = "UNAVAILABLE"
		}
	}
	after, readErr := panelruntime.ReadDeployment(data)
	if readErr != nil || after != s.Deployment {
		return errors.Join(readErr, errors.New("launcher 桥接期间绑定变化"))
	}
	return json.NewEncoder(output).Encode(out)
}
