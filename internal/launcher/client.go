package launcher

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"syscall"
	"time"

	"nginxpanel/internal/panelruntime"
	"nginxpanel/internal/secure"
)

type Client struct {
	DataDir string
	direct  bool
}

var ErrOperationNotFound = errors.New("当前 launcher 启动中没有原操作记录")

// The connection binds a daemon container generation, its actual PID 1 and
// executable inode. Response data cannot supply or replace this evidence.
type peerProof struct {
	container  panelruntime.DockerInstance
	executable os.FileInfo
}

func verifyPeer(ctx context.Context, c *net.UnixConn, d panelruntime.Deployment) (peerProof, error) {
	var zero peerProof
	cred, err := credentials(c)
	if err != nil {
		return zero, err
	}
	if cred == nil || int(cred.Uid) != d.UID || cred.Pid <= 1 {
		return zero, errors.New("launcher 响应进程身份不匹配")
	}
	instance, err := panelruntime.InspectDocker(ctx, d, int(cred.Pid))
	if err != nil {
		return zero, err
	}
	base := "/proc/" + strconv.Itoa(int(cred.Pid))
	if err = verifyPeerProcess(base, int(cred.Pid), d); err != nil {
		return zero, err
	}
	exe, err := os.Open(base + "/exe")
	if err != nil {
		return zero, err
	}
	defer exe.Close()
	info, err := exe.Stat()
	if err != nil {
		return zero, err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || st.Uid != 0 || st.Gid != 0 || info.Mode().Perm() != 0555 || info.Size() <= 0 || info.Size() > panelruntime.BinaryLimit {
		return zero, errors.New("launcher 执行文件的归属或类型无效")
	}
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(exe, panelruntime.BinaryLimit+1))
	if err != nil {
		return zero, err
	}
	if n != info.Size() || !secure.RootFileUnchanged(exe, info) || hex.EncodeToString(h.Sum(nil)) != d.LauncherSHA256 {
		return zero, errors.New("launcher 执行文件与宿主机批准不匹配")
	}
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	return peerProof{container: instance, executable: info}, nil
}

func (p peerProof) confirm(ctx context.Context, d panelruntime.Deployment) error {
	if p.executable == nil {
		return errors.New("launcher 连接缺少宿主机核对依据")
	}
	after, err := panelruntime.InspectDocker(ctx, d, p.container.PID)
	if err != nil {
		return err
	}
	if after != p.container {
		return errors.New("面板容器在 launcher 请求期间重启或重建")
	}
	base := "/proc/" + strconv.Itoa(p.container.PID)
	if err = verifyPeerProcess(base, p.container.PID, d); err != nil {
		return err
	}
	info, err := os.Stat(base + "/exe")
	if err != nil {
		return err
	}
	beforeStat, beforeOK := p.executable.Sys().(*syscall.Stat_t)
	afterStat, afterOK := info.Sys().(*syscall.Stat_t)
	if !beforeOK || !afterOK || !os.SameFile(p.executable, info) || p.executable.Mode() != info.Mode() || p.executable.Size() != info.Size() || beforeStat.Uid != afterStat.Uid || beforeStat.Gid != afterStat.Gid || beforeStat.Mtim != afterStat.Mtim || beforeStat.Ctim != afterStat.Ctim {
		return errors.New("launcher 实际程序在请求期间变化")
	}
	return ctx.Err()
}

func (c Client) call(ctx context.Context, method, path string, in, out any) error {
	return c.callPeer(ctx, method, path, in, out, nil)
}
func (c Client) callPeer(ctx context.Context, method, path string, in, out any, peerPID *int) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if os.Geteuid() != 0 {
		return errors.New("launcher 控制仅允许宿主机 root")
	}
	d, err := panelruntime.ReadDeployment(c.DataDir)
	if err != nil {
		return err
	}
	if d.Mode != "docker" {
		return errors.New("launcher 控制需要容器面板绑定")
	}
	var proof peerProof
	// Transport may detach its dial context from request cancellation. Use the
	// bounded caller context for both the socket and host-side Docker checks.
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true, DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
		conn, err := (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "unix", Socket(c.DataDir))
		if err != nil {
			return nil, err
		}
		unixConn, ok := conn.(*net.UnixConn)
		if !ok {
			conn.Close()
			return nil, errors.New("launcher 连接不是 Unix Socket")
		}
		checked, err := verifyPeer(ctx, unixConn, d)
		if err != nil {
			conn.Close()
			return nil, err
		}
		proof = checked
		return conn, nil
	}}
	defer transport.CloseIdleConnections()
	var body io.Reader
	if in != nil {
		raw, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://launcher"+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("launcher 不允许重定向") }}
	response, err := client.Do(req)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, 16385))
	if err != nil || len(raw) > 16384 {
		return errors.New("launcher 响应超过限制")
	}
	if err = proof.confirm(ctx, d); err != nil {
		return err
	}
	if peerPID != nil {
		*peerPID = proof.container.PID
	}
	var envelope struct {
		Code      string          `json:"code"`
		Message   string          `json:"message"`
		Data      json.RawMessage `json:"data"`
		RequestID string          `json:"request_id"`
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if dec.Decode(&envelope) != nil || dec.Decode(new(any)) != io.EOF || !idValue.MatchString(envelope.RequestID) {
		return errors.New("launcher 响应格式无效")
	}
	if response.StatusCode != 200 && response.StatusCode != 202 || envelope.Code != "OK" {
		if response.StatusCode == http.StatusNotFound && envelope.Code == "NOT_FOUND" {
			return ErrOperationNotFound
		}
		return fmt.Errorf("launcher 拒绝请求：HTTP %d，%s", response.StatusCode, envelope.Code)
	}
	dec = json.NewDecoder(bytes.NewReader(envelope.Data))
	dec.DisallowUnknownFields()
	if dec.Decode(out) != nil || dec.Decode(new(any)) != io.EOF {
		return errors.New("launcher 响应数据无效")
	}
	return nil
}
func (c Client) Status(ctx context.Context) (Status, error) {
	out, _, err := c.StatusPeer(ctx)
	return out, err
}

// StatusPeer returns the authenticated launcher's host PID for checking its
// child. Launcher response data never substitutes for host peer evidence.
func (c Client) StatusPeer(ctx context.Context) (Status, int, error) {
	if !c.direct {
		if s, use, err := c.bridgeProgram(); err != nil {
			return Status{}, 0, err
		} else if use {
			r, err := c.bridge(ctx, s, bridgeRequest{Action: "status"})
			if err != nil {
				return Status{}, 0, err
			}
			return *r.Status, r.PeerPID, nil
		}
	}
	var out Status
	var peer int
	err := c.callPeer(ctx, http.MethodGet, "/v1/status", nil, &out, &peer)
	if err == nil && !bridgeStatusValid(out, Protocol) {
		err = errors.New("launcher 状态身份无效")
	}
	return out, peer, err
}
func (c Client) Control(ctx context.Context, in Request) (Operation, error) {
	if !c.direct {
		if s, use, err := c.bridgeProgram(); err != nil {
			return Operation{}, err
		} else if use {
			if !validRequestAt(in, s.Release.LauncherVersion) {
				return Operation{}, errors.New("launcher 桥接请求身份无效")
			}
			r, err := c.bridge(ctx, s, bridgeRequest{Action: "control", Request: &in})
			if err != nil {
				return Operation{}, err
			}
			return *r.Operation, nil
		}
	}
	var out Operation
	if !validRequest(in) {
		return out, errors.New("launcher 控制请求无效")
	}
	err := c.call(ctx, http.MethodPost, "/v1/control", in, &out)
	if err == nil && (out.Request != in || !validOperation(out)) {
		err = errors.New("launcher 操作回执不匹配")
	}
	return out, err
}
func (c Client) Operation(ctx context.Context, id string) (Operation, error) {
	if !c.direct {
		if s, use, err := c.bridgeProgram(); err != nil {
			return Operation{}, err
		} else if use {
			if !idValue.MatchString(id) {
				return Operation{}, errors.New("launcher 操作标识无效")
			}
			r, err := c.bridge(ctx, s, bridgeRequest{Action: "operation", OperationID: id})
			if err != nil {
				return Operation{}, err
			}
			return *r.Operation, nil
		}
	}
	var out Operation
	if !idValue.MatchString(id) {
		return out, errors.New("launcher 操作标识无效")
	}
	err := c.call(ctx, http.MethodGet, "/v1/operations/"+id, nil, &out)
	if err == nil && (out.Request.OperationID != id || !validOperation(out)) {
		err = errors.New("launcher 操作回执不匹配")
	}
	return out, err
}
