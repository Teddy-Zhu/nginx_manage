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
	"strings"
	"syscall"
	"time"

	"nginxpanel/internal/panelruntime"
	"nginxpanel/internal/secure"
)

type Client struct{ DataDir string }

// A same-UID serve process can replace a writable socket inode. SO_PEERCRED,
// namespace PID 1 and the immutable launcher digest authenticate the responder.
func verifyPeer(c *net.UnixConn, d panelruntime.Deployment) error {
	cred, err := credentials(c)
	if err != nil {
		return err
	}
	if cred == nil || int(cred.Uid) != d.UID || cred.Pid <= 1 {
		return errors.New("launcher 响应进程身份不匹配")
	}
	base := "/proc/" + strconv.Itoa(int(cred.Pid))
	f, err := os.Open(base + "/status")
	if err != nil {
		return err
	}
	raw, err := io.ReadAll(io.LimitReader(f, 16385))
	f.Close()
	if err != nil || len(raw) > 16384 {
		return errors.New("无法核对 launcher PID 命名空间")
	}
	init := false
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 3 && fields[0] == "NSpid:" && fields[1] == strconv.Itoa(int(cred.Pid)) && fields[len(fields)-1] == "1" {
			init = true
		}
	}
	if !init {
		return errors.New("launcher 必须是独立容器 PID 1")
	}
	exe, err := os.Open(base + "/exe")
	if err != nil {
		return err
	}
	defer exe.Close()
	info, err := exe.Stat()
	if err != nil {
		return err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || st.Uid != 0 || info.Mode().Perm()&0022 != 0 || info.Size() > panelruntime.BinaryLimit {
		return errors.New("launcher 执行文件的归属或类型无效")
	}
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(exe, panelruntime.BinaryLimit+1))
	if err != nil {
		return err
	}
	if n != info.Size() || !secure.RootFileUnchanged(exe, info) || hex.EncodeToString(h.Sum(nil)) != d.LauncherSHA256 {
		return errors.New("launcher 执行文件与宿主机批准不匹配")
	}
	return nil
}
func (c Client) call(ctx context.Context, method, path string, in, out any) error {
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
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		conn, err := (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "unix", Socket(c.DataDir))
		if err != nil {
			return nil, err
		}
		unixConn, ok := conn.(*net.UnixConn)
		if !ok {
			conn.Close()
			return nil, errors.New("launcher 连接不是 Unix Socket")
		}
		if err = verifyPeer(unixConn, d); err != nil {
			conn.Close()
			return nil, err
		}
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
	var out Status
	err := c.call(ctx, http.MethodGet, "/v1/status", nil, &out)
	if err == nil && (out.Protocol != Protocol || !idValue.MatchString(out.BootID) || out.ReleaseID != "" && !releaseValue.MatchString(out.ReleaseID) || out.Operation != nil && (!validOperation(*out.Operation) || out.Operation.Request.BootID != out.BootID)) {
		err = errors.New("launcher 状态身份无效")
	}
	return out, err
}
func (c Client) Restart(ctx context.Context, in Request) (Operation, error) {
	var out Operation
	err := c.call(ctx, http.MethodPost, "/v1/restart", in, &out)
	if err == nil && (out.Request != in || !validOperation(out)) {
		err = errors.New("launcher 操作回执不匹配")
	}
	return out, err
}
func (c Client) Operation(ctx context.Context, id string) (Operation, error) {
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
