package panelready

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"nginxpanel/internal/panelruntime"
)

var ErrNotReady = errors.New("面板尚未就绪")

func procRead(name string) ([]byte, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, 16385))
	if err != nil {
		return nil, err
	}
	if len(raw) > 16384 {
		return nil, errors.New("readiness 对端进程信息超出上限")
	}
	return raw, nil
}

func verifyPeer(c *net.UnixConn, s panelruntime.Snapshot, pid, parentPID int) (int, error) {
	cred, err := credentials(c)
	if err != nil {
		return 0, err
	}
	if cred == nil || int(cred.Uid) != s.Deployment.UID || int(cred.Gid) != s.Deployment.GID || cred.Pid <= 1 || parentPID == 0 && int(cred.Pid) != pid {
		return 0, errors.New("readiness 对端不属于原面板进程")
	}
	base := "/proc/" + strconv.Itoa(int(cred.Pid))
	actual, err := os.Stat(base + "/exe")
	if err != nil {
		return 0, err
	}
	expected, err := os.Stat(filepath.Join(s.Directory, "nginxpanel"))
	if err != nil {
		return 0, err
	}
	if !os.SameFile(actual, expected) {
		return 0, errors.New("readiness 对端未执行当前受信程序")
	}
	if parentPID != 0 {
		stat, err := procRead(base + "/stat")
		if err != nil {
			return 0, err
		}
		end := strings.LastIndex(string(stat), ") ")
		if end < 0 {
			return 0, errors.New("readiness 对端进程状态格式无效")
		}
		fields := strings.Fields(string(stat[end+2:]))
		if len(fields) < 2 || fields[1] != strconv.Itoa(parentPID) {
			return 0, errors.New("readiness 对端不是原 launcher 的直接子进程")
		}
		status, err := procRead(base + "/status")
		if err != nil {
			return 0, err
		}
		matched := false
		for _, line := range strings.Split(string(status), "\n") {
			fields := strings.Fields(line)
			if len(fields) >= 3 && fields[0] == "NSpid:" && fields[1] == strconv.Itoa(int(cred.Pid)) && fields[len(fields)-1] == strconv.Itoa(pid) {
				matched = true
			}
		}
		if !matched {
			return 0, errors.New("readiness 对端容器 PID 与原启动实例不一致")
		}
		childNS, err := os.Stat(base + "/ns/pid")
		if err != nil {
			return 0, err
		}
		parentNS, err := os.Stat("/proc/" + strconv.Itoa(parentPID) + "/ns/pid")
		if err != nil {
			return 0, err
		}
		if !os.SameFile(childNS, parentNS) {
			return 0, errors.New("readiness 与 launcher 不在同一 PID 命名空间")
		}
	}
	return int(cred.Pid), nil
}

func decode(raw []byte, out any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(out); err != nil {
		return err
	}
	if d.Decode(new(any)) != io.EOF {
		return errors.New("readiness 响应包含额外数据")
	}
	return nil
}

// Read authenticates the actual socket responder. A same-UID process cannot
// substitute another socket and claim the original service instance.
func Read(ctx context.Context, s panelruntime.Snapshot, pid, parentPID int) (Status, int, error) {
	var out Status
	peer := 0
	if os.Geteuid() != 0 || pid <= 1 || s.Deployment.Mode == "native" && parentPID != 0 || s.Deployment.Mode == "docker" && parentPID <= 1 {
		return out, peer, errors.New("readiness 检查需要 root 和原进程身份")
	}
	t := &http.Transport{Proxy: nil, DisableKeepAlives: true, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		c, err := (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "unix", Socket(s.Deployment.DataDir))
		if err != nil {
			return nil, err
		}
		u, ok := c.(*net.UnixConn)
		if !ok {
			c.Close()
			return nil, errors.New("readiness 连接不是 Unix Socket")
		}
		peer, err = verifyPeer(u, s, pid, parentPID)
		if err != nil {
			c.Close()
			return nil, err
		}
		return c, nil
	}}
	defer t.CloseIdleConnections()
	c := &http.Client{Transport: t, Timeout: 6 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("readiness 不接受重定向") }}
	r, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://readiness/v1/readiness", nil)
	if err != nil {
		return out, peer, err
	}
	response, err := c.Do(r)
	if err != nil {
		return out, peer, err
	}
	defer response.Body.Close()
	media, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		return out, peer, errors.New("readiness 响应类型无效")
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, ResponseLimit+1))
	if err != nil {
		return out, peer, err
	}
	if len(raw) > ResponseLimit {
		return out, peer, errors.New("readiness 响应超过上限")
	}
	var envelope Envelope
	if err = decode(raw, &envelope); err != nil {
		return out, peer, err
	}
	if !idValue.MatchString(envelope.RequestID) || response.Header.Get("X-Request-ID") != envelope.RequestID || !idValue.MatchString(envelope.NodeID) {
		return out, peer, errors.New("readiness 响应身份无效")
	}
	if response.StatusCode == http.StatusServiceUnavailable && envelope.Code == "NOT_READY" && envelope.Data == nil {
		return out, peer, fmt.Errorf("%w: %s", ErrNotReady, envelope.Message)
	}
	if response.StatusCode != http.StatusOK || envelope.Code != "OK" || envelope.Data == nil {
		return out, peer, errors.New("readiness 响应未确认成功")
	}
	out = *envelope.Data
	if err = out.Validate(); err != nil {
		return out, peer, err
	}
	if out.PID != pid || out.NodeID != envelope.NodeID || out.ReleaseID != s.Release.ID || out.Mode != s.Deployment.Mode || out.Version != s.Release.Version {
		return out, peer, errors.New("readiness 不属于原受信发布和进程")
	}
	return out, peer, nil
}
