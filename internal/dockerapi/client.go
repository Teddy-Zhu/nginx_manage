// Package dockerapi provides the fixed, root-only local Docker transport.
package dockerapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"nginxpanel/internal/secure"
)

// The daemon endpoint is a host installation invariant. DOCKER_HOST, contexts,
// CLI plugins and a caller-selected URL are deliberately not consulted.
const dockerSocket = "/run/docker.sock"
const Version = "1.47"
const apiPrefix = "/v" + Version

type Client struct {
	http      *http.Client
	transport *http.Transport
}

// StatusError distinguishes an authoritative absence from a lost response.
type StatusError struct{ StatusCode int }

func (e *StatusError) Error() string { return fmt.Sprintf("Docker IPC 返回 HTTP %d", e.StatusCode) }

func New() (*Client, error) {
	if os.Geteuid() != 0 {
		return nil, errors.New("Docker 接入仅允许宿主机 root")
	}
	if err := secure.RootDirectory("/run", 0755); err != nil {
		return nil, err
	}
	info, err := os.Lstat(dockerSocket)
	if err != nil {
		return nil, err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || info.Mode()&os.ModeSocket == 0 || st.Uid != 0 || info.Mode().Perm()&0007 != 0 {
		return nil, errors.New("Docker Socket 归属或权限无效")
	}
	t := &http.Transport{Proxy: nil, DisableKeepAlives: true, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		c, err := (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "unix", dockerSocket)
		if err != nil {
			return nil, err
		}
		raw, err := c.(*net.UnixConn).SyscallConn()
		if err == nil {
			var check error
			err = raw.Control(func(fd uintptr) {
				peer, e := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
				if e != nil {
					check = e
				} else if peer.Uid != 0 {
					check = errors.New("Docker 对端并非宿主机 root")
				}
			})
			if err == nil {
				err = check
			}
		}
		if err != nil {
			c.Close()
			return nil, err
		}
		deadline := time.Now().Add(20 * time.Second)
		if requested, ok := ctx.Deadline(); ok && requested.Before(deadline) {
			deadline = requested
		}
		if err = c.SetDeadline(deadline); err != nil {
			c.Close()
			return nil, err
		}
		return c, nil
	}}
	return &Client{&http.Client{Transport: t, Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("Docker IPC 不允许重定向") }}, t}, nil
}
func (d *Client) Close() { d.transport.CloseIdleConnections() }
func (d *Client) Request(ctx context.Context, method, path string, input any) (*http.Response, error) {
	var body io.Reader
	if input != nil {
		raw, err := json.Marshal(input)
		if err != nil {
			return nil, err
		}
		body = bytes.NewReader(raw)
	}
	r, err := http.NewRequestWithContext(ctx, method, "http://docker"+apiPrefix+path, body)
	if err != nil {
		return nil, err
	}
	if input != nil {
		r.Header.Set("Content-Type", "application/json")
	}
	upgrade := strings.HasPrefix(path, "/exec/") && strings.HasSuffix(path, "/start")
	if upgrade {
		r.Header.Set("Connection", "Upgrade")
		r.Header.Set("Upgrade", "tcp")
	}
	resp, err := d.http.Do(r)
	if err != nil {
		return nil, err
	}
	if (resp.StatusCode < 200 || resp.StatusCode >= 300) && !(upgrade && resp.StatusCode == http.StatusSwitchingProtocols) {
		resp.Body.Close()
		return nil, &StatusError{StatusCode: resp.StatusCode}
	}
	return resp, nil
}
func (d *Client) JSON(ctx context.Context, method, path string, input, out any) error {
	resp, err := d.Request(ctx, method, path, input)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, (256<<10)+1))
	if err != nil {
		return err
	}
	if len(raw) > 256<<10 {
		return errors.New("Docker IPC 响应超过预算")
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(raw, out)
}
