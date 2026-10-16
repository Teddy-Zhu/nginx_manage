package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"nginxpanel/internal/fail2ban"
	"nginxpanel/internal/fault"
	"nginxpanel/internal/secure"
)

type panelLoginLog struct{ server *Server }

func (l panelLoginLog) directory() string {
	return filepath.Join(l.server.DataDir, "agent", "security")
}
func (l panelLoginLog) available() bool {
	return !l.server.Dev && os.Geteuid() == 0 && l.server.MetricsScope == "host" && l.server.MaintenanceScope == "host"
}
func (l panelLoginLog) checkDirectory(create bool) error {
	var err error
	if create {
		err = secure.RootDirectory(l.directory(), 0700)
	} else {
		err = existingRootDirectory(l.directory())
	}
	if err != nil {
		return err
	}
	info, err := os.Lstat(l.directory())
	if err != nil {
		return err
	}
	if info.Mode().Perm() != 0700 || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return errors.New("面板登录日志目录权限无法核对")
	}
	return nil
}
func panelLoginFile(path string, create bool) (*os.File, error) {
	flags := os.O_RDONLY | syscall.O_NOFOLLOW | syscall.O_NONBLOCK
	if create {
		flags = os.O_RDWR | os.O_CREATE | syscall.O_NOFOLLOW | syscall.O_NONBLOCK
	}
	f, err := os.OpenFile(path, flags, 0600)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err == nil {
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || stat.Uid != 0 || stat.Nlink != 1 || info.Size() < 0 || info.Size() > fail2ban.PanelLoginFileBytes {
			err = errors.New("面板登录日志文件身份、权限或大小无法核对")
		}
	}
	if err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}
func (l panelLoginLog) prepare() error {
	if !l.available() {
		return fault.Unavailable("面板登录日志须由 root Agent 确认宿主机范围")
	}
	if err := l.checkDirectory(true); err != nil {
		return err
	}
	unlock, err := (&Journal{Dir: l.directory()}).rootLock("login.lock")
	if err != nil {
		return err
	}
	defer unlock()
	f, err := panelLoginFile(filepath.Join(l.directory(), "login.jsonl"), true)
	if err != nil {
		return err
	}
	return errors.Join(f.Close(), syncDir(l.directory()))
}
func (l panelLoginLog) append(ctx context.Context, in fail2ban.PanelLoginInput) (fail2ban.PanelLoginEvent, error) {
	var out fail2ban.PanelLoginEvent
	if !in.Valid() {
		return out, fault.Invalid("面板登录事件合同无效")
	}
	if !l.available() {
		return out, fault.Unavailable("面板登录日志未确认宿主机范围")
	}
	if err := ctx.Err(); err != nil {
		return out, err
	}
	if err := l.checkDirectory(true); err != nil {
		return out, err
	}
	unlock, err := (&Journal{Dir: l.directory()}).rootLock("login.lock")
	if err != nil {
		return out, err
	}
	defer unlock()
	path := filepath.Join(l.directory(), "login.jsonl")
	f, err := panelLoginFile(path, true)
	if err != nil {
		return out, err
	}
	defer func() {
		if f != nil {
			f.Close()
		}
	}()
	out = fail2ban.PanelLoginEvent{Time: time.Now().UTC().Format("2006-01-02T15:04:05-07:00"), Event: "login_failed", PeerAddr: in.PeerAddr, Source: "tcp_peer", RequestID: in.RequestID}
	raw := append([]byte(out.Line()), '\n')
	info, err := f.Stat()
	if err != nil {
		return out, err
	}
	if info.Size() > 0 {
		var tail [1]byte
		if _, err = f.ReadAt(tail[:], info.Size()-1); err != nil {
			return out, err
		}
		if tail[0] != '\n' {
			return out, errors.New("面板登录日志存在未完成的记录，须由宿主机管理员检查")
		}
	}
	if info.Size()+int64(len(raw)) > fail2ban.PanelLoginFileBytes {
		previous := path + ".1"
		old, readErr := panelLoginFile(previous, false)
		if readErr == nil {
			readErr = old.Close()
		}
		if readErr != nil && !os.IsNotExist(readErr) {
			return out, readErr
		}
		if err = f.Close(); err != nil {
			return out, err
		}
		f = nil
		if err = os.Rename(path, previous); err != nil {
			return out, err
		}
		if err = syncDir(l.directory()); err != nil {
			return out, err
		}
		f, err = panelLoginFile(path, true)
		if err != nil {
			return out, err
		}
	}
	if err = ctx.Err(); err != nil {
		return out, err
	}
	if _, err = f.Seek(0, io.SeekEnd); err != nil {
		return out, err
	}
	n, err := f.Write(raw)
	if err != nil {
		return out, err
	}
	if n != len(raw) {
		return out, io.ErrShortWrite
	}
	if err = f.Sync(); err != nil {
		return out, err
	}
	err = f.Close()
	f = nil
	return out, errors.Join(err, syncDir(l.directory()))
}
func panelLoginTail(f *os.File) ([]fail2ban.PanelLoginEvent, int64, error) {
	info, err := f.Stat()
	if err != nil {
		return nil, 0, err
	}
	start := info.Size() - 16*1024
	if start < 0 {
		start = 0
	}
	raw, err := io.ReadAll(io.NewSectionReader(f, start, 16*1024))
	if err != nil {
		return nil, 0, err
	}
	if start > 0 {
		i := bytes.IndexByte(raw, '\n')
		if i < 0 {
			return nil, 0, errors.New("面板登录日志尾部无法核对")
		}
		raw = raw[i+1:]
	}
	if len(raw) > 0 && raw[len(raw)-1] != '\n' {
		return nil, 0, errors.New("面板登录日志存在未完成的记录")
	}
	out := []fail2ban.PanelLoginEvent{}
	for _, line := range bytes.Split(raw, []byte{'\n'}) {
		if len(line) == 0 {
			continue
		}
		var event fail2ban.PanelLoginEvent
		if len(line) > 512 || json.Unmarshal(line, &event) != nil || !event.Valid() || event.Line() != string(line) {
			return nil, 0, errors.New("面板登录日志记录无法核对")
		}
		out = append(out, event)
	}
	return out, info.Size(), nil
}
func (l panelLoginLog) read() (fail2ban.PanelLoginStatus, error) {
	out := fail2ban.EmptyPanelLogin(l.server.MetricsScope, "")
	if !l.available() {
		out.Reason = "面板登录日志须由 root Agent 确认宿主机范围"
		return out, nil
	}
	if err := l.checkDirectory(false); err != nil {
		out.Reason = "面板登录日志目录尚未准备或无法核对"
		return out, nil
	}
	unlock, err := (&Journal{Dir: l.directory()}).rootLock("login.lock")
	if err != nil {
		return out, err
	}
	defer unlock()
	for _, name := range []string{"login.jsonl.1", "login.jsonl"} {
		f, err := panelLoginFile(filepath.Join(l.directory(), name), false)
		if os.IsNotExist(err) && name == "login.jsonl.1" {
			continue
		}
		if err != nil {
			return fail2ban.EmptyPanelLogin(out.Scope, "面板登录日志文件无法核对"), nil
		}
		events, size, readErr := panelLoginTail(f)
		closeErr := f.Close()
		if readErr != nil || closeErr != nil {
			return fail2ban.EmptyPanelLogin(out.Scope, "面板登录日志记录不完整或无法读取"), nil
		}
		out.Events = append(out.Events, events...)
		out.Bytes += size
	}
	if len(out.Events) > 20 {
		out.Events = out.Events[len(out.Events)-20:]
	}
	for i, j := 0, len(out.Events)-1; i < j; i, j = i+1, j-1 {
		out.Events[i], out.Events[j] = out.Events[j], out.Events[i]
	}
	out.Available = true
	return out, nil
}
func (l panelLoginLog) handlers(mux *http.ServeMux) {
	mux.HandleFunc("POST /v1/fail2ban/panel-login", func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 1024)
		defer r.Body.Close()
		var in fail2ban.PanelLoginInput
		d := json.NewDecoder(r.Body)
		d.DisallowUnknownFields()
		if d.Decode(&in) != nil || d.Decode(new(any)) != io.EOF {
			fail2banNginxReply(w, nil, fault.Invalid("面板登录事件格式无效"))
			return
		}
		out, err := l.append(r.Context(), in)
		fail2banNginxReply(w, out, err)
	})
	mux.HandleFunc("GET /v1/fail2ban/panel-login", func(w http.ResponseWriter, r *http.Request) { out, err := l.read(); fail2banNginxReply(w, out, err) })
}
func (c *Client) RecordPanelLogin(ctx context.Context, in fail2ban.PanelLoginInput) error {
	if !in.Valid() {
		return fault.Invalid("面板登录事件合同无效")
	}
	var out fail2ban.PanelLoginEvent
	err := c.envelopeRequest(ctx, http.MethodPost, "/v1/fail2ban/panel-login", in, &out)
	if err == nil && (!out.Valid() || out.PeerAddr != in.PeerAddr || out.RequestID != in.RequestID) {
		return errors.New("面板登录事件回执无法核对")
	}
	return err
}
func (c *Client) ReadPanelLogin(ctx context.Context) (fail2ban.PanelLoginStatus, error) {
	var out fail2ban.PanelLoginStatus
	err := c.envelopeRequest(ctx, http.MethodGet, "/v1/fail2ban/panel-login", nil, &out)
	if err == nil && !out.Valid() {
		err = errors.New("面板登录日志结果合同无法核对")
	}
	return out, err
}
