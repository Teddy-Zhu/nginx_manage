package panelruntime

import (
	"context"
	"errors"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
	"nginxpanel/internal/protocol"
)

type NativeInput struct {
	DataDir, Binary, WebDir, Listen string
	UID, GID, IPCGID                int
}

// BindNative publishes the root administrator's initial installation. Online
// updates instead require a signed staged approval and maintenance transaction.
func BindNative(ctx context.Context, in NativeInput) (Snapshot, error) {
	var out Snapshot
	if os.Geteuid() != 0 {
		return out, errors.New("原生面板初始化需要本机 root")
	}
	root, err := Root(in.DataDir)
	if err != nil {
		return out, err
	}
	binary, err := filepath.EvalSymlinks(in.Binary)
	if err != nil {
		return out, err
	}
	web, err := filepath.EvalSymlinks(in.WebDir)
	if err != nil {
		return out, err
	}
	r, err := describe(ctx, binary)
	if err != nil {
		return out, err
	}
	if r.AgentProtocol != protocol.Agent {
		return out, errors.New("初始程序与本机 Agent 协议不一致")
	}
	r.Web, err = inventory(web, false)
	if err != nil {
		return out, err
	}
	r.ID = releaseID(r)
	if err = r.validate(); err != nil {
		return out, err
	}
	d := Deployment{Schema: Schema, Mode: "native", DataDir: in.DataDir, Listen: in.Listen, UID: in.UID, GID: in.GID, IPCGID: in.IPCGID, InitialRelease: r.ID}
	if err = d.validate(in.DataDir); err != nil {
		return out, err
	}
	unlock, err := publicationLock(root)
	if err != nil {
		return out, err
	}
	defer unlock()
	return bindRelease(ctx, root, binary, web, r, d)
}

// ExecNative is the fixed systemd entry point. The selected immutable program
// rechecks its own inode after taking the writer lock, before opening any data.
func ExecNative(data string) error {
	s, err := Read(data)
	if err != nil {
		return err
	}
	if s.Deployment.Mode != "native" || os.Geteuid() != s.Deployment.UID || os.Getegid() != s.Deployment.GID {
		return errors.New("原生启动入口与面板部署身份不一致")
	}
	binary := filepath.Join(s.Directory, "nginxpanel")
	args := []string{binary, "serve", "--data-dir", data, "--listen", s.Deployment.Listen, "--web-dir", filepath.Join(s.Directory, "web"), "--nginx-modules", "/etc/nginxpanel/nginx-modules.json", "--panel-runtime", "native"}
	return unix.Exec(binary, args, []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C", "TZ=UTC", "SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt"})
}

// CheckProcess must run with the writer lock held. A bootstrap wrapper or
// launcher may have read current just before a root version selection; a stale
// child must fail before vault access or automatic schema migration.
func CheckProcess(data, mode, listen, web, version string) (Snapshot, error) {
	s, err := Read(data)
	if err != nil {
		return s, err
	}
	d := s.Deployment
	if d.Mode != mode || d.Listen != listen || d.UID != os.Geteuid() || d.GID != os.Getegid() || s.Release.Version != version {
		return s, errors.New("当前程序与 root 面板运行绑定不一致")
	}
	resolved, err := filepath.EvalSymlinks(web)
	if err != nil {
		return s, err
	}
	if resolved != filepath.Join(s.Directory, "web") {
		return s, errors.New("面板前端不属于当前批准版本")
	}
	return s, checkExecutable(s)
}

// CheckInit prevents a repeated bootstrap command from opening newer data with
// the original installation binary after the selected release has changed.
func CheckInit(data string) error {
	s, err := Read(data)
	if err != nil {
		return err
	}
	if s.Deployment.UID != os.Geteuid() || s.Deployment.GID != os.Getegid() {
		return errors.New("初始化程序与面板部署身份不一致")
	}
	return checkExecutable(s)
}

func checkExecutable(s Snapshot) error {
	live, err := os.Stat("/proc/self/exe")
	if err != nil {
		return err
	}
	expected, err := os.Stat(filepath.Join(s.Directory, "nginxpanel"))
	if err != nil {
		return err
	}
	if !os.SameFile(live, expected) {
		return errors.New("运行中的面板程序不是当前批准的执行文件")
	}
	return nil
}
