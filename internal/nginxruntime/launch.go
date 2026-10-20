package nginxruntime

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
)

// Launch only executes the locally bound, reverified Nginx with fixed arguments.
// Exec preserves systemd's master PID and signal/exit-status ownership.
func Launch(ctx context.Context, data string, check bool) error {
	if os.Geteuid() != 0 {
		return errors.New("原生 Nginx 启动需要本机 root")
	}
	b, _, err := Read(ctx, data)
	if err != nil {
		return err
	}
	actual, err := probe(ctx, b.Binary)
	if err != nil {
		return err
	}
	if actual != b.Version {
		return errors.New("已绑定 Nginx 的版本响应已变化")
	}
	if err = verifyExecutable(b.Binary, b.SHA256); err != nil {
		return err
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	args := []string{b.Binary, "-p", data + "/", "-c", filepath.Join(data, "nginx", "active", "nginx.conf"), "-e", "stderr"}
	if check {
		args = append(args, "-t", "-q")
	} else {
		if err = clearStaleProbe(ctx, data); err != nil {
			return err
		}
		args = append(args, "-g", "daemon off;")
	}
	return syscall.Exec(b.Binary, args, Environment())
}
