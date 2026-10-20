package nginxruntime

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"nginxpanel/internal/secure"
)

// Nginx leaves its pathname socket behind after an interrupted shutdown. Only
// the reserved, root-owned probe may be removed; a bound socket is not stale,
// even when it is not accepting connections yet.
func clearStaleProbe(ctx context.Context, data string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	dir := filepath.Join(data, "run")
	if err := secure.RootDirectory(dir, 0755); err != nil {
		return err
	}
	name := filepath.Join(dir, "nginx-probe.sock")
	before, err := os.Lstat(name)
	if os.IsNotExist(err) {
		return ctx.Err()
	}
	if err != nil {
		return err
	}
	stat, ok := before.Sys().(*syscall.Stat_t)
	if !ok || before.Mode()&os.ModeSocket == 0 || stat.Uid != 0 {
		return errors.New("Nginx 探测路径的类型或归属无效")
	}
	if err = probeNotBound(name); err != nil {
		return err
	}
	call, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel()
	conn, dialErr := (&net.Dialer{}).DialContext(call, "unix", name)
	if dialErr == nil {
		conn.Close()
		return errors.New("Nginx 探测 Socket 仍在使用")
	}
	if !errors.Is(dialErr, syscall.ECONNREFUSED) {
		return dialErr
	}
	if err = probeNotBound(name); err != nil {
		return err
	}
	after, err := os.Lstat(name)
	if err != nil {
		return err
	}
	current, ok := after.Sys().(*syscall.Stat_t)
	if !ok || !os.SameFile(before, after) || current.Ctim != stat.Ctim || after.Mode() != before.Mode() || current.Uid != 0 || current.Gid != stat.Gid {
		return errors.New("Nginx 探测 Socket 在核对期间变化")
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	return os.Remove(name)
}

func probeNotBound(name string) error {
	self, err := os.Stat("/proc/self/ns/net")
	if err != nil {
		return err
	}
	initial, err := os.Stat("/proc/1/ns/net")
	if err != nil || !os.SameFile(self, initial) {
		return errors.New("无法核对初始网络命名空间的 Nginx 探测 Socket")
	}
	f, err := os.Open("/proc/net/unix")
	if err != nil {
		return err
	}
	defer f.Close()
	const limit = 2 << 20
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return err
	}
	if len(raw) > limit || !strings.HasPrefix(string(raw), "Num ") || raw[len(raw)-1] != '\n' {
		return errors.New("无法完整核对 Nginx 探测 Socket 的内核状态")
	}
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 8 && fields[7] == name {
			return errors.New("Nginx 探测 Socket 仍有内核引用")
		}
	}
	return nil
}
