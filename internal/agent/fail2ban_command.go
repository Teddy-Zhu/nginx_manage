package agent

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	"nginxpanel/internal/fail2ban"
)

func fail2banTool(name string) fail2ban.Tool {
	out := fail2ban.Tool{ID: name, Reason: "固定系统目录中未发现受信程序"}
	present, unknown := false, false
	for _, dir := range []string{"/usr/bin", "/usr/sbin", "/bin", "/sbin"} {
		path := filepath.Join(dir, name)
		if err := fail2banToolDirectory(dir); err != nil {
			unknown = unknown || !os.IsNotExist(err)
			continue
		}
		if _, err := os.Lstat(path); err != nil {
			if !os.IsNotExist(err) {
				unknown = true
			}
			continue
		}
		present = true
		if resolved, err := trustedFile(path, true); err == nil {
			out.Present, out.Trusted, out.Path, out.Resolved, out.Reason = &present, true, path, resolved, ""
			return out
		}
		out.Path, out.Reason = path, "文件存在，但路径或权限未通过 root 保护核对"
	}
	if present || !unknown {
		out.Present = &present
	} else {
		out.Reason = "固定程序路径无法完整读取"
	}
	return out
}

// System directories may use root-owned usr-merge aliases. Check each link
// before following it rather than trusting only the final directory.
func fail2banToolDirectory(dir string) error {
	for links := 0; links < 8; links++ {
		if err := existingRootDirectory(filepath.Dir(dir)); err != nil {
			return err
		}
		info, err := os.Lstat(dir)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink == 0 {
			return existingRootDirectory(dir)
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 {
			return ErrExternalChange
		}
		target, err := os.Readlink(dir)
		if err != nil {
			return err
		}
		if !filepath.IsAbs(target) {
			target = filepath.Join(filepath.Dir(dir), target)
		}
		dir = filepath.Clean(target)
	}
	return ErrExternalChange
}

// All callers supply fixed diagnostic verbs or validated package metadata.
// No caller accepts API tool paths, Python, shell text or control commands.
func fail2banRun(ctx context.Context, tool fail2ban.Tool, args []string, limit int) ([]byte, error) {
	if !tool.Trusted || tool.Resolved == "" {
		return nil, errors.New("trusted diagnostic program unavailable")
	}
	call, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	cmd := exec.CommandContext(call, tool.Resolved, args...)
	cmd.Args[0] = tool.Path
	cmd.Dir = "/"
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C", "LANG=C", "PYTHONNOUSERSITE=1", "PYTHONSAFEPATH=1", "PYTHONDONTWRITEBYTECODE=1", "SYSTEMD_PAGER=cat"}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = 250 * time.Millisecond
	out, diagnostic := firewallOutput{limit: limit}, firewallOutput{limit: 4096}
	cmd.Stdout, cmd.Stderr = &out, &diagnostic
	err := cmd.Run()
	if out.exceeded || diagnostic.exceeded {
		return nil, errors.New("diagnostic output exceeds budget")
	}
	return out.data.Bytes(), err
}
