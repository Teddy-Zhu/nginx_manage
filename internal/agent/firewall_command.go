package agent

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
)

type firewallOutput struct {
	data     bytes.Buffer
	limit    int
	exceeded bool
}

func (w *firewallOutput) Write(p []byte) (int, error) {
	if w.data.Len()+len(p) > w.limit {
		w.exceeded = true
		return 0, errors.New("firewall read exceeds output budget")
	}
	return w.data.Write(p)
}

// This is a closed read-only command set. Neither tool names nor arguments
// originate in an HTTP request, a configuration file, or PATH lookup.
func firewallRead(ctx context.Context, name, action string, limit int) ([]byte, error) {
	return firewallReadCommand(ctx, name, action, limit, false)
}

func firewallReadCommand(ctx context.Context, name, action string, limit int, rejectDiagnostic bool) ([]byte, error) {
	var args []string
	switch {
	case name == "sshd" && action == "effective":
		args = []string{"-T"}
	case name == "nft" && action == "rules":
		args = []string{"--json", "--numeric", "--terse", "list", "ruleset"}
	case name == "ufw" && action == "status":
		args = []string{"status"}
	case name == "ufw" && action == "added":
		args = []string{"show", "added"}
	case (name == "iptables" || name == "ip6tables" || name == "iptables-nft" || name == "ip6tables-nft" || name == "iptables-legacy" || name == "ip6tables-legacy") && action == "version":
		args = []string{"--version"}
	case (name == "iptables-nft-save" || name == "ip6tables-nft-save" || name == "iptables-legacy-save" || name == "ip6tables-legacy-save") && action == "rules":
		args = []string{}
	case (name == "iptables-nft-save" || name == "ip6tables-nft-save" || name == "iptables-legacy-save" || name == "ip6tables-legacy-save") && action == "version":
		args = []string{"--version"}
	default:
		return nil, errors.New("unsupported firewall diagnostic command")
	}
	if action == "rules" && name != "nft" {
		// Even a save command can invoke modprobe if a table disappears
		// between enumeration and inspection. Keep that fallback read-only.
		var noModuleLoad string
		for _, dir := range []string{"/usr/bin", "/bin"} {
			path := filepath.Join(dir, "false")
			if _, e := trustedFile(path, true); e == nil {
				noModuleLoad = path
				break
			}
		}
		if noModuleLoad == "" {
			return nil, errors.New("module-load blocker is unavailable")
		}
		args = []string{"--modprobe", noModuleLoad}
	}
	var binary, invoked string
	for _, dir := range []string{"/usr/sbin", "/usr/bin", "/sbin", "/bin"} {
		path := filepath.Join(dir, name)
		if resolved, e := trustedFile(path, true); e == nil {
			binary, invoked = resolved, path
			break
		}
	}
	if binary == "" {
		return nil, errors.New("trusted firewall tool is unavailable")
	}
	call, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	cmd := exec.CommandContext(call, binary, args...)
	// xtables-nft/legacy-multi select their applet using the original argv[0].
	cmd.Args[0] = invoked
	cmd.Dir = "/"
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C", "LANG=C", "PYTHONDONTWRITEBYTECODE=1"}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = 250 * time.Millisecond
	out, diagnostic := firewallOutput{limit: limit}, firewallOutput{limit: 8 << 10}
	cmd.Stdout = &out
	cmd.Stderr = &diagnostic
	if e := cmd.Run(); e != nil {
		return nil, e
	}
	if out.exceeded || diagnostic.exceeded || rejectDiagnostic && diagnostic.data.Len() != 0 {
		return nil, errors.New("firewall read returned diagnostics or exceeded its output budget")
	}
	return out.data.Bytes(), nil
}
