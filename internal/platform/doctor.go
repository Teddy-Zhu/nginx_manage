package platform

import (
	"bufio"
	"nginxpanel/internal/monitoring"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

type Tool struct {
	Installed bool   `json:"installed"`
	Path      string `json:"path,omitempty"`
	Running   *bool  `json:"running"`
}
type DNS struct {
	ResolvConf     string `json:"resolv_conf"`
	LinkTarget     string `json:"link_target,omitempty"`
	CandidateOwner string `json:"candidate_owner"`
	Writable       bool   `json:"writable"`
	Reason         string `json:"reason"`
}
type Report struct {
	OS           string                `json:"os"`
	Version      string                `json:"version"`
	Architecture string                `json:"architecture"`
	Kernel       string                `json:"kernel"`
	Tools        map[string]Tool       `json:"tools"`
	DNS          DNS                   `json:"dns"`
	SELinux      string                `json:"selinux"`
	AppArmor     string                `json:"apparmor"`
	Source       string                `json:"source"`
	Monitoring   monitoring.Capability `json:"monitoring"`
}

func Detect() Report {
	r := Report{Architecture: runtime.GOARCH, Tools: map[string]Tool{}, DNS: DNS{ResolvConf: "/etc/resolv.conf", CandidateOwner: "unknown", Reason: "尚未验证持久配置所有者与局部恢复能力，保持只读"}, Source: "local-process"}
	if f, err := os.Open("/etc/os-release"); err == nil {
		defer f.Close()
		s := bufio.NewScanner(f)
		for s.Scan() {
			k, v, ok := strings.Cut(s.Text(), "=")
			if !ok {
				continue
			}
			v = strings.Trim(v, `"`)
			if k == "ID" {
				r.OS = v
			}
			if k == "VERSION_ID" {
				r.Version = v
			}
		}
	}
	if b, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		r.Kernel = strings.TrimSpace(string(b))
	}
	for _, name := range []string{"nginx", "systemctl", "nft", "iptables", "iptables-legacy", "iptables-nft", "ufw", "firewall-cmd", "fail2ban-client", "python3", "netplan"} {
		t := Tool{}
		for _, dir := range []string{"/usr/sbin", "/usr/bin", "/sbin", "/bin"} {
			p := filepath.Join(dir, name)
			if info, err := os.Stat(p); err == nil && info.Mode().IsRegular() && info.Mode().Perm()&0111 != 0 {
				t.Installed = true
				t.Path = p
				break
			}
		}
		r.Tools[name] = t
	}
	if target, err := os.Readlink("/etc/resolv.conf"); err == nil {
		r.DNS.LinkTarget = target
		switch {
		case strings.Contains(target, "systemd/resolve"):
			r.DNS.CandidateOwner = "resolved (upstream unverified)"
		case strings.Contains(target, "NetworkManager"):
			r.DNS.CandidateOwner = "NetworkManager (unverified)"
		default:
			r.DNS.CandidateOwner = "external-manager"
		}
	} else if info, err := os.Lstat("/etc/resolv.conf"); err == nil && info.Mode().IsRegular() {
		r.DNS.CandidateOwner = "regular-file (ownership unverified)"
	}
	r.SELinux = "unknown"
	if b, err := os.ReadFile("/sys/fs/selinux/enforce"); err == nil {
		if strings.TrimSpace(string(b)) == "1" {
			r.SELinux = "enforcing"
		} else {
			r.SELinux = "permissive"
		}
	}
	r.AppArmor = "unknown"
	if b, err := os.ReadFile("/sys/module/apparmor/parameters/enabled"); err == nil {
		r.AppArmor = strings.TrimSpace(string(b))
	}
	return r
}
