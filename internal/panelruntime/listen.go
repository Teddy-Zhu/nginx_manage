package panelruntime

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"syscall"
)

func ValidateListen(address string) error {
	a, err := netip.ParseAddrPort(address)
	if err != nil || a.String() != address || a.Addr().Zone() != "" || a.Addr().Is4In6() || a.Port() < 1024 || (!a.Addr().IsUnspecified() && !a.Addr().IsLoopback() && !a.Addr().IsGlobalUnicast()) {
		return errors.New("管理地址须为规范 IPv4:端口或 [IPv6]:端口，端口为 1024–65535")
	}
	return nil
}

// Listen keeps IPv4 bindings in tcp4 so process ownership checks observe the
// same address. An IPv6 wildcard uses Go's dual-stack listener when available.
func Listen(address string) (net.Listener, error) {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	network := "tcp"
	if net.ParseIP(host).To4() != nil {
		network = "tcp4"
	}
	return net.Listen(network, address)
}

// RecommendListen asks the kernel for an unused port when port is zero. The
// caller saves the selected address; service restarts never choose a new port.
func RecommendListen(port int) (string, error) {
	if port != 0 && (port < 1024 || port > 65535) {
		return "", errors.New("管理端口须为 1024–65535")
	}
	l, err := Listen(fmt.Sprintf("[::]:%d", port))
	if errors.Is(err, syscall.EAFNOSUPPORT) || errors.Is(err, syscall.EADDRNOTAVAIL) || errors.Is(err, syscall.EPROTONOSUPPORT) {
		l, err = Listen(fmt.Sprintf("0.0.0.0:%d", port))
	}
	if err != nil {
		return "", fmt.Errorf("无法选择空闲管理端口：%w", err)
	}
	address := l.Addr().String()
	if err = l.Close(); err != nil {
		return "", err
	}
	return address, ValidateListen(address)
}

// LocalListen turns wildcard bindings into a concrete local probe target.
func LocalListen(address string) string {
	a, err := netip.ParseAddrPort(address)
	if err != nil || !a.Addr().IsUnspecified() {
		return address
	}
	host := "127.0.0.1"
	if a.Addr().Is6() {
		host = "::1"
	}
	return net.JoinHostPort(host, fmt.Sprint(a.Port()))
}

func (d Deployment) Protocol() string {
	if d.HTTP {
		return "http"
	}
	return "https"
}

func (d Deployment) AccessURLs() ([]string, error) { return accessURLs(d.Listen, d.Protocol()) }

func AccessURLs(address string) ([]string, error) { return accessURLs(address, "https") }

func accessURLs(address, protocol string) ([]string, error) {
	if err := ValidateListen(address); err != nil {
		return nil, err
	}
	a, _ := netip.ParseAddrPort(address)
	if !a.Addr().IsUnspecified() {
		return []string{protocol + "://" + address}, nil
	}
	interfaces, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	for _, item := range interfaces {
		ip, _, err := net.ParseCIDR(item.String())
		if err != nil || !ip.IsGlobalUnicast() || a.Addr().Is4() && ip.To4() == nil {
			continue
		}
		seen[protocol+"://"+net.JoinHostPort(ip.String(), fmt.Sprint(a.Port()))] = true
	}
	urls := make([]string, 0, len(seen))
	for u := range seen {
		urls = append(urls, u)
	}
	sort.Strings(urls)
	return urls, nil
}

// SetListen requires the caller to exclude maintenance and hold the stopped
// application's writer lock.
func SetListen(data, address string) error { return SetAccess(data, address, "") }

func SetAccess(data, address, protocol string) error {
	if os.Geteuid() != 0 {
		return errors.New("修改管理地址需要本机 root")
	}
	if protocol != "" && protocol != "http" && protocol != "https" {
		return errors.New("管理协议须为 http 或 https")
	}
	root, err := Root(data)
	if err != nil {
		return err
	}
	unlock, err := publicationLock(root)
	if err != nil {
		return err
	}
	defer unlock()
	d, err := ReadDeployment(data)
	if err != nil {
		return err
	}
	if address == "" {
		address = d.Listen
	}
	if err := ValidateListen(address); err != nil {
		return err
	}
	if protocol == "" {
		protocol = d.Protocol()
	}
	if d.Listen == address && d.Protocol() == protocol {
		return nil
	}
	l, err := Listen(address)
	if err != nil {
		return fmt.Errorf("管理地址不可用，原配置保留：%w", err)
	}
	defer l.Close()
	before, err := json.Marshal(d)
	if err != nil {
		return err
	}
	d.Listen = address
	d.HTTP = protocol == "http"
	after, err := json.Marshal(d)
	if err != nil {
		return err
	}
	return replaceDeploymentFile(filepath.Join(root, "launcher.json"), before, after, DeploymentLimit)
}
