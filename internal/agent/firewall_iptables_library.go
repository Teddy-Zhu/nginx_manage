package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	goiptables "github.com/coreos/go-iptables/iptables"
	"golang.org/x/sys/unix"

	"nginxpanel/internal/firewall"
	"nginxpanel/internal/secure"
)

// IPTablesLibraryApplet identifies the isolated, closed read-only entry point.
const IPTablesLibraryApplet = "_nginxpanel-iptables-read"
const iptablesLibraryEnvironment = "NGINXPANEL_IPTABLES_READER"
const iptablesLibraryInputBytes = 4 << 20

type iptablesLibraryRequest struct {
	Version                  int
	Docker                   *iptablesLibraryDockerScope
	Parent                   networkdProcess
	Deadline                 int64
	Workspace                string
	Helper, Command, Blocker ufwBoundFile
	ExpectedVersion          string
	Image                    iptablesImage
}

type iptablesLibraryBridge struct {
	Version          int
	Docker           bool
	Parent           networkdProcess
	Deadline         int64
	Command, Blocker ufwBoundFile
	ExpectedVersion  string
	Chains           []string
}

func validIPTablesLibraryChain(name string) bool {
	if name == "INPUT" || name == "FORWARD" || name == "DOCKER-USER" || name == firewall.IPTablesHostChain || name == firewall.IPTablesDockerChain {
		return true
	}
	for prefix, size := range map[string]int{firewall.IPTablesHostChain + "-": 12, firewall.IPTablesDockerChain + "-": 10} {
		if strings.HasPrefix(name, prefix) && len(name) == len(prefix)+size && strings.Trim(name[len(prefix):], "0123456789abcdef") == "" {
			return true
		}
	}
	return false
}

// The upstream library has no injectable executor. It runs only in this
// bounded helper, with an explicit private applet path and a read-only bridge.
// No module replacement, shell, PATH backend selection or library write API is
// used. The original save image remains the complete foreign-rule authority.
func (binding *iptablesToolBinding) verifyLibrary(ctx context.Context, image iptablesImage, docker *iptablesLibraryDockerScope) (resultErr error) {
	if image.chain("filter", "INPUT") == nil {
		if docker != nil && (docker.Generation != nil || docker.RequireHook) {
			return errors.New("Docker 固定读取缺少 filter/INPUT 环境")
		}
		return nil // An unused family must not create or load a filter table.
	}
	role := binding.Backend
	if image.Family == "ipv6" {
		role = "ip6tables-" + strings.TrimPrefix(role, "iptables-")
	} else if image.Family != "ipv4" {
		return errors.New("go-iptables 地址族无效")
	}
	command, err := binding.tool(role)
	if err != nil {
		return err
	}
	blocker, err := binding.tool("false")
	if err != nil {
		return err
	}
	unlock, err := (&Journal{Dir: "/run/nginxpanel-host"}).rootLock("iptables-library.lock")
	if err != nil {
		return err
	}
	defer unlock()
	const parent = "/run/nginxpanel-host"
	entries, err := os.ReadDir(parent)
	if err != nil {
		return err
	}
	stale := 0
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "iptables-library-") {
			stale++
		}
	}
	if stale >= 16 {
		return errors.New("go-iptables 私有读取目录达到上限，须本机核对遗留进程与目录")
	}
	workspace, err := os.MkdirTemp(parent, "iptables-library-")
	if err != nil {
		return err
	}
	defer func() {
		if err := os.RemoveAll(workspace); err != nil {
			resultErr = errors.Join(resultErr, errors.New("go-iptables 私有读取目录清理失败"))
		}
	}()
	helper, err := openFirewallELF(binding.Helper, iptablesHelperBytes)
	if err != nil {
		return err
	}
	defer helper.Close()
	process, err := networkProcess(uint32(os.Getpid()))
	if err != nil {
		return err
	}
	call, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	deadline, _ := call.Deadline()
	request := iptablesLibraryRequest{Version: 3, Docker: docker, Parent: process, Deadline: deadline.UnixMilli(), Workspace: workspace, Helper: binding.Helper, Command: command, Blocker: blocker, Image: image}
	for _, version := range binding.Versions {
		if version.Role == role {
			request.ExpectedVersion = version.Version
		}
	}
	raw, err := json.Marshal(request)
	if err != nil || len(raw) > iptablesLibraryInputBytes {
		return errors.New("go-iptables 私有读取输入超过 4 MiB 或无法编码")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	child := exec.CommandContext(call, "/proc/self/fd/3", "_iptables-library")
	child.ExtraFiles = []*os.File{helper}
	child.Dir = "/"
	child.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C", "LANG=C"}
	child.Stdin = bytes.NewReader(raw)
	child.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
	child.Cancel = func() error { return syscall.Kill(-child.Process.Pid, syscall.SIGKILL) }
	child.WaitDelay = 250 * time.Millisecond
	stdout, stderr := firewallOutput{limit: 64}, firewallOutput{limit: 8 << 10}
	child.Stdout, child.Stderr = &stdout, &stderr
	if err = child.Run(); err != nil || call.Err() != nil || stdout.exceeded || stderr.exceeded || stderr.data.Len() != 0 || stdout.data.String() != secure.Hash(raw) {
		return errors.New("go-iptables 固定链及受管规则读取失败、漂移、超时或输出超限")
	}
	return nil
}

func iptablesLibraryParent(expected networkdProcess) error {
	if os.Geteuid() != 0 || !validDNSProcess(expected) {
		return errors.New("go-iptables 私有读取父进程无效")
	}
	if err := unix.Prctl(unix.PR_SET_PDEATHSIG, uintptr(unix.SIGKILL), 0, 0, 0); err != nil {
		return err
	}
	parent, err := networkProcess(uint32(os.Getppid()))
	if err != nil || parent != expected {
		return errors.New("go-iptables 原父进程已变化")
	}
	return nil
}

func validIPTablesLibraryCommand(command, blocker ufwBoundFile, version string) bool {
	backend, _, err := firewallVersion([]byte(version))
	wanted := "nftables"
	if strings.HasSuffix(command.Role, "-legacy") {
		wanted = "legacy"
	}
	return validIPTablesBoundFile(command, 16<<20) && slices.Contains([]string{"iptables-nft", "ip6tables-nft", "iptables-legacy", "ip6tables-legacy"}, command.Role) && filepath.Base(command.Invoked) == command.Role && validIPTablesBoundFile(blocker, 16<<20) && blocker.Role == "false" && filepath.Base(blocker.Invoked) == "false" && err == nil && backend == wanted && iptablesToolVersionMatches(command.Role, version)
}

// RunIPTablesLibrary is a private entry of the pinned executable. Only a digest
// of the exact input is returned after all library reads agree with that image.
func RunIPTablesLibrary() error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	raw, err := io.ReadAll(io.LimitReader(os.Stdin, iptablesLibraryInputBytes+1))
	invalid := errors.New("go-iptables 私有读取请求无效")
	var request iptablesLibraryRequest
	if err != nil || len(raw) > iptablesLibraryInputBytes || ufwToolJSON(raw, &request) != nil || request.Version != 3 || !validIPTablesLibraryCommand(request.Command, request.Blocker, request.ExpectedVersion) || request.Deadline <= time.Now().UnixMilli() || request.Deadline > time.Now().Add(8*time.Second).UnixMilli() || filepath.Dir(request.Workspace) != "/run/nginxpanel-host" || !strings.HasPrefix(filepath.Base(request.Workspace), "iptables-library-") || !validIPTablesBoundFile(request.Helper, iptablesHelperBytes) || request.Helper.Role != "nginxpanel" {
		return invalid
	}
	if err = iptablesLibraryParent(request.Parent); err != nil {
		return err
	}
	helper := os.NewFile(3, "iptables-library-helper")
	defer helper.Close()
	info, err := helper.Stat()
	if err != nil {
		return invalid
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	wanted := request.Helper.File
	if !ok || stat.Uid != 0 || uint64(stat.Dev) != wanted.Device || stat.Ino != wanted.Inode || info.Size() != wanted.Bytes || uint32(info.Mode()) != wanted.Mode || info.ModTime().UnixNano() != wanted.Modified || stat.Ctim.Sec*1e9+stat.Ctim.Nsec != wanted.Changed {
		return invalid
	}
	if _, err = unix.Fgetxattr(3, "security.capability", nil); !errors.Is(err, unix.ENODATA) && !errors.Is(err, unix.ENOTSUP) {
		return invalid
	}
	if err = secure.RootDirectory(request.Workspace, 0700); err != nil {
		return err
	}
	input := request.Image.chain("filter", "INPUT")
	if input == nil || input.Policy != "ACCEPT" && input.Policy != "DROP" || request.Image.Family != "ipv4" && request.Image.Family != "ipv6" || strings.HasPrefix(request.Command.Role, "ip6tables-") != (request.Image.Family == "ipv6") {
		return invalid
	}
	chains, inspect := []string{}, []string{"INPUT"}
	if request.Docker != nil {
		if err = proveDockerIPTablesGeneration(request.Image, request.Docker.Generation); err != nil {
			return err
		}
		if request.Docker.RequireHook && !observeDockerFirewallHook(request.Image).Observed {
			return errors.New("Docker 固定读取的原始转发挂接无法核对")
		}
		for _, name := range []string{"FORWARD", "DOCKER-USER"} {
			if request.Image.chain("filter", name) != nil {
				inspect = append(inspect, name)
			}
		}
	} else if err = proveEmptyDockerNamespace(request.Image); err != nil {
		return err
	}
	managed, dockerManaged := 0, 0
	for _, table := range request.Image.Tables {
		if table.Name != "filter" {
			continue
		}
		for _, chain := range table.Chains {
			chains = append(chains, chain.Name)
			if strings.HasPrefix(chain.Name, firewall.IPTablesHostChain) {
				managed++
				if !validIPTablesLibraryChain(chain.Name) || managed > 2 {
					return invalid
				}
				inspect = append(inspect, chain.Name)
			}
			if strings.HasPrefix(chain.Name, firewall.IPTablesDockerChain) {
				dockerManaged++
				if request.Docker == nil || !validIPTablesLibraryChain(chain.Name) || dockerManaged > 2 {
					return invalid
				}
				inspect = append(inspect, chain.Name)
			}
		}
	}
	process, err := networkProcess(uint32(os.Getpid()))
	if err != nil {
		return err
	}
	bridge := iptablesLibraryBridge{Version: 3, Docker: request.Docker != nil, Parent: process, Deadline: request.Deadline, Command: request.Command, Blocker: request.Blocker, ExpectedVersion: request.ExpectedVersion, Chains: inspect}
	environment, err := json.Marshal(bridge)
	if err != nil || len(environment) > 16<<10 {
		return invalid
	}
	if err = os.Setenv(iptablesLibraryEnvironment, string(environment)); err != nil {
		return err
	}
	path := filepath.Join(request.Workspace, IPTablesLibraryApplet)
	if err = os.Symlink("/proc/"+strconv.Itoa(os.Getpid())+"/fd/3", path); err != nil {
		return err
	}
	family := goiptables.ProtocolIPv4
	if request.Image.Family == "ipv6" {
		family = goiptables.ProtocolIPv6
	}
	reader, err := goiptables.New(goiptables.Path(path), goiptables.IPFamily(family), goiptables.Timeout(1))
	if err != nil || reader.Proto() != family {
		return invalid
	}
	major, minor, _ := reader.GetIptablesVersion()
	if major < 1 || major == 1 && minor < 6 {
		return errors.New("go-iptables 要求支持有界 --wait 的 1.6.0 或更新版本")
	}
	actual, err := reader.ListChains("filter")
	slices.Sort(actual)
	slices.Sort(chains)
	if err != nil || !slices.Equal(actual, chains) {
		return errors.New("go-iptables 链清单与原完整规则不一致")
	}
	for _, name := range inspect {
		rows, err := reader.List("filter", name)
		if err != nil || compareIPTablesLibraryChain(request.Image, name, rows) != nil {
			return errors.New("go-iptables 当前入口或受管规则与原完整规则不一致")
		}
	}
	if err = iptablesLibraryParent(request.Parent); err != nil || time.Now().UnixMilli() >= request.Deadline {
		return invalid
	}
	_, err = io.WriteString(os.Stdout, secure.Hash(raw))
	return err
}

func compareIPTablesLibraryChain(image iptablesImage, name string, rows []string) error {
	invalid := errors.New("go-iptables 链读取与原规则不一致")
	chain := image.chain("filter", name)
	if chain == nil || len(rows) != len(chain.Rules)+1 {
		return invalid
	}
	declaration, err := xtablesWords(rows[0])
	expected := []string{"-N", name}
	if name == "INPUT" || name == "FORWARD" {
		expected = []string{"-P", name, chain.Policy}
	}
	if err != nil || !slices.Equal(declaration, expected) {
		return invalid
	}
	for index, row := range rows[1:] {
		args, err := xtablesWords(row)
		if err != nil || len(args) < 3 || args[0] != "-A" || args[1] != name {
			return invalid
		}
		args = args[2:]
		if len(args) >= 3 && args[len(args)-3] == "-c" {
			for _, counter := range args[len(args)-2:] {
				if _, err = strconv.ParseUint(counter, 10, 64); err != nil {
					return invalid
				}
			}
			args = args[:len(args)-3]
		}
		prior := chain.Rules[index]
		// Foreign forwarding rules retain their exact native tokens; only
		// authenticated owned generations use the closed semantic grammar.
		if name == "FORWARD" || name == "DOCKER-USER" {
			if !slices.Equal(prior, args) {
				return invalid
			}
			continue
		}
		// Foreign INPUT expressions stay opaque. The full native-save image
		// owns their drift proof; library reads verify positions and ownership.
		if name == "INPUT" && !iptablesReservedArgument(prior) && !iptablesReservedArgument(args) {
			continue
		}
		if strings.HasPrefix(name, firewall.IPTablesDockerChain) {
			before, err := dockerIPTablesRuleKey(name, image.Family, prior)
			after, actualErr := dockerIPTablesRuleKey(name, image.Family, args)
			if err != nil || actualErr != nil || before != after {
				return invalid
			}
			continue
		}
		before, err := iptablesOwnedRuleKey(name, image.Family, prior)
		if err != nil {
			return invalid
		}
		after, err := iptablesOwnedRuleKey(name, image.Family, args)
		if err != nil || before != after {
			return invalid
		}
	}
	return nil
}

// RunIPTablesLibraryBridge is reached only through the explicit private applet.
// The upstream library cannot expose its mutation methods through this bridge.
func RunIPTablesLibraryBridge() error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	raw := os.Getenv(iptablesLibraryEnvironment)
	var request iptablesLibraryBridge
	invalid := errors.New("go-iptables 只读桥接请求无效")
	if len(raw) > 16<<10 || ufwToolJSON([]byte(raw), &request) != nil || request.Version != 3 || !validIPTablesLibraryCommand(request.Command, request.Blocker, request.ExpectedVersion) || request.Deadline <= time.Now().UnixMilli() || request.Deadline > time.Now().Add(8*time.Second).UnixMilli() || len(request.Chains) < 1 || len(request.Chains) > 7 || !request.Docker && len(request.Chains) > 3 {
		return invalid
	}
	seen := map[string]bool{}
	for _, chain := range request.Chains {
		if seen[chain] || !validIPTablesLibraryChain(chain) || !request.Docker && (chain == "FORWARD" || chain == "DOCKER-USER" || strings.HasPrefix(chain, firewall.IPTablesDockerChain)) {
			return invalid
		}
		seen[chain] = true
	}
	if !seen["INPUT"] {
		return invalid
	}
	if err := iptablesLibraryParent(request.Parent); err != nil {
		return err
	}
	action, input := "version", []byte(nil)
	args := os.Args[1:]
	if !slices.Equal(args, []string{"--version"}) {
		if len(args) != 5 && len(args) != 6 {
			return invalid
		}
		if !slices.Equal(args[:3], []string{"-t", "filter", "-S"}) || !slices.Equal(args[len(args)-2:], []string{"--wait", "1"}) {
			return invalid
		}
		action = "list"
		if len(args) == 6 {
			if !slices.Contains(request.Chains, args[3]) {
				return invalid
			}
			input = []byte(args[3])
		}
	}
	ctx, cancel := context.WithDeadline(context.Background(), time.UnixMilli(request.Deadline))
	defer cancel()
	out, err := runIPTablesBound(ctx, request.Command, request.Blocker, action, input)
	if err != nil {
		return err
	}
	if action == "version" {
		_, version, err := firewallVersion(out)
		if err != nil || version != request.ExpectedVersion {
			return invalid
		}
	}
	if err = iptablesLibraryParent(request.Parent); err != nil || ctx.Err() != nil {
		return invalid
	}
	_, err = os.Stdout.Write(out)
	return err
}
