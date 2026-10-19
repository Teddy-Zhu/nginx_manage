package agent

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"nginxpanel/internal/fail2ban"
	"nginxpanel/internal/secure"
)

var fail2banVersion = regexp.MustCompile(`^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}[a-zA-Z0-9.+_-]{0,32}$`)
var fail2banInvocation = regexp.MustCompile(`^[a-f0-9]{32}$`)

type fail2banLiveService struct {
	view       fail2ban.Service
	invocation string
	inode      string
	file       os.FileInfo
}

func fail2banBoundTool(b *fail2banBinding) (fail2ban.Tool, error) {
	tool := fail2banTool("fail2ban-client")
	if !tool.Trusted || tool.Path != b.ClientPath || tool.Resolved != b.ClientResolved {
		return tool, errors.New("已批准客户端路径或权限无法保持核对，须本机检查")
	}
	hash, err := secure.HashRootFile(tool.Resolved, 4<<20)
	if err != nil {
		return tool, errors.New("已批准客户端摘要无法读取，须本机检查")
	}
	if hash != b.ClientSHA256 {
		return tool, errors.New("已批准客户端文件发生变化，须本机重新接入")
	}
	return tool, nil
}
func fail2banCurrentBinding(data string, b *fail2banBinding, required bool) error {
	if !required {
		return nil
	}
	current, err := selectFail2banBinding(data)
	if err != nil || current == nil || current.State != "bound" || current.ID != b.ID {
		return errors.New("实例读取授权已变更，请刷新接入状态")
	}
	if b.managed != nil && (current.managed == nil || b.managed.JailSelection != current.managed.JailSelection) {
		return errors.New("受管 jail 配置在读取期间变化，请刷新")
	}
	return nil
}
func fail2banReadLimited(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > limit {
		return nil, errors.New("宿主机实例身份读取超限")
	}
	return raw, nil
}
func fail2banSocketOwner(path string, pid int64) (string, os.FileInfo, error) {
	if err := existingRootDirectory(filepath.Dir(path)); err != nil {
		return "", nil, errors.New("已接入 Socket 目录未通过 root 保护核对")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return "", nil, errors.New("已接入 Socket 不存在或无法读取")
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != 0 || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm()&0022 != 0 {
		return "", nil, errors.New("已接入 Socket 类型、归属或权限发生变化")
	}
	raw, err := fail2banReadLimited("/proc/net/unix", 2<<20)
	if err != nil {
		return "", nil, errors.New("Unix Socket 内核归属无法完整读取")
	}
	inode := ""
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 8 || fields[7] != path {
			continue
		}
		if inode != "" || len(fields) != 8 || fields[3] != "00010000" || fields[4] != "0001" || fields[5] != "01" {
			return "", nil, errors.New("Socket 监听状态或归属存在歧义")
		}
		value, err := strconv.ParseUint(fields[6], 10, 64)
		if err != nil || value == 0 {
			return "", nil, errors.New("Socket 内核身份无效")
		}
		inode = fields[6]
	}
	if inode == "" {
		return "", nil, errors.New("未发现已接入 Socket 的内核监听")
	}
	dir := "/proc/" + strconv.FormatInt(pid, 10) + "/fd"
	fdInfo, err := os.Stat(dir)
	if err != nil {
		return "", nil, errors.New("服务进程的 Socket 归属不可读取")
	}
	owner, ok := fdInfo.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != 0 {
		return "", nil, errors.New("已接入服务不是 root 实例")
	}
	f, err := os.Open(dir)
	if err != nil {
		return "", nil, errors.New("服务文件描述符无法读取")
	}
	entries, err := f.ReadDir(513)
	closeErr := f.Close()
	if err != nil && err != io.EOF || closeErr != nil || len(entries) > 512 {
		return "", nil, errors.New("服务文件描述符无法完整读取")
	}
	for _, entry := range entries {
		target, err := os.Readlink(filepath.Join(dir, entry.Name()))
		if err == nil && target == "socket:["+inode+"]" {
			return inode, info, nil
		}
	}
	return "", nil, errors.New("Socket 监听不属于已批准服务的主进程")
}
func readFail2banLiveService(ctx context.Context, b *fail2banBinding) (fail2banLiveService, error) {
	var out fail2banLiveService
	raw, err := fail2banRun(ctx, fail2banTool("systemctl"), []string{"show", "--all", "--no-pager", "--property=Id,LoadState,ActiveState,SubState,UnitFileState,MainPID,InvocationID,TriggeredBy", b.Service}, 8192)
	if err != nil {
		return out, errors.New("已接入服务状态无法完整读取")
	}
	values := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok || len(value) > 512 {
			return out, errors.New("服务元数据格式未知")
		}
		switch key {
		case "Id", "LoadState", "ActiveState", "SubState", "UnitFileState", "MainPID", "InvocationID", "TriggeredBy":
		default:
			return out, errors.New("服务元数据包含未知字段")
		}
		if _, duplicate := values[key]; duplicate {
			return out, errors.New("服务元数据重复")
		}
		values[key] = value
	}
	if len(values) != 8 || values["Id"] != b.Service {
		return out, errors.New("服务身份或元数据无法完整核对")
	}
	if values["TriggeredBy"] != "" {
		return out, errors.New("此服务有 Socket 或其他激活依赖，须通过单独的启动授权接入")
	}
	pid, err := strconv.ParseInt(values["MainPID"], 10, 32)
	if err != nil || pid <= 1 || values["LoadState"] != "loaded" || values["ActiveState"] != "active" || values["SubState"] != "running" || !fail2banInvocation.MatchString(values["InvocationID"]) || values["InvocationID"] == strings.Repeat("0", 32) {
		return out, errors.New("已接入服务未处于可核对的运行状态，不尝试连接或启动")
	}
	if values["UnitFileState"] != "" && !fail2banServiceWord.MatchString(values["UnitFileState"]) {
		return out, errors.New("服务开机状态未知")
	}
	out.inode, out.file, err = fail2banSocketOwner(b.Socket, pid)
	if err != nil {
		return out, err
	}
	if b.managed != nil {
		if err = fail2banManagedProcess(ctx, b.managed, pid); err != nil {
			return out, err
		}
	}
	out.invocation = values["InvocationID"]
	out.view = fail2ban.Service{ID: b.Service, Available: true, Load: values["LoadState"], Active: values["ActiveState"], Sub: values["SubState"], UnitFile: values["UnitFileState"], MainPID: &pid}
	return out, nil
}

// Set every early configuration parameter, so status reads neither the global
// configuration nor a client log file. Only version/status verbs are sent.
func fail2banReadArgs(socket, verb string) []string {
	return []string{"-s", socket, "-p", "/dev/null", "--logtarget", "STDERR", "--loglevel", "ERROR", "--syslogsocket", "/dev/null", verb}
}
func readFail2banBound(ctx context.Context, data string, b *fail2banBinding, current bool, jail string) (string, fail2ban.Service, []byte, error) {
	var empty fail2ban.Service
	if err := fail2banCurrentBinding(data, b, current); err != nil {
		return "", empty, nil, err
	}
	program, err := selectFail2banClient(b)
	if err != nil {
		return "", empty, nil, err
	}
	program, err = program.authenticate(ctx)
	if err != nil {
		return "", empty, nil, err
	}
	if err = fail2banCurrentBinding(data, b, current); err != nil {
		return "", empty, nil, err
	}
	var before fail2banLiveService
	var serviceErr, clientErr error
	var clientRaw []byte
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); before, serviceErr = readFail2banLiveService(ctx, b) }()
	go func() { defer wg.Done(); clientRaw, clientErr = program.run(ctx, []string{"--version"}, 4096) }()
	wg.Wait()
	if serviceErr != nil {
		return "", empty, nil, serviceErr
	}
	match := fail2banClientVersion.FindStringSubmatch(strings.TrimSpace(string(clientRaw)))
	if clientErr != nil || match == nil || b.ClientVersion != "" && match[1] != b.ClientVersion {
		return "", empty, nil, errors.New("客户端版本发生变化或无法核对，须本机重新接入")
	}
	if err := fail2banCurrentBinding(data, b, current); err != nil {
		return "", empty, nil, err
	}
	if ctx.Err() != nil {
		return "", empty, nil, errors.New("实例采集已取消或超过期限")
	}
	var versionRaw, statusRaw []byte
	var versionErr, statusErr error
	status := fail2banReadArgs(b.Socket, "status")
	if jail != "" {
		status = append(status, jail)
	}
	wg.Add(2)
	go func() {
		defer wg.Done()
		versionRaw, versionErr = program.run(ctx, fail2banReadArgs(b.Socket, "version"), 4096)
	}()
	go func() { defer wg.Done(); statusRaw, statusErr = program.run(ctx, status, 128<<10) }()
	wg.Wait()
	version := strings.TrimSpace(string(versionRaw))
	if versionErr != nil || statusErr != nil || !fail2banVersion.MatchString(version) || version != match[1] {
		return "", empty, nil, errors.New("服务端版本或完整状态无法核对；不返回部分成功")
	}
	after, err := readFail2banLiveService(ctx, b)
	if err != nil {
		return "", empty, nil, errors.New("读取结束时无法再次核对实例：" + err.Error())
	}
	if before.invocation != after.invocation || *before.view.MainPID != *after.view.MainPID || before.inode != after.inode || !os.SameFile(before.file, after.file) {
		return "", empty, nil, errors.New("读取期间服务或 Socket 身份变化，请重新读取")
	}
	if err = program.unchanged(ctx, data); err != nil {
		return "", empty, nil, err
	}
	if err = fail2banCurrentBinding(data, b, current); err != nil {
		return "", empty, nil, err
	}
	if ctx.Err() != nil {
		return "", empty, nil, errors.New("实例采集已取消或超过期限")
	}
	return version, after.view, statusRaw, nil
}
