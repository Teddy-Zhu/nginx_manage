package agent

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"nginxpanel/internal/fail2ban"
	"nginxpanel/internal/fault"
	"nginxpanel/internal/secure"
)

// Check each source component before following links, including /lib aliases;
// checking only the resolved file would permit an untrusted redirecting path.
func fail2banExistingUnitPath(name string) (string, error) {
	if !filepath.IsAbs(name) || filepath.Clean(name) != name || len(name) > 4096 || strings.ContainsAny(name, " \t\r\n\x00\\") {
		return "", errors.New("单元文件路径无效")
	}
	pending := strings.Split(name, "/")
	current, links, steps := "/", 0, 0
	for len(pending) > 0 {
		steps++
		if steps > 256 {
			return "", errors.New("单元文件路径解析超过预算")
		}
		part := pending[0]
		pending = pending[1:]
		switch part {
		case "", ".":
			continue
		case "..":
			current = filepath.Dir(current)
			continue
		}
		next := filepath.Join(current, part)
		if len(next) > 4096 {
			return "", errors.New("单元文件路径过长")
		}
		info, err := os.Lstat(next)
		if err != nil {
			return "", err
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 {
			return "", errors.New("单元文件路径须由 root 持有")
		}
		if info.Mode()&os.ModeSymlink != 0 {
			links++
			if links > 16 {
				return "", errors.New("单元文件路径链接超过预算")
			}
			target, err := os.Readlink(next)
			if err != nil || target == "" || len(target) > 4096 || strings.ContainsAny(target, " \t\r\n\x00\\") {
				return "", errors.New("单元文件链接目标无效")
			}
			if filepath.IsAbs(target) {
				current = "/"
			}
			// Resolve links before '..', matching the kernel's path semantics.
			pending = append(strings.Split(target, "/"), pending...)
			continue
		}
		if info.Mode().Perm()&0022 != 0 || len(pending) > 0 && !info.IsDir() {
			return "", errors.New("单元文件路径不可被其他账户写入")
		}
		current = next
	}
	return current, nil
}

// The local root grant pins loaded unit files, including drop-ins. A remote
// request can select neither a service name nor a new unit configuration.
func fail2banExistingUnitHash(ctx context.Context, service string) (string, error) {
	if !fail2banUnit.MatchString(service) || service == fail2banManagedService {
		return "", errors.New("已有实例服务名称无效")
	}
	metadata := func() (string, map[string]string, error) {
		raw, err := fail2banRun(ctx, fail2banTool("systemctl"), []string{"show", "--all", "--no-pager", "--property=FragmentPath,DropInPaths,NeedDaemonReload,TriggeredBy", service}, 8192)
		if err != nil {
			return "", nil, errors.New("已有实例的加载单元无法读取")
		}
		values := map[string]string{}
		for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
			key, value, ok := strings.Cut(line, "=")
			if !ok {
				return "", nil, errors.New("已有实例单元属性格式未知")
			}
			switch key {
			case "FragmentPath", "DropInPaths", "NeedDaemonReload", "TriggeredBy":
			default:
				return "", nil, errors.New("已有实例单元属性包含未知字段")
			}
			if _, exists := values[key]; exists {
				return "", nil, errors.New("已有实例单元属性重复")
			}
			values[key] = value
		}
		if len(values) != 4 || values["FragmentPath"] == "" || values["NeedDaemonReload"] != "no" || values["TriggeredBy"] != "" {
			return "", nil, errors.New("已有实例单元未加载、待重新加载或存在其他激活来源，须本机核对")
		}
		return string(raw), values, nil
	}
	before, values, err := metadata()
	if err != nil {
		return "", err
	}
	paths := append([]string{values["FragmentPath"]}, strings.Fields(values["DropInPaths"])...)
	if len(paths) > 17 {
		return "", errors.New("已有实例单元覆盖项超过核对预算")
	}
	type unitFile struct{ Path, Resolved, SHA256 string }
	files := make([]unitFile, 0, len(paths))
	seen := map[string]bool{}
	for _, name := range paths {
		if !filepath.IsAbs(name) || filepath.Clean(name) != name || len(name) > 1024 || strings.ContainsAny(name, " \t\r\n\x00\\") || seen[name] {
			return "", errors.New("已有实例单元路径无效或重复")
		}
		seen[name] = true
		resolved, err := fail2banExistingUnitPath(name)
		if err != nil {
			return "", errors.New("已有实例单元路径无法解析")
		}
		hash, err := secure.HashRootFile(resolved, 256<<10)
		if err != nil {
			return "", errors.New("已有实例单元文件的内容或 root 保护无法核对")
		}
		after, err := fail2banExistingUnitPath(name)
		if err != nil || after != resolved {
			return "", errors.New("已有实例单元路径在读取期间变化")
		}
		files = append(files, unitFile{name, resolved, hash})
	}
	after, _, err := metadata()
	if err != nil || after != before {
		return "", errors.New("已有实例加载单元在读取期间变化")
	}
	if err = ctx.Err(); err != nil {
		return "", err
	}
	raw, _ := json.Marshal(files)
	return secure.Hash(raw), nil
}

func fail2banExistingControlBinding(ctx context.Context, data, id string) (*fail2banBinding, error) {
	b, err := selectFail2banBinding(data)
	if err != nil {
		return nil, err
	}
	if b == nil || b.managed != nil || b.State != "bound" || !b.ServiceControl || id != "" && b.ID != id {
		return nil, fault.Conflict("已有实例尚未由本机 root 授予服务控制，或原授权已变更")
	}
	if _, err = fail2banBoundTool(b); err != nil {
		return nil, err
	}
	hash, err := fail2banExistingUnitHash(ctx, b.Service)
	if err != nil {
		return nil, err
	}
	if hash != b.UnitSHA256 {
		return nil, errors.New("已有实例单元文件或覆盖项已变化，须本机重新接入")
	}
	return b, nil
}

func fail2banExistingStopped(b *fail2banBinding, service fail2ban.Service) error {
	if !service.Available || service.ID != b.Service || service.MainPID == nil || *service.MainPID != 0 || service.Active != "inactive" && service.Active != "failed" {
		return errors.New("已有实例停止状态尚未确认")
	}
	if _, err := os.Lstat(b.Socket); !os.IsNotExist(err) {
		return errors.New("原 Socket 尚未移除或无法核对，停止结果未确认")
	}
	raw, err := fail2banReadLimited("/proc/net/unix", 2<<20)
	if err != nil {
		return errors.New("Socket 内核状态无法完整核对")
	}
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 8 && fields[7] == b.Socket {
			return errors.New("原 Socket 仍存在内核引用，停止结果未确认")
		}
	}
	return nil
}

// The caller holds the lifecycle, optional Nginx and binding locks.
func (l *fail2banLifecycle) existingPlan(ctx context.Context, out fail2ban.LifecyclePlan) (fail2ban.LifecyclePlan, error) {
	b, err := fail2banExistingControlBinding(ctx, l.server.DataDir, "")
	if err != nil {
		return out, err
	}
	service, invocation, err := lifecycleServiceFor(ctx, b.Service)
	if err != nil {
		return out, err
	}
	if service.Load != "loaded" {
		return out, fault.Conflict("已接入服务未完整加载")
	}
	if service.Active == "active" {
		_, _, raw, err := readFail2banBound(ctx, l.server.DataDir, b, true, "")
		if err != nil {
			return out, err
		}
		jails, err := parseFail2banJails(raw)
		if err != nil {
			return out, err
		}
		for _, jail := range jails {
			out.Jails = append(out.Jails, jail.Name)
		}
		sort.Strings(out.Jails)
	} else if err = fail2banExistingStopped(b, service); err != nil {
		return out, err
	}
	after, afterInvocation, err := lifecycleServiceFor(ctx, b.Service)
	if err != nil || invocation != afterInvocation || !sameFail2banLifecycleService(service, after) {
		return out, errors.New("已有实例服务代次或状态在预览期间变化")
	}
	out.Managed, out.Service, out.Input.BaseID = readFail2banManaged(l.server.DataDir), service, b.ID
	switch out.Input.Action {
	case "start":
		out.Impacts = []string{"启动已接入的全局 Fail2ban 服务，按原实例配置恢复全部 jail，包括 SSH 等系统保护", "保留原配置与状态库；封禁恢复由官方引擎决定"}
	case "stop":
		out.Impacts = []string{"停止已接入的全局 Fail2ban 服务，影响全部 jail，包括 SSH 等系统保护", "原配置与状态库保留；官方服务停止不代表本应用动作集合已经清空，动作状态须另行核对"}
	case "enable":
		out.Impacts = []string{"设置已接入的全局 Fail2ban 服务开机启用，影响全部 jail 的开机保护；当前服务不启动"}
	case "disable":
		out.Impacts = []string{"取消已接入的全局 Fail2ban 服务开机启用，全部 jail 将失去此开机启动保障；当前服务不停止"}
	default:
		return out, fault.Invalid("已有实例仅允许服务控制")
	}
	raw, _ := json.Marshal(struct {
		Input      fail2ban.LifecycleInput
		Binding    *fail2banBinding
		Service    fail2ban.Service
		Invocation string
		Jails      []string
	}{out.Input, b, service, invocation, out.Jails})
	out.Input.Target = secure.Hash(raw)
	return out, ctx.Err()
}

func sameFail2banLifecycleService(a, b fail2ban.Service) bool {
	left, _ := json.Marshal(a)
	right, _ := json.Marshal(b)
	return string(left) == string(right)
}

func (l *fail2banLifecycle) dispatchExisting(ctx context.Context, request fail2ban.LifecycleRequest) error {
	unlock, err := (&Journal{Dir: fail2banBindingDir(l.server.DataDir)}).rootLock("binding.lock")
	if err != nil {
		return err
	}
	defer unlock()
	plan, err := l.plan(ctx, request.Input.LifecyclePreviewInput, request.OperationID)
	if err != nil {
		return err
	}
	if plan.Input != request.Input {
		return errors.New("已有实例派发前基准变化，未发送服务命令")
	}
	// The durable Sent marker is already present. Never invoke this path during
	// recovery, even if the process is interrupted before systemctl returns.
	budget := 25 * time.Second
	if request.Input.Action == "start" {
		budget = 70 * time.Second
	}
	_, err = fail2banManagedExec(ctx, fail2banTool("systemctl"), []string{request.Input.Action, plan.Service.ID}, budget, 8192)
	return err
}

func (l *fail2banLifecycle) proveExisting(ctx context.Context, input fail2ban.LifecycleInput) (fail2ban.Service, error) {
	b, err := fail2banExistingControlBinding(ctx, l.server.DataDir, input.BaseID)
	if err != nil {
		return fail2ban.Service{}, err
	}
	service, invocation, err := lifecycleServiceFor(ctx, b.Service)
	if err != nil {
		return service, err
	}
	if service.Load != "loaded" {
		return service, errors.New("原全局服务加载状态无法确认")
	}
	switch input.Action {
	case "start":
		var raw []byte
		_, service, raw, err = readFail2banBound(ctx, l.server.DataDir, b, true, "")
		if err == nil {
			_, err = parseFail2banJails(raw)
		}
	case "stop":
		err = fail2banExistingStopped(b, service)
	case "enable":
		if service.UnitFile != "enabled" {
			err = errors.New("全局服务开机启用状态尚未确认")
		}
	case "disable":
		if service.UnitFile != "disabled" {
			err = errors.New("全局服务开机停用状态尚未确认")
		}
	default:
		err = errors.New("已有实例服务操作未知")
	}
	if err != nil {
		return service, err
	}
	if _, err = fail2banExistingControlBinding(ctx, l.server.DataDir, input.BaseID); err != nil {
		return service, err
	}
	after, afterInvocation, err := lifecycleServiceFor(ctx, b.Service)
	if err != nil || invocation != afterInvocation || !sameFail2banLifecycleService(service, after) {
		return service, errors.New("全局服务在结果核对期间变化")
	}
	return service, err
}
