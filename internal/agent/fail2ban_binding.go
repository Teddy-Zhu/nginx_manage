package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"golang.org/x/sys/unix"
	"nginxpanel/internal/fail2ban"
	"nginxpanel/internal/secure"
)

var fail2banUnit = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.@-]{0,110}\.service$`)
var fail2banDigest = regexp.MustCompile(`^[a-f0-9]{64}$`)

type fail2banBinding struct {
	managed        *fail2banManagedRecord
	Schema         int    `json:"schema"`
	ID             string `json:"id"`
	PreviousID     string `json:"previous_id"`
	State          string `json:"state"`
	Service        string `json:"service"`
	Socket         string `json:"socket"`
	ClientPath     string `json:"client_path"`
	ClientResolved string `json:"client_resolved"`
	ClientSHA256   string `json:"client_sha256"`
	ClientVersion  string `json:"client_version"`
	ServiceControl bool   `json:"service_control"`
	UnitSHA256     string `json:"unit_sha256"`
	ApprovedAt     int64  `json:"approved_at"`
}

func (b *fail2banBinding) view() fail2ban.BindingView {
	if b == nil {
		return fail2ban.BindingView{Engine: fail2ban.EngineIdentity{Owner: "none"}, State: "unbound", Reason: "尚未由本机 root 接入已有实例"}
	}
	out := fail2ban.BindingView{Engine: fail2ban.EngineIdentity{Owner: "existing"}, State: b.State, ID: b.ID, Service: b.Service, Socket: b.Socket, ClientPath: b.ClientResolved, ClientVersion: b.ClientVersion, ServiceControl: b.ServiceControl, ApprovedAt: b.ApprovedAt}
	if b.managed != nil {
		out.Engine = b.managed.engine()
		out.ServiceControl = true
		out.Reason = "受管安装可单独控制服务；jail 配置及保护状态须分别核对"
	}
	if b.State == "unbound" {
		out.Engine = fail2ban.EngineIdentity{Owner: "none"}
		out.Reason = "实例读取授权已撤销；现有服务及 jail 继续由原所有者管理"
	}
	return out
}
func fail2banBindingDir(data string) string { return filepath.Join(data, "agent", "fail2ban") }
func validFail2banSocket(path string) bool {
	return strings.HasPrefix(path, "/run/") && filepath.Clean(path) == path && len(path) < 108 && !strings.ContainsAny(path, " \t\r\n\x00\\")
}
func loadFail2banBinding(data string) (*fail2banBinding, error) {
	var index struct {
		ID string `json:"id"`
	}
	raw, err := listenerRead(filepath.Join(fail2banBindingDir(data), "current.json"), 1024)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&index) != nil || d.Decode(new(any)) != io.EOF || !validID(index.ID) {
		return nil, errors.New("Fail2ban 接入指针无效")
	}
	raw, err = listenerRead(filepath.Join(fail2banBindingDir(data), "bindings", index.ID+".json"), 8192)
	if err != nil {
		return nil, err
	}
	var b fail2banBinding
	d = json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&b) != nil || d.Decode(new(any)) != io.EOF || b.Schema != 1 || b.ID != index.ID || b.PreviousID != "" && !validID(b.PreviousID) || b.ApprovedAt <= 0 {
		return nil, errors.New("Fail2ban 接入记录无效")
	}
	if b.State == "unbound" {
		if b.Service != "" || b.Socket != "" || b.ClientPath != "" || b.ClientResolved != "" || b.ClientSHA256 != "" || b.ClientVersion != "" || b.ServiceControl || b.UnitSHA256 != "" {
			return nil, errors.New("Fail2ban 撤销记录无效")
		}
	} else if b.State != "bound" || !fail2banUnit.MatchString(b.Service) || !validFail2banSocket(b.Socket) || !fail2banDigest.MatchString(b.ClientSHA256) || !fail2banVersion.MatchString(b.ClientVersion) || !filepath.IsAbs(b.ClientResolved) || filepath.Clean(b.ClientResolved) != b.ClientResolved || !validFail2banClientPath(b.ClientPath) {
		return nil, errors.New("Fail2ban 固定实例登记无效")
	}
	if b.ServiceControl && (!fail2banDigest.MatchString(b.UnitSHA256) || b.Service == fail2banManagedService) || !b.ServiceControl && b.UnitSHA256 != "" {
		return nil, errors.New("Fail2ban 服务控制授权无效")
	}
	return &b, nil
}
func validFail2banClientPath(path string) bool {
	for _, dir := range []string{"/usr/bin", "/usr/sbin", "/bin", "/sbin"} {
		if path == dir+"/fail2ban-client" {
			return true
		}
	}
	return false
}
func fail2banBindingView(data string) fail2ban.BindingView {
	b, err := selectFail2banBinding(data)
	if err != nil {
		out := fail2ban.UnknownBinding()
		out.Reason = "root 接入或受管安装登记无法核对，须在本机检查"
		return out
	}
	return b.view()
}
func saveFail2banBinding(data string, b *fail2banBinding) error {
	if b.managed != nil {
		return errors.New("受管读取授权不能写为已有实例接入记录")
	}
	dir := filepath.Join(fail2banBindingDir(data), "bindings")
	if err := secure.RootDirectory(dir, 0700); err != nil {
		return err
	}
	// Keep each approval/revocation before atomically publishing its pointer.
	tmp := filepath.Join(dir, "."+secure.ID()+".tmp")
	if err := rootJSONWrite(tmp, b, 8192); err != nil {
		return err
	}
	defer os.Remove(tmp)
	if err := unix.Renameat2(unix.AT_FDCWD, tmp, unix.AT_FDCWD, filepath.Join(dir, b.ID+".json"), unix.RENAME_NOREPLACE); err != nil {
		return err
	}
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	err = f.Sync()
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return rootJSONWrite(filepath.Join(fail2banBindingDir(data), "current.json"), struct {
		ID string `json:"id"`
	}{b.ID}, 1024)
}

// ManageFail2banBinding is local-root-only, without an IPC or public write route.
// Optional service control does not grant ownership of existing jails.
func ManageFail2banBinding(ctx context.Context, data, scope, action, service, socket string, serviceControl bool) (fail2ban.BindingView, error) {
	out := fail2ban.UnknownBinding()
	if os.Geteuid() != 0 || scope != "host" || (&HostDNS{Scope: scope}).hostScopeReason() != "" {
		return out, errors.New("Fail2ban 接入须在宿主机由 root 指定 --fail2ban-scope=host")
	}
	if !filepath.IsAbs(data) || filepath.Clean(data) != data {
		return out, errors.New("Fail2ban 数据目录须为规范绝对路径")
	}
	if action != "bind" && action != "binding" && action != "unbind" {
		return out, errors.New("未知 Fail2ban 接入操作")
	}
	if action != "bind" && serviceControl {
		return out, errors.New("仅接入操作可以授予服务控制")
	}
	if action == "binding" {
		b, err := loadFail2banBinding(data)
		if err != nil {
			return out, err
		}
		return b.view(), nil
	}
	unlock, err := (&Journal{Dir: fail2banBindingDir(data)}).rootLock("binding.lock")
	if err != nil {
		return out, err
	}
	defer unlock()
	if err = fail2banManagedIdle(data, ""); err != nil {
		return out, err
	}
	prior, err := loadFail2banBinding(data)
	if err != nil {
		return out, err
	}
	b := &fail2banBinding{Schema: 1, ID: secure.ID(), State: "unbound", ApprovedAt: time.Now().Unix()}
	if prior != nil {
		b.PreviousID = prior.ID
	}
	if action == "unbind" {
		if prior == nil || prior.State == "unbound" {
			return prior.view(), nil
		}
	} else {
		if fail2banManagedData(data) {
			r, e := loadFail2banManaged(data)
			if e != nil {
				return out, e
			}
			if r != nil && r.State != "rolled-back" {
				return out, errors.New("已有受管安装登记，不能另行接入已有实例")
			}
		}
		if !fail2banUnit.MatchString(service) || !validFail2banSocket(socket) {
			return out, errors.New("须指定固定 service 及 /run 下规范的 Unix Socket 路径")
		}
		tool := fail2banTool("fail2ban-client")
		if !tool.Trusted {
			return out, errors.New("固定系统路径中没有受信 Fail2ban 客户端")
		}
		hash, err := secure.HashRootFile(tool.Resolved, 4<<20)
		if err != nil {
			return out, err
		}
		b.State, b.Service, b.Socket, b.ClientPath, b.ClientResolved, b.ClientSHA256 = "bound", service, socket, tool.Path, tool.Resolved, hash
		call, cancel := context.WithTimeout(ctx, 8*time.Second)
		defer cancel()
		version, _, raw, err := readFail2banBound(call, data, b, false, "")
		if err != nil {
			return out, err
		}
		if _, err = parseFail2banJails(raw); err != nil {
			return out, err
		}
		b.ClientVersion = version
		if serviceControl {
			if service == fail2banManagedService {
				return out, errors.New("已有实例控制不能占用独立受管服务名称")
			}
			b.UnitSHA256, err = fail2banExistingUnitHash(call, service)
			if err != nil {
				return out, err
			}
			b.ServiceControl = true
		}
		if prior != nil && prior.State == "bound" && prior.Service == b.Service && prior.Socket == b.Socket && prior.ClientPath == b.ClientPath && prior.ClientResolved == b.ClientResolved && prior.ClientSHA256 == b.ClientSHA256 && prior.ClientVersion == b.ClientVersion && prior.ServiceControl == b.ServiceControl && prior.UnitSHA256 == b.UnitSHA256 {
			return prior.view(), nil
		}
	}
	if err := ctx.Err(); err != nil {
		return out, err
	}
	if err = fail2banExistingOwnershipIdle(data); err != nil {
		return out, err
	}
	if err = saveFail2banBinding(data, b); err != nil {
		return out, err
	}
	stored, err := loadFail2banBinding(data)
	if err != nil {
		return out, err
	}
	if stored == nil || stored.ID != b.ID {
		return out, errors.New("Fail2ban 接入发布结果未确认")
	}
	return stored.view(), nil
}
