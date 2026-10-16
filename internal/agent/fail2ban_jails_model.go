package agent

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"nginxpanel/internal/fail2ban"
	"nginxpanel/internal/firewall"
	"nginxpanel/internal/nginxconfig"
	"nginxpanel/internal/secure"
)

const fail2banJailsKind = "nginx.fail2ban-jails"
const fail2banJailBundleLimit = 256 << 10

type Fail2banJailsRequest = fail2ban.JailsRequest

type fail2banJailIntent struct {
	Basis            fail2banJailBasis     `json:"basis"`
	Nginx            bool                  `json:"nginx"`
	InstallationID   string                `json:"installation_id"`
	EngineKey        string                `json:"engine_key"`
	Target           string                `json:"target"`
	BeforeID         string                `json:"before_id"`
	AfterID          string                `json:"after_id"`
	Invocation       string                `json:"invocation"`
	SocketInode      string                `json:"socket_inode"`
	BeforeRegistry   fail2banNginxRegistry `json:"before_registry"`
	AfterRegistry    fail2banNginxRegistry `json:"after_registry"`
	RollbackRegistry fail2banNginxRegistry `json:"rollback_registry"`
	BansHash         string                `json:"bans_hash"`
	EffectsPossible  bool                  `json:"effects_possible"`
}

type Fail2banJailsOperation = fail2ban.JailsOperation

func fail2banJailsView(r Record) Fail2banJailsOperation {
	return Fail2banJailsOperation{ID: r.OperationID, State: r.State, Stage: r.Stage, BeforeID: r.Fail2banJails.BeforeID, AfterID: r.Fail2banJails.AfterID, RequestHash: r.RequestHash, Target: r.Fail2banJails.Target, Error: r.Error}
}

// Sources come only from the active root Nginx manifest or the fixed root login log.
// User labels and logical resource IDs never become executable config text.
type fail2banJailBundle struct {
	HostProtectionID string              `json:"host_protection_id"`
	HostProtected    []string            `json:"host_protected"`
	Schema           int                 `json:"schema"`
	ID               string              `json:"id"`
	InstallationID   string              `json:"installation_id"`
	EngineKey        string              `json:"engine_key"`
	NginxDir         string              `json:"nginx_dir"`
	NginxHash        string              `json:"nginx_hash"`
	Policy           fail2ban.Policy     `json:"policy"`
	Sources          map[string]string   `json:"sources"`
	Proxies          map[string][]string `json:"proxies"`
}

func fail2banJailNameFor(id string) string { return "nginxpanel-" + id }
func (r *fail2banManagedRecord) jailBundlePath(id string) string {
	return filepath.Join(r.work(), "jail-bundles", id+".json")
}
func (r *fail2banManagedRecord) jailCandidate(id string) string {
	return filepath.Join(r.work(), "jail-configs", id)
}

func (b fail2banJailBundle) valid(r *fail2banManagedRecord) error {
	if b.Schema != 1 || !validID(b.ID) || b.InstallationID != r.OperationID || b.EngineKey != fail2banNginxEngineKey(r.binding()) || !(b.NginxDir == "" && b.NginxHash == "" || (validID(b.NginxDir) || b.NginxDir == "bootstrap") && fail2banDigest.MatchString(b.NginxHash)) || b.HostProtected == nil || b.Sources == nil || b.Proxies == nil || len(b.Sources) > 32 || !validClientDenyBindings(b.Proxies) {
		return errors.New("受管 jail 配置包身份或来源无效")
	}
	normalized, err := b.Policy.Normalize()
	if err != nil || normalized.Hash() != b.Policy.Hash() {
		return errors.New("受管 jail 配置包内容无效")
	}
	count := 0
	host := false
	resources := map[string]bool{}
	for _, j := range b.Policy.Jails {
		if !j.Enabled {
			continue
		}
		count++
		if j.Template == fail2ban.PanelLoginTemplate && j.Action == "host-input" {
			host = true
			if b.Sources[j.ID] != fail2banPanelLoginPath {
				return errors.New("面板 jail 仅允许固定 root 登录日志")
			}
			continue
		}
		resources[j.ResourceID] = true
		kind, resource, ok := nginxconfig.ManagedLogPath(b.Sources[j.ID])
		if j.Action != "nginx-client" || !ok || kind != "nginx" || resource != j.ResourceID || filepath.Base(b.Sources[j.ID]) != "access.log" || len(b.Proxies[j.ResourceID]) == 0 || b.NginxDir == "" {
			return errors.New("受管 jail 仅允许已绑定的 Nginx 客户端动作或面板宿主机入口")
		}
	}
	if count != len(b.Sources) || len(resources) != len(b.Proxies) {
		return errors.New("受管 jail 配置包包含多余日志或代理来源")
	}
	if host {
		protected, err := (firewall.NFTBanSet{Addresses: []string{}, Protected: b.HostProtected}).Normalize()
		a, _ := json.Marshal(protected.Protected)
		expected, _ := json.Marshal(b.HostProtected)
		if !validID(b.HostProtectionID) || len(b.HostProtected) == 0 || err != nil || string(a) != string(expected) {
			return errors.New("面板 jail 保护依据不完整")
		}
	} else if b.HostProtectionID != "" || len(b.HostProtected) != 0 {
		return errors.New("非宿主机 jail 不接受保护批准材料")
	}
	return nil
}

func loadFail2banJailBundle(r *fail2banManagedRecord, id string) (*fail2banJailBundle, error) {
	if id == "" {
		return nil, nil
	}
	if !validID(id) {
		return nil, errors.New("受管 jail 配置包 ID 无效")
	}
	var b fail2banJailBundle
	if err := readFail2banNginxJSON(r.jailBundlePath(id), &b, fail2banJailBundleLimit); err != nil {
		return nil, err
	}
	if b.ID != id {
		return nil, errors.New("受管 jail 配置包指针不匹配")
	}
	return &b, b.valid(r)
}

func selectedFail2banJails(r *fail2banManagedRecord) (string, *fail2banJailBundle, error) {
	var pointer struct {
		ID string `json:"id"`
	}
	err := readFail2banNginxJSON(filepath.Join(r.work(), "jail-current.json"), &pointer, 1024)
	if os.IsNotExist(err) {
		return "", nil, nil
	}
	if err != nil {
		return "", nil, err
	}
	b, err := loadFail2banJailBundle(r, pointer.ID)
	return pointer.ID, b, err
}

func selectFail2banJails(r *fail2banManagedRecord, id string) error {
	if _, err := loadFail2banJailBundle(r, id); err != nil {
		return err
	}
	return rootJSONWrite(filepath.Join(r.work(), "jail-current.json"), struct {
		ID string `json:"id"`
	}{id}, 1024)
}

func saveFail2banJailBundle(r *fail2banManagedRecord, b fail2banJailBundle) error {
	if err := b.valid(r); err != nil {
		return err
	}
	if err := secure.RootDirectory(filepath.Dir(r.jailBundlePath(b.ID)), 0700); err != nil {
		return err
	}
	raw, err := json.Marshal(b)
	if err != nil || len(raw) > fail2banJailBundleLimit {
		return errors.New("受管 jail 配置包超出预算")
	}
	return writeFail2banJailImmutable(r.jailBundlePath(b.ID), raw, fail2banJailBundleLimit)
}

func fail2banJailNames(b *fail2banJailBundle) []string {
	names := []string{}
	if b != nil {
		for _, j := range b.Policy.Jails {
			if j.Enabled {
				names = append(names, fail2banJailNameFor(j.ID))
			}
		}
	}
	sort.Strings(names)
	return names
}

func ownedFail2banJails(b *fail2banBinding) (map[string]bool, error) {
	out := map[string]bool{}
	if b.managed == nil {
		return out, nil
	}
	bundle, err := loadFail2banJailBundle(b.managed, b.managed.jailSelection)
	if err != nil {
		return nil, err
	}
	for _, name := range fail2banJailNames(bundle) {
		out[name] = true
	}
	return out, nil
}

func fail2banJailConfig(r *fail2banManagedRecord, b *fail2banJailBundle) (map[string]string, error) {
	files := map[string]string{}
	for name, content := range r.files() {
		if name != fail2banManagedUnit {
			files[filepath.Base(name)] = content
		}
	}
	if b == nil {
		return files, nil
	}
	if err := b.valid(r); err != nil {
		return nil, err
	}
	var jail strings.Builder
	for _, j := range b.Policy.Jails {
		if !j.Enabled {
			continue
		}
		filter, err := fail2ban.FilterConfig(j.Template)
		if err != nil {
			return nil, err
		}
		files["filter.d/nginxpanel-"+j.Template+".conf"] = filter
		values, err := fail2banIgnoreSet(j, b)
		if err != nil {
			return nil, err
		}
		action, _, err := fail2banJailAction(r, j)
		if err != nil {
			return nil, err
		}
		jail.WriteString("[" + fail2banJailNameFor(j.ID) + "]\nenabled = true\nbackend = polling\nusedns = no\nlogencoding = utf-8\nfilter = nginxpanel-" + j.Template + "\naction = " + action + "\nlogpath = " + filepath.Join(r.DataDir, b.Sources[j.ID]) + "\nignoreip = " + strings.Join(values, " ") + "\nbantime = " + strconv.FormatInt(j.BanTime, 10) + "\nfindtime = " + strconv.FormatInt(j.FindTime, 10) + "\nmaxretry = " + strconv.Itoa(j.MaxRetry) + "\n\n")
	}
	if jail.Len() > 0 {
		// Installation admission restricts both paths to safe absolute ASCII.
		if strings.Trim(r.ManagerPath+r.DataDir, "/abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-") != "" {
			return nil, errors.New("动作桥程序或数据目录不符合固定路径约束")
		}
		files["jail.d/nginxpanel.conf"] = jail.String()
		for _, j := range b.Policy.Jails {
			if !j.Enabled {
				continue
			}
			action, command, err := fail2banJailAction(r, j)
			if err != nil {
				return nil, err
			}
			files["action.d/"+action+".conf"] = "[Definition]\nactionstart = " + command + "\nactionstop = " + command + "\nactioncheck =\nactionban = " + command + "\nactionunban = " + command + "\n\n[Init]\ntimeout = 5\n"
		}
	}
	return files, nil
}

const fail2banPanelLoginPath = "agent/security/login.jsonl"

func fail2banJailAction(r *fail2banManagedRecord, j fail2ban.DesiredJail) (string, string, error) {
	if strings.Trim(r.ManagerPath+r.DataDir, "/abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-") != "" {
		return "", "", errors.New("动作桥路径不符合固定约束")
	}
	action, command := "nginxpanel-nginx", "fail2ban-nginx-refresh"
	if j.Action == "host-input" && j.Template == fail2ban.PanelLoginTemplate {
		action, command = "nginxpanel-host-input", "fail2ban-host-sync-refresh"
	} else if j.Action != "nginx-client" {
		return "", "", errors.New("该 jail 动作尚不支持")
	}
	return action, r.ManagerPath + " " + command + " --data-dir " + r.DataDir + " --fail2ban-scope host", nil
}

func fail2banJailNeedsNginx(b *fail2banJailBundle) bool {
	if b != nil {
		for _, j := range b.Policy.Jails {
			if j.Enabled && j.Action == "nginx-client" {
				return true
			}
		}
	}
	return false
}
func fail2banJailNeedsHost(b *fail2banJailBundle) bool {
	if b != nil {
		for _, j := range b.Policy.Jails {
			if j.Enabled && j.Action == "host-input" {
				return true
			}
		}
	}
	return false
}
