package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"

	"golang.org/x/sys/unix"
	"nginxpanel/internal/fail2ban"
	"nginxpanel/internal/fault"
	"nginxpanel/internal/secure"
)

type fail2banNginxGrant struct {
	Jail       string `json:"jail"`
	ResourceID string `json:"resource_id"`
	EngineKey  string `json:"engine_key"`
}

type fail2banNginxRegistry struct {
	Schema      int                  `json:"schema"`
	ID          string               `json:"id"`
	PreviousID  string               `json:"previous_id"`
	RequestHash string               `json:"request_hash"`
	ApprovedAt  int64                `json:"approved_at"`
	Grants      []fail2banNginxGrant `json:"grants"`
}

type Fail2banNginxRequest struct {
	Protocol    int    `json:"protocol"`
	OperationID string `json:"operation_id"`
	BaseID      string `json:"base_id"`
	Jail        string `json:"jail"`
	ResourceID  string `json:"resource_id"`
	Action      string `json:"action"`
}

func fail2banNginxDir(data string) string {
	return filepath.Join(data, "agent", "fail2ban", "nginx")
}

func readFail2banNginxJSON(path string, value any, limit int64) error {
	raw, err := listenerRead(path, limit)
	if err != nil {
		return err
	}
	return decodeFail2banNginxJSON(raw, value)
}

func decodeFail2banNginxJSON(raw []byte, value any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(value) != nil || d.Decode(new(any)) != io.EOF {
		return errors.New("Nginx 动作授权记录格式无效")
	}
	return nil
}

func loadFail2banNginxRegistry(data string) (fail2banNginxRegistry, error) {
	empty := fail2banNginxRegistry{Schema: 1, Grants: []fail2banNginxGrant{}}
	dir := fail2banNginxDir(data)
	if err := existingRootDirectory(dir); err != nil {
		if os.IsNotExist(err) {
			return empty, nil
		}
		return empty, err
	}
	var pointer struct {
		ID string `json:"id"`
	}
	if err := readFail2banNginxJSON(filepath.Join(dir, "current.json"), &pointer, 1024); err != nil {
		if os.IsNotExist(err) {
			return empty, nil
		}
		return empty, err
	}
	if !validID(pointer.ID) {
		return empty, errors.New("Nginx 动作授权指针无效")
	}
	var r fail2banNginxRegistry
	if err := readFail2banNginxJSON(filepath.Join(dir, "grants", pointer.ID+".json"), &r, 32<<10); err != nil {
		return empty, err
	}
	if r.ID != pointer.ID {
		return empty, errors.New("Nginx 动作授权指针不匹配")
	}
	if err := validFail2banNginxRegistry(r, false); err != nil {
		return empty, err
	}
	return r, nil
}

func validFail2banNginxRegistry(r fail2banNginxRegistry, allowEmpty bool) error {
	if allowEmpty && r.Schema == 1 && r.ID == "" && r.PreviousID == "" && r.RequestHash == "" && r.ApprovedAt == 0 && r.Grants != nil && len(r.Grants) == 0 {
		return nil
	}
	if r.Schema != 1 || !validID(r.ID) || r.PreviousID != "" && !validID(r.PreviousID) || r.PreviousID == r.ID || r.ApprovedAt <= 0 || !fail2banDigest.MatchString(r.RequestHash) || r.Grants == nil || len(r.Grants) > 32 {
		return errors.New("Nginx 动作授权内容无效")
	}
	last := ""
	for _, grant := range r.Grants {
		if !fail2banJailName.MatchString(grant.Jail) || grant.Jail <= last || !validID(grant.ResourceID) || !fail2banDigest.MatchString(grant.EngineKey) {
			return errors.New("Nginx 动作授权绑定无效")
		}
		last = grant.Jail
	}
	return nil
}

// Managed lifecycle event IDs change on service control; installation identity
// stays stable. An existing-instance read grant must be reapproved after rebind.
func fail2banNginxEngineKey(b *fail2banBinding) string {
	id := b.ID
	if b.managed != nil {
		id = ""
	}
	raw, _ := json.Marshal(struct {
		ID, Service, Socket, ClientPath, ClientResolved, ClientSHA256, ClientVersion string
		Engine                                                                       fail2ban.EngineIdentity
	}{id, b.Service, b.Socket, b.ClientPath, b.ClientResolved, b.ClientSHA256, b.ClientVersion, b.view().Engine})
	return secure.Hash(raw)
}

func saveFail2banNginxRegistry(data string, r fail2banNginxRegistry) error {
	if err := validFail2banNginxRegistry(r, false); err != nil {
		return err
	}
	dir := fail2banNginxDir(data)
	grants := filepath.Join(dir, "grants")
	if err := secure.RootDirectory(grants, 0700); err != nil {
		return err
	}
	entries, err := os.ReadDir(grants)
	if err != nil {
		return err
	}
	path := filepath.Join(grants, r.ID+".json")
	var saved fail2banNginxRegistry
	if err = readFail2banNginxJSON(path, &saved, 32<<10); err == nil {
		existingGrants, _ := json.Marshal(saved.Grants)
		requestedGrants, _ := json.Marshal(r.Grants)
		if saved.Schema != r.Schema || saved.ID != r.ID || saved.ApprovedAt <= 0 || saved.RequestHash != r.RequestHash || saved.PreviousID != r.PreviousID || !bytes.Equal(existingGrants, requestedGrants) {
			return fault.Conflict("动作授权操作 ID 已用于其他请求")
		}
	} else {
		if !os.IsNotExist(err) {
			return err
		}
		if len(entries) >= 2048 {
			return errors.New("Nginx 动作授权记录容量已满，须本机维护")
		}
		tmp := filepath.Join(grants, "."+secure.ID())
		defer os.Remove(tmp)
		if err = rootJSONWrite(tmp, r, 32<<10); err != nil {
			return err
		}
		if err = unix.Renameat2(unix.AT_FDCWD, tmp, unix.AT_FDCWD, path, unix.RENAME_NOREPLACE); err != nil {
			return err
		}
		if err = syncDir(grants); err != nil {
			return err
		}
	}
	return rootJSONWrite(filepath.Join(dir, "current.json"), struct {
		ID string `json:"id"`
	}{r.ID}, 1024)
}

func (f *fail2banNginxExecutor) manage(ctx context.Context, in Fail2banNginxRequest) (fail2banNginxRegistry, error) {
	if in.Protocol != Protocol || !validID(in.OperationID) || in.BaseID != "" && !validID(in.BaseID) || !fail2banJailName.MatchString(in.Jail) || in.Action != "bind" && in.Action != "unbind" || in.Action == "bind" && !validID(in.ResourceID) || in.Action == "unbind" && in.ResourceID != "" {
		return fail2banNginxRegistry{}, fault.Invalid("动作授权请求无效")
	}
	leave, ok := f.nginx.maintenance.enter(false)
	if !ok {
		return fail2banNginxRegistry{}, ErrBusy
	}
	defer leave()
	n := f.nginx
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.closed || n.unlock == nil {
		return fail2banNginxRegistry{}, ErrRuntimeUnavailable
	}
	if err := ctx.Err(); err != nil {
		return fail2banNginxRegistry{}, err
	}
	unlock, err := (&Journal{Dir: fail2banBindingDir(n.DataDir)}).rootLock("binding.lock")
	if err != nil {
		return fail2banNginxRegistry{}, err
	}
	defer unlock()
	prior, err := loadFail2banNginxRegistry(n.DataDir)
	if err != nil {
		return prior, err
	}
	raw, _ := json.Marshal(in)
	hash := secure.Hash(raw)
	if prior.ID == in.OperationID {
		if prior.RequestHash != hash {
			return prior, fault.Conflict("动作授权操作 ID 冲突")
		}
		return prior, nil
	}
	if prior.ID != in.BaseID {
		return prior, fault.Conflict("动作授权基准已变化，请重新读取")
	}
	if err = fail2banUpgradeQuiesceIdle(n.DataDir, ""); err != nil {
		return prior, err
	}
	if err = fail2banUpgradeActivationIdle(n.DataDir, ""); err != nil {
		return prior, err
	}
	records, err := n.Journal.List()
	if err != nil {
		return prior, err
	}
	for _, record := range records {
		if (record.Kind == fail2banJailsKind || record.Kind == fail2banAddressKind || record.Kind == fail2banLifecycleKind || record.Kind == fail2banPythonKind || record.Kind == fail2banPythonPlanningKind) && pendingNginxRecord(record) {
			return prior, ErrBusy
		}
	}
	managed, err := loadFail2banManaged(n.DataDir)
	if err != nil {
		return prior, err
	}
	if managed != nil && managed.State == "installed" {
		_, bundle, err := selectedFail2banJails(managed)
		if err != nil {
			return prior, err
		}
		for _, name := range fail2banJailNames(bundle) {
			if name == in.Jail {
				return prior, fault.Conflict("受管 jail 的动作授权须随 jail 配置应用，不能单独改绑或撤销")
			}
		}
	}
	if in.Action == "bind" {
		records, err := n.Journal.List()
		if err != nil {
			return prior, err
		}
		for _, r := range records {
			if pendingNginxRecord(r) {
				return prior, ErrBusy
			}
		}
		_, m, err := n.active()
		if err != nil || len(m.ClientDeny[in.ResourceID]) == 0 {
			return prior, errors.New("目标站点未发布明确的客户端拒绝入口")
		}
		b, err := selectFail2banBinding(n.DataDir)
		if err != nil || b == nil || b.State != "bound" {
			return prior, errors.New("没有当前有效的 Fail2ban 实例授权")
		}
		version, _, status, err := readFail2banBound(ctx, n.DataDir, b, true, in.Jail)
		if err != nil {
			return prior, err
		}
		if version != "1.1.1" {
			return prior, errors.New("Nginx 动作仅支持经核对的 Fail2ban 1.1.1")
		}
		jail := fail2ban.Jail{Name: in.Jail}
		if err = parseFail2banJail(status, &jail); err != nil {
			return prior, err
		}
		grants := []fail2banNginxGrant{}
		for _, grant := range prior.Grants {
			if grant.Jail != in.Jail {
				grants = append(grants, grant)
			}
		}
		prior.Grants = append(grants, fail2banNginxGrant{Jail: in.Jail, ResourceID: in.ResourceID, EngineKey: fail2banNginxEngineKey(b)})
	} else {
		grants := []fail2banNginxGrant{}
		for _, grant := range prior.Grants {
			if grant.Jail != in.Jail {
				grants = append(grants, grant)
			}
		}
		prior.Grants = grants
	}
	if len(prior.Grants) > 32 {
		return prior, fault.Invalid("Nginx 动作最多授权 32 个 jail")
	}
	sort.Slice(prior.Grants, func(i, j int) bool { return prior.Grants[i].Jail < prior.Grants[j].Jail })
	prior.ID, prior.PreviousID, prior.RequestHash, prior.ApprovedAt = in.OperationID, in.BaseID, hash, time.Now().Unix()
	if err := ctx.Err(); err != nil {
		return prior, err
	}
	if err = saveFail2banNginxRegistry(n.DataDir, prior); err != nil {
		return prior, err
	}
	f.mu.Lock()
	f.value.Registry = prior
	f.registryVersion++
	f.mu.Unlock()
	f.enqueue()
	return prior, nil
}
