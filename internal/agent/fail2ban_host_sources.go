package agent

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"

	"nginxpanel/internal/fail2ban"
	"nginxpanel/internal/secure"
)

type fail2banHostSourcesPolicy struct {
	Jails []string `json:"jails"`
}

func (p fail2banHostSourcesPolicy) normalize() (fail2banHostSourcesPolicy, error) {
	out := fail2banHostSourcesPolicy{Jails: []string{}}
	if len(p.Jails) == 0 || len(p.Jails) > fail2ban.MaxJails {
		return out, errors.New("须明确 1 至 32 个官方 jail 名称")
	}
	seen := map[string]bool{}
	for _, jail := range p.Jails {
		if !fail2banJailName.MatchString(jail) || seen[jail] {
			return out, errors.New("宿主机封禁来源 jail 名称无效或重复")
		}
		seen[jail] = true
		out.Jails = append(out.Jails, jail)
	}
	sort.Strings(out.Jails)
	return out, nil
}

type fail2banHostSourcesEvent struct {
	Schema         int                       `json:"schema"`
	ID             string                    `json:"id"`
	PreviousID     string                    `json:"previous_id"`
	Action         string                    `json:"action"`
	Owner          string                    `json:"owner"`
	RegistrationID string                    `json:"registration_id"`
	NamespaceID    string                    `json:"namespace_id"`
	EngineKey      string                    `json:"engine_key"`
	Policy         fail2banHostSourcesPolicy `json:"policy"`
	ApprovedAt     int64                     `json:"approved_at"`
	RequestHash    string                    `json:"request_hash"`
}

func (e fail2banHostSourcesEvent) requestHash() string {
	e.ApprovedAt, e.RequestHash = 0, ""
	raw, _ := json.Marshal(e)
	return secure.Hash(append([]byte("nginxpanel:fail2ban-host-sources:v1:"), raw...))
}

func (e fail2banHostSourcesEvent) valid() bool {
	if e.Schema != 1 || !validID(e.ID) || e.PreviousID != "" && !validID(e.PreviousID) || e.ID == e.PreviousID || !validID(e.Owner) || !validID(e.RegistrationID) || !fail2banDigest.MatchString(e.NamespaceID) || !fail2banDigest.MatchString(e.EngineKey) || e.ApprovedAt <= 0 || e.Policy.Jails == nil || e.RequestHash != e.requestHash() {
		return false
	}
	if e.Action == "revoke" {
		return e.PreviousID != "" && len(e.Policy.Jails) == 0
	}
	policy, err := e.Policy.normalize()
	return e.Action == "approve" && err == nil && sameFail2banHostJails(policy.Jails, e.Policy.Jails)
}

func sameFail2banHostJails(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func fail2banHostSourcesDir(dataDir string) string {
	return filepath.Join(dataDir, "agent", "fail2ban", "host-sources")
}

func loadFail2banHostSourcesEvent(dataDir, id string) (*fail2banHostSourcesEvent, error) {
	if !validID(id) {
		return nil, errors.New("宿主机封禁来源批准标识无效")
	}
	var e fail2banHostSourcesEvent
	if err := readFail2banHostProtectionJSON(filepath.Join(fail2banHostSourcesDir(dataDir), "events", id+".json"), &e); err != nil {
		return nil, err
	}
	if e.ID != id || !e.valid() {
		return nil, errors.New("宿主机封禁来源记录或摘要无效")
	}
	return &e, nil
}

func loadFail2banHostSources(dataDir string) (*fail2banHostSourcesEvent, error) {
	dir := fail2banHostSourcesDir(dataDir)
	if err := existingRootDirectory(dir); err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var pointer struct {
		ID string `json:"id"`
	}
	if err := readFail2banHostProtectionJSON(filepath.Join(dir, "current.json"), &pointer); err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	return loadFail2banHostSourcesEvent(dataDir, pointer.ID)
}

// Caller holds the shared host-input lock and the original pointer CAS.
func saveFail2banHostSources(dataDir string, event *fail2banHostSourcesEvent) error {
	if !event.valid() {
		return errors.New("拒绝保存无效封禁来源批准")
	}
	dir := fail2banHostSourcesDir(dataDir)
	events := filepath.Join(dir, "events")
	if err := secure.RootDirectory(events, 0700); err != nil {
		return err
	}
	saved, err := loadFail2banHostSourcesEvent(dataDir, event.ID)
	if err == nil {
		if saved.RequestHash != event.RequestHash {
			return errors.New("封禁来源批准 UUID 已用于其他请求")
		}
		event.ApprovedAt = saved.ApprovedAt
	} else {
		if !os.IsNotExist(err) {
			return err
		}
		entries, e := os.ReadDir(events)
		if e != nil {
			return e
		}
		if len(entries) >= 2048 {
			return errors.New("宿主机封禁来源批准记录容量已满，须本机维护")
		}
	}
	raw, err := json.Marshal(event)
	if err != nil {
		return err
	}
	if err = writeFail2banJailImmutable(filepath.Join(events, event.ID+".json"), raw, fail2banHostProtectionBytes); err != nil {
		return err
	}
	return rootJSONWrite(filepath.Join(dir, "current.json"), struct {
		ID string `json:"id"`
	}{event.ID}, 1024)
}
