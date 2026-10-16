package agent

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"

	"nginxpanel/internal/fail2ban"
	"nginxpanel/internal/firewall"
	"nginxpanel/internal/secure"
)

const fail2banHostProtectionBytes = 16 << 10

type fail2banHostProtectionEvent struct {
	Schema         int                                `json:"schema"`
	ID             string                             `json:"id"`
	PreviousID     string                             `json:"previous_id"`
	Action         string                             `json:"action"`
	RegistrationID string                             `json:"registration_id"`
	Owner          string                             `json:"owner"`
	NamespaceID    string                             `json:"namespace_id"`
	ApprovedAt     int64                              `json:"approved_at"`
	Policy         fail2ban.HostInputProtectionPolicy `json:"policy"`
	PolicyHash     string                             `json:"policy_hash"`
	RequestHash    string                             `json:"request_hash"`
}

func fail2banHostProtectionDir(dataDir string) string {
	return filepath.Join(dataDir, "agent", "fail2ban", "host-protection")
}

func readFail2banHostProtectionJSON(path string, value any) error {
	raw, err := listenerRead(path, fail2banHostProtectionBytes)
	if err != nil {
		return err
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(value) != nil || d.Decode(new(any)) != io.EOF {
		return errors.New("宿主机动作保护来源文件格式无效")
	}
	return nil
}

func (e fail2banHostProtectionEvent) requestHash() string {
	e.ApprovedAt, e.RequestHash = 0, ""
	raw, _ := json.Marshal(e)
	return secure.Hash(append([]byte("nginxpanel:fail2ban-host-protection:v1:"), raw...))
}

func (e fail2banHostProtectionEvent) valid() bool {
	if e.Schema != 1 || !validID(e.ID) || e.PreviousID != "" && !validID(e.PreviousID) || e.PreviousID == e.ID || !validID(e.RegistrationID) || !validID(e.Owner) || !fail2banDigest.MatchString(e.NamespaceID) || e.ApprovedAt <= 0 || e.Policy.AdminSources == nil || e.Policy.ProxySources == nil || e.PolicyHash != e.Policy.Hash() || e.RequestHash != e.requestHash() {
		return false
	}
	switch e.Action {
	case "approve":
		policy, err := e.Policy.Normalize()
		return err == nil && policy.Hash() == e.PolicyHash
	case "revoke":
		return e.PreviousID != "" && len(e.Policy.AdminSources) == 0 && len(e.Policy.ProxySources) == 0
	default:
		return false
	}
}

func loadFail2banHostProtectionEvent(dataDir, id string) (*fail2banHostProtectionEvent, error) {
	if !validID(id) {
		return nil, errors.New("宿主机保护批准标识无效")
	}
	var event fail2banHostProtectionEvent
	err := readFail2banHostProtectionJSON(filepath.Join(fail2banHostProtectionDir(dataDir), "events", id+".json"), &event)
	if err != nil {
		return nil, err
	}
	if event.ID != id || !event.valid() {
		return nil, errors.New("宿主机保护批准内容或摘要无效")
	}
	return &event, nil
}

func loadFail2banHostProtection(dataDir string) (*fail2banHostProtectionEvent, error) {
	dir := fail2banHostProtectionDir(dataDir)
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
	return loadFail2banHostProtectionEvent(dataDir, pointer.ID)
}

// The immutable event precedes the pointer. A retry may finish publishing that
// exact event only while its original CAS base is still current; no replay can
// roll the pointer back to a superseded approval.
func saveFail2banHostProtection(dataDir string, event *fail2banHostProtectionEvent) error {
	if !event.valid() {
		return errors.New("拒绝保存无效宿主机保护批准")
	}
	dir := fail2banHostProtectionDir(dataDir)
	events := filepath.Join(dir, "events")
	if err := secure.RootDirectory(events, 0700); err != nil {
		return err
	}
	existing, err := loadFail2banHostProtectionEvent(dataDir, event.ID)
	if err == nil {
		if existing.RequestHash != event.RequestHash {
			return errors.New("保护批准操作标识已用于其他请求")
		}
		event.ApprovedAt = existing.ApprovedAt
	} else {
		if !os.IsNotExist(err) {
			return err
		}
		entries, e := os.ReadDir(events)
		if e != nil {
			return e
		}
		if len(entries) >= 2048 {
			return errors.New("宿主机保护批准记录容量已满，须本机维护")
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

func fail2banHostProtectionView(dataDir string, kernel firewall.KernelView, registration firewall.RegistrationView) fail2ban.HostInputProtectionView {
	out := fail2ban.EmptyHostInputProtection("尚未核对目标本机 root 保护来源批准")
	event, err := loadFail2banHostProtection(dataDir)
	if err != nil {
		out.Reason = "宿主机保护批准记录无法完整读取，须本机检查"
		return out
	}
	if event == nil {
		out.State, out.Reason = "unapproved", "尚未由目标本机 root 批准管理来源与代理来源"
		return out
	}
	out.ID, out.ApprovedAt, out.PolicyHash = event.ID, event.ApprovedAt, event.PolicyHash
	out.AdminSources, out.ProxySources = event.Policy.AdminSources, event.Policy.ProxySources
	if event.Action == "revoke" {
		out.State, out.Reason = "revoked", "宿主机保护来源批准已撤销；不会据此直接移除运行封禁"
		return out
	}
	if !kernel.Available {
		out.Reason = "内核快照不可用，无法核对保护批准的命名空间与登记"
		return out
	}
	rootRegistration, err := loadFail2banHostRegistration(dataDir)
	if err != nil {
		out.Reason = "独立登记无法读取，无法核对保护批准"
		return out
	}
	if rootRegistration == nil || rootRegistration.State != "registered" || !registration.Verified || rootRegistration.Owner != event.Owner || rootRegistration.OperationID != event.RegistrationID || registration.OperationID != event.RegistrationID || kernel.NamespaceID != event.NamespaceID || rootRegistration.Confirmed.NamespaceID != kernel.NamespaceID {
		out.State, out.Reason = "stale", "保护批准对应的所有者、登记或命名空间已变化，须目标本机重新批准"
		return out
	}
	out.State, out.Verified, out.Reason = "approved", true, ""
	return out
}
