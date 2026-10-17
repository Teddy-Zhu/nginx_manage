package agent

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"time"

	"nginxpanel/internal/fail2ban"
	"nginxpanel/internal/secure"
)

const fail2banExistingKind = "nginx.fail2ban-existing-ownership"
const fail2banExistingCaptureLimit = 16 << 20

type fail2banExistingCapture struct {
	Plan          fail2ban.ExistingJailPlan      `json:"plan"`
	Binding       fail2banBinding                `json:"binding"`
	Unit          string                         `json:"unit"`
	Server        string                         `json:"server"`
	Invocation    string                         `json:"invocation"`
	Socket        string                         `json:"socket"`
	Snapshot      fail2banExistingConfigSnapshot `json:"snapshot"`
	CandidateHash string                         `json:"candidate_hash"`
	DumpHash      string                         `json:"dump_hash"`
}

type fail2banExistingIntent struct {
	Action          string `json:"action"`
	Name            string `json:"name"`
	BindingID       string `json:"binding_id"`
	AdoptionID      string `json:"adoption_id"`
	CaptureHash     string `json:"capture_hash"`
	Target          string `json:"target"`
	CancelRequested bool   `json:"cancel_requested"`
}

// Each current pointer refers to an immutable local event. Neither a capture
// nor a prepared journal is authority; only the published adopt event is.
type fail2banExistingGrant struct {
	Schema     int    `json:"schema"`
	ID         string `json:"id"`
	PreviousID string `json:"previous_id"`
	Action     string `json:"action"`
	Name       string `json:"name"`
	BindingID  string `json:"binding_id"`
	AdoptionID string `json:"adoption_id"`
	At         int64  `json:"at"`
}

type Fail2banExistingOwnershipOperation struct {
	ID         string `json:"id"`
	State      string `json:"state"`
	Stage      string `json:"stage"`
	Action     string `json:"action"`
	Name       string `json:"name"`
	BindingID  string `json:"binding_id"`
	AdoptionID string `json:"adoption_id"`
	Target     string `json:"target"`
	Error      string `json:"error"`
}

func fail2banExistingDir(data string) string {
	return filepath.Join(fail2banBindingDir(data), "existing-jails")
}
func fail2banExistingOverlayName(name string) string {
	return "jail.d/zzzz-nginxpanel-existing-" + name + ".local"
}
func fail2banExistingCapturePath(data, id string) string {
	return filepath.Join(fail2banExistingDir(data), "captures", id+".json")
}
func fail2banExistingGrantPath(data, id string) string {
	return filepath.Join(fail2banExistingDir(data), "events", id+".json")
}
func fail2banExistingPointerPath(data, name string) string {
	return filepath.Join(fail2banExistingDir(data), "current", name+".json")
}

func prepareFail2banExistingOwnership(data string) error {
	root := fail2banExistingDir(data)
	for _, path := range []string{root, filepath.Join(root, "captures"), filepath.Join(root, "events"), filepath.Join(root, "current")} {
		if err := secure.RootDirectory(path, 0700); err != nil {
			return err
		}
	}
	for _, path := range []string{filepath.Join(root, "captures"), filepath.Join(root, "events"), filepath.Join(root, "current"), root, fail2banBindingDir(data)} {
		if err := syncDir(path); err != nil {
			return err
		}
	}
	return nil
}

func equalFail2banExistingPolicy(a, b fail2ban.ExistingJailPolicy) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return bytes.Equal(x, y)
}

func (c fail2banExistingCapture) valid() error {
	before, e1 := c.Plan.Before.Normalize()
	after, e2 := c.Plan.After.Normalize()
	if c.Plan.Profile.Validate() != nil || e1 != nil || e2 != nil || !before.Enabled || !equalFail2banExistingPolicy(before, c.Plan.Before) || !equalFail2banExistingPolicy(after, c.Plan.After) || !equalFail2banExistingPolicy(before, after) || c.Binding.Schema != 1 || c.Binding.State != "bound" || !validID(c.Binding.ID) || c.Plan.BindingID != c.Binding.ID || !fail2banUnit.MatchString(c.Binding.Service) || !validFail2banSocket(c.Binding.Socket) || !validFail2banClientPath(c.Binding.ClientPath) || !filepath.IsAbs(c.Binding.ClientResolved) || !fail2banDigest.MatchString(c.Binding.ClientSHA256) || c.Binding.ClientVersion != fail2ban.RegexVersion || c.Plan.At <= 0 || !fail2banDigest.MatchString(c.Plan.Target) || !fail2banDigest.MatchString(c.Unit) || !fail2banDigest.MatchString(c.Server) || !fail2banInvocation.MatchString(c.Invocation) || c.Socket == "" || !fail2banDigest.MatchString(c.CandidateHash) || !fail2banDigest.MatchString(c.DumpHash) || len(c.Plan.Jails) == 0 || len(c.Plan.Jails) > 64 || len(c.Snapshot.Files) == 0 || len(c.Snapshot.Files) > 1024 {
		return errors.New("已有 jail 接管材料身份或参数不完整")
	}
	seen, found, total := map[string]bool{}, false, 0
	for _, name := range c.Plan.Jails {
		if !fail2banJailName.MatchString(name) || seen[name] {
			return errors.New("接管 jail 名单无效")
		}
		seen[name], found = true, found || name == c.Plan.Profile.Name
	}
	if !found || !fail2banDigest.MatchString(c.Plan.BanProof) {
		return errors.New("接管目标名单或封禁观察摘要无效")
	}
	for name, raw := range c.Snapshot.Files {
		if filepath.Clean(name) != name || filepath.IsAbs(name) || name == "." || strings.HasPrefix(name, "../") || strings.ContainsAny(name, "\x00\r\n\\") || len(raw) > 256<<10 {
			return errors.New("接管配置快照无效")
		}
		total += len(raw)
	}
	if total > 8<<20 || len(c.Snapshot.Files["jail.conf"]) == 0 || len(c.Snapshot.Files["fail2ban.conf"]) == 0 {
		return errors.New("接管配置快照超限或不完整")
	}
	name := fail2banExistingOverlayName(c.Plan.Profile.Name)
	if _, exists := c.Snapshot.Files[name]; exists {
		return errors.New("接管前已有同名覆盖文件")
	}
	files := maps.Clone(c.Snapshot.Files)
	files[name] = []byte(fail2banExistingOverlay(c.Plan.Profile, c.Plan.Before))
	actual := (fail2banExistingConfigSnapshot{Files: files}).hash()
	if actual != c.CandidateHash {
		return errors.New("接管候选配置摘要不匹配")
	}
	return nil
}

func loadFail2banExistingCapture(data, id, hash string) (*fail2banExistingCapture, error) {
	if !validID(id) || !fail2banDigest.MatchString(hash) {
		return nil, errors.New("已有 jail 接管快照引用无效")
	}
	raw, err := listenerRead(fail2banExistingCapturePath(data, id), fail2banExistingCaptureLimit)
	if err != nil {
		return nil, err
	}
	if secure.Hash(raw) != hash {
		return nil, errors.New("已有 jail 接管快照发生变化")
	}
	var c fail2banExistingCapture
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&c) != nil || d.Decode(new(any)) != io.EOF {
		return nil, errors.New("已有 jail 接管快照格式无效")
	}
	return &c, c.valid()
}

func fail2banExistingRequestHash(i fail2banExistingIntent) string {
	raw, _ := json.Marshal(struct{ Action, Name, BindingID, AdoptionID, Target string }{i.Action, i.Name, i.BindingID, i.AdoptionID, i.Target})
	return secure.Hash(append([]byte("nginxpanel:fail2ban-existing-ownership:v1:"), raw...))
}

func validFail2banExistingRecord(data string, r Record) (*fail2banExistingCapture, error) {
	i := r.Fail2banExisting
	if r.Kind != fail2banExistingKind || !validID(r.OperationID) || i == nil || !fail2banJailName.MatchString(i.Name) || !validID(i.BindingID) || !validID(i.AdoptionID) || !fail2banDigest.MatchString(i.CaptureHash) || !fail2banDigest.MatchString(i.Target) || i.Action != "adopt" && i.Action != "release" || i.Action == "adopt" && i.AdoptionID != r.OperationID || r.RequestHash != fail2banExistingRequestHash(*i) {
		return nil, errors.New("已有 jail 接管操作合同无效")
	}
	if !(r.State == "running" && r.Stage == "prepared" || r.State == "recovery_required" && r.Stage == "ownership_unconfirmed" || r.State == "succeeded" && r.Stage == i.Action+"_confirmed" || r.State == "failed" && r.Stage == "cancelled" && i.CancelRequested) {
		return nil, errors.New("已有 jail 所有权操作状态未知")
	}
	c, err := loadFail2banExistingCapture(data, i.AdoptionID, i.CaptureHash)
	if err != nil {
		return nil, err
	}
	if c.Plan.Profile.Name != i.Name || c.Plan.BindingID != i.BindingID || c.Plan.Target != i.Target {
		return nil, errors.New("已有 jail 接管操作与快照不匹配")
	}
	return c, nil
}

func loadFail2banExistingGrant(data, name string) (*fail2banExistingGrant, error) {
	if !fail2banJailName.MatchString(name) {
		return nil, errors.New("已有 jail 所有权名称无效")
	}
	var pointer struct {
		ID string `json:"id"`
	}
	err := readFail2banNginxJSON(fail2banExistingPointerPath(data, name), &pointer, 1024)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !validID(pointer.ID) {
		return nil, errors.New("已有 jail 所有权指针无效")
	}
	var g fail2banExistingGrant
	if err = readFail2banNginxJSON(fail2banExistingGrantPath(data, pointer.ID), &g, 8192); err != nil {
		return nil, err
	}
	if g.Schema != 1 || g.ID != pointer.ID || g.Name != name || !validID(g.BindingID) || !validID(g.AdoptionID) || g.PreviousID != "" && (!validID(g.PreviousID) || g.PreviousID == g.ID) || g.Action != "adopt" && g.Action != "release" || g.Action == "adopt" && g.ID != g.AdoptionID || g.Action == "release" && g.PreviousID != g.AdoptionID || g.At <= 0 {
		return nil, errors.New("已有 jail 所有权事件无效")
	}
	journal := &Journal{Dir: filepath.Join(data, "agent", "operations")}
	r, err := journal.Get(g.ID)
	if err != nil {
		return nil, err
	}
	if _, err = validFail2banExistingRecord(data, r); err != nil {
		return nil, err
	}
	if r.State != "succeeded" && r.State != "running" && r.State != "recovery_required" {
		return nil, errors.New("所有权事件指向无效操作状态")
	}
	if r.Fail2banExisting.Name != g.Name || r.Fail2banExisting.Action != g.Action || r.Fail2banExisting.BindingID != g.BindingID || r.Fail2banExisting.AdoptionID != g.AdoptionID {
		return nil, errors.New("已有 jail 所有权事件与操作不一致")
	}
	return &g, nil
}

func fail2banExistingOwnershipIdle(data string) error {
	dir := filepath.Join(fail2banExistingDir(data), "current")
	if _, err := os.Lstat(dir); os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return err
	}
	if err := existingRootDirectory(dir); err != nil {
		return err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	if len(entries) > 64 {
		return errors.New("已有 jail 所有权登记超限")
	}
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".json") || !entry.Type().IsRegular() {
			return errors.New("已有 jail 所有权目录存在未知文件")
		}
		g, err := loadFail2banExistingGrant(data, strings.TrimSuffix(entry.Name(), ".json"))
		if err != nil {
			return err
		}
		if g == nil || g.Action == "adopt" {
			return errors.New("已有 jail 尚由本应用接管，须先显式释放，才能变更实例接入")
		}
	}
	return nil
}

func publishFail2banExistingGrant(data string, r Record) error {
	i := r.Fail2banExisting
	g, err := loadFail2banExistingGrant(data, i.Name)
	if err != nil {
		return err
	}
	if g != nil && g.ID == r.OperationID {
		return nil
	}
	previous := ""
	if i.Action == "release" {
		if g == nil || g.Action != "adopt" || g.ID != i.AdoptionID {
			return ErrExternalChange
		}
		previous = g.ID
	} else if g != nil {
		if g.Action != "release" {
			return ErrExternalChange
		}
		previous = g.ID
	}
	event := fail2banExistingGrant{Schema: 1, ID: r.OperationID, PreviousID: previous, Action: i.Action, Name: i.Name, BindingID: i.BindingID, AdoptionID: i.AdoptionID, At: time.Now().Unix()}
	eventPath := fail2banExistingGrantPath(data, event.ID)
	if err = secure.RootDirectory(filepath.Dir(eventPath), 0700); err != nil {
		return err
	}
	entries, err := os.ReadDir(filepath.Dir(eventPath))
	if err != nil {
		return err
	}
	if len(entries) >= 2048 {
		if _, err = os.Lstat(eventPath); err != nil {
			return errors.New("已有 jail 所有权历史容量已满")
		}
	}
	// Reuse the original timestamp after an interrupted immutable publication.
	var saved fail2banExistingGrant
	if e := readFail2banNginxJSON(eventPath, &saved, 8192); e == nil {
		if saved.ID != event.ID || saved.PreviousID != event.PreviousID || saved.Action != event.Action || saved.Name != event.Name || saved.BindingID != event.BindingID || saved.AdoptionID != event.AdoptionID || saved.Schema != 1 || saved.At <= 0 {
			return ErrExternalChange
		}
		event = saved
	} else if !os.IsNotExist(e) {
		return e
	}
	raw, _ := json.Marshal(event)
	if err = writeFail2banJailImmutable(eventPath, raw, 8192); err != nil {
		return err
	}
	if err = syncDir(filepath.Dir(eventPath)); err != nil {
		return err
	}
	path := fail2banExistingPointerPath(data, event.Name)
	if err = secure.RootDirectory(filepath.Dir(path), 0700); err != nil {
		return err
	}
	return rootJSONWrite(path, struct {
		ID string `json:"id"`
	}{event.ID}, 1024)
}

func fail2banExistingOperation(r Record) Fail2banExistingOwnershipOperation {
	i := r.Fail2banExisting
	return Fail2banExistingOwnershipOperation{ID: r.OperationID, State: r.State, Stage: r.Stage, Action: i.Action, Name: i.Name, BindingID: i.BindingID, AdoptionID: i.AdoptionID, Target: i.Target, Error: r.Error}
}
