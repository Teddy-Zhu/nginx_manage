package agent

import (
	"encoding/json"
	"errors"
	"maps"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"nginxpanel/internal/fail2ban"
	"nginxpanel/internal/secure"
)

const fail2banExistingPolicyKind = "nginx.fail2ban-existing-policy"

type fail2banExistingPolicySelection struct {
	Schema          int                         `json:"schema"`
	ID              string                      `json:"id"`
	AdoptionID      string                      `json:"adoption_id"`
	PreviousID      string                      `json:"previous_id"`
	Policy          fail2ban.ExistingJailPolicy `json:"policy"`
	DumpHash        string                      `json:"dump_hash"`
	EnabledDumpHash string                      `json:"enabled_dump_hash"`
	NativeProof     string                      `json:"native_proof"`
}

type Fail2banExistingPolicyPlan = fail2ban.ExistingPolicyPlan

type fail2banExistingPolicyCapture struct {
	Schema       int                             `json:"schema"`
	Plan         Fail2banExistingPolicyPlan      `json:"plan"`
	BaseTarget   string                          `json:"base_target"`
	Unit         string                          `json:"unit"`
	Server       string                          `json:"server"`
	Invocation   string                          `json:"invocation"`
	Socket       string                          `json:"socket"`
	ClockProof   string                          `json:"clock_proof"`
	StopBanProof string                          `json:"stop_ban_proof"`
	Snapshot     fail2banExistingConfigSnapshot  `json:"snapshot"`
	BeforeJails  []string                        `json:"before_jails"`
	AfterJails   []string                        `json:"after_jails"`
	Before       fail2banExistingPolicySelection `json:"before"`
	After        fail2banExistingPolicySelection `json:"after"`
}

type fail2banExistingPolicyIntent struct {
	AdoptionID      string `json:"adoption_id"`
	CaptureHash     string `json:"capture_hash"`
	Target          string `json:"target"`
	Sent            bool   `json:"sent"`
	Submission      string `json:"submission"`
	CancelRequested bool   `json:"cancel_requested"`
	// Reuse the existing boot/PID/start-time identity and exit proof. A lost
	// reload reply cannot authorize another reload or a racing compensation.
	Pending *networkdProcess           `json:"pending,omitempty"`
	Bans    map[string]fail2banBanTime `json:"bans"`
}

type Fail2banExistingPolicyOperation = fail2ban.ExistingPolicyOperation

func fail2banExistingPolicyPath(data, kind, id string) string {
	return filepath.Join(fail2banExistingDir(data), kind, id+".json")
}

func (s fail2banExistingPolicySelection) valid() bool {
	p, err := s.Policy.Normalize()
	return s.Schema == 1 && validID(s.ID) && validID(s.AdoptionID) && (s.PreviousID == "" || validID(s.PreviousID)) && err == nil && equalFail2banExistingPolicy(p, s.Policy) && fail2banDigest.MatchString(s.DumpHash) && fail2banDigest.MatchString(s.EnabledDumpHash) && fail2banDigest.MatchString(s.NativeProof)
}

func initialFail2banExistingPolicy(c *fail2banExistingCapture, adoption string) fail2banExistingPolicySelection {
	return fail2banExistingPolicySelection{Schema: 1, ID: adoption, AdoptionID: adoption, Policy: c.Plan.Before, DumpHash: c.DumpHash, EnabledDumpHash: c.DumpHash, NativeProof: c.Plan.NativeProof}
}

func loadFail2banExistingPolicy(data string, c *fail2banExistingCapture, adoption string) (fail2banExistingPolicySelection, error) {
	var pointer struct {
		ID string `json:"id"`
	}
	err := readFail2banNginxJSON(fail2banExistingPolicyPath(data, "policy-current", adoption), &pointer, 1024)
	if os.IsNotExist(err) {
		return initialFail2banExistingPolicy(c, adoption), nil
	}
	if err != nil {
		return fail2banExistingPolicySelection{}, err
	}
	if !validID(pointer.ID) || pointer.ID == adoption {
		return fail2banExistingPolicySelection{}, errors.New("已有 jail 参数指针无效")
	}
	var selected fail2banExistingPolicySelection
	if err = readFail2banNginxJSON(fail2banExistingPolicyPath(data, "policy-events", pointer.ID), &selected, 8192); err != nil {
		return selected, err
	}
	if !selected.valid() || selected.ID != pointer.ID || selected.AdoptionID != adoption || selected.NativeProof != c.Plan.NativeProof {
		return selected, errors.New("已有 jail 参数事件无效")
	}
	r, err := (&Journal{Dir: filepath.Join(data, "agent", "operations")}).Get(selected.ID)
	if err != nil {
		return selected, err
	}
	frozen, err := validFail2banExistingPolicyRecord(data, r)
	if err != nil {
		return selected, err
	}
	a, _ := json.Marshal(selected)
	b, _ := json.Marshal(frozen.After)
	if string(a) != string(b) || !r.Fail2banExistingPolicy.Sent || r.Fail2banExistingPolicy.CancelRequested || r.State == "failed" {
		return selected, errors.New("已有 jail 参数事件与原操作不一致")
	}
	return selected, nil
}

func (c *fail2banExistingPolicyCapture) afterSnapshot() fail2banExistingConfigSnapshot {
	files := maps.Clone(c.Snapshot.Files)
	files[fail2banExistingOverlayName(c.Plan.Name)] = []byte(fail2banExistingOverlay(fail2ban.ExistingJailProfile{Name: c.Plan.Name}, c.Plan.After))
	return fail2banExistingConfigSnapshot{Files: files}
}

func (c *fail2banExistingPolicyCapture) valid() error {
	p := c.Plan
	if c.Schema != 1 || !p.Valid() || !fail2banDigest.MatchString(c.BaseTarget) || !fail2banDigest.MatchString(c.Unit) || !fail2banDigest.MatchString(c.Server) || !fail2banInvocation.MatchString(c.Invocation) || c.Socket == "" || !c.Before.valid() || !c.After.valid() || c.Before.ID != p.BaseID || c.Before.AdoptionID != p.AdoptionID || c.After.AdoptionID != p.AdoptionID || c.After.PreviousID != c.Before.ID || c.After.ID == c.Before.ID || c.After.NativeProof != c.Before.NativeProof || !equalFail2banExistingPolicy(c.Before.Policy, p.Before) || !equalFail2banExistingPolicy(c.After.Policy, p.After) || p.Before.Enabled && !fail2banDigest.MatchString(c.ClockProof) {
		return errors.New("已有 jail 参数快照身份或状态无效")
	}
	if len(c.Snapshot.Files) == 0 || len(c.Snapshot.Files) > 1024 {
		return errors.New("已有 jail 参数配置快照超限")
	}
	if c.After.Policy.Enabled && c.After.DumpHash != c.After.EnabledDumpHash || !c.After.Policy.Enabled && c.After.DumpHash != fail2banDumpHash([][]any{}) || c.Before.Policy.Enabled && c.Before.DumpHash != c.Before.EnabledDumpHash || !c.Before.Policy.Enabled && c.Before.DumpHash != fail2banDumpHash([][]any{}) {
		return errors.New("已有 jail 参数启用配置摘要无效")
	}
	if p.StopConfirmation && !fail2banDigest.MatchString(c.StopBanProof) || !p.StopConfirmation && c.StopBanProof != "" {
		return errors.New("已有 jail 停用封禁确认依据无效")
	}
	total := 0
	for name, raw := range c.Snapshot.Files {
		if filepath.Clean(name) != name || filepath.IsAbs(name) || name == "." || strings.HasPrefix(name, "../") || strings.ContainsAny(name, "\x00\r\n\\") || len(raw) > 256<<10 {
			return errors.New("已有 jail 参数配置路径无效")
		}
		total += len(raw)
	}
	if total > 8<<20 || string(c.Snapshot.Files[fail2banExistingOverlayName(p.Name)]) != fail2banExistingOverlay(fail2ban.ExistingJailProfile{Name: p.Name}, p.Before) {
		return errors.New("已有 jail 原参数覆盖文件不匹配")
	}
	for _, names := range [][]string{c.BeforeJails, c.AfterJails} {
		seen := map[string]bool{}
		if len(names) > 64 {
			return errors.New("已有 jail 参数名单超限")
		}
		for _, name := range names {
			if !fail2banJailName.MatchString(name) || seen[name] {
				return errors.New("已有 jail 参数名单无效")
			}
			seen[name] = true
		}
	}
	if !sameExistingPolicyJails(c.AfterJails, existingPolicyJails(c.BeforeJails, p.Name, p.After.Enabled)) || !sameExistingPolicyJails(c.BeforeJails, existingPolicyJails(c.BeforeJails, p.Name, p.Before.Enabled)) {
		return errors.New("已有 jail 参数前后名单不一致")
	}
	return nil
}

func fail2banExistingPolicyRequestHash(i fail2banExistingPolicyIntent) string {
	raw, _ := json.Marshal([]string{i.AdoptionID, i.CaptureHash, i.Target})
	return secure.Hash(append([]byte("nginxpanel:fail2ban-existing-policy:v1:"), raw...))
}

func validFail2banExistingPolicyRecord(data string, r Record) (*fail2banExistingPolicyCapture, error) {
	i := r.Fail2banExistingPolicy
	if r.Kind != fail2banExistingPolicyKind || !validID(r.OperationID) || i == nil || !validID(i.AdoptionID) || !fail2banDigest.MatchString(i.CaptureHash) || !fail2banDigest.MatchString(i.Target) {
		return nil, errors.New("已有 jail 参数操作合同无效")
	}
	if r.Fail2banExistingPolicyJob == nil {
		if r.RequestHash != fail2banExistingPolicyRequestHash(*i) {
			return nil, errors.New("已有 jail 参数请求摘要无效")
		}
	} else if err := validFail2banExistingPolicyJobRequest(r); err != nil {
		return nil, err
	}
	switch r.State {
	case "running", "recovery_required", "succeeded", "failed":
	default:
		return nil, errors.New("已有 jail 参数操作状态无效")
	}
	if i.Sent {
		if i.Pending == nil || !validID(i.Pending.Boot) || i.Pending.PID < 2 || i.Pending.Start == "" || i.Bans == nil || len(i.Bans) > 1024 {
			return nil, errors.New("已有 jail reload 恢复依据不完整")
		}
		if start, err := strconv.ParseUint(i.Pending.Start, 10, 64); err != nil || start == 0 {
			return nil, errors.New("已有 jail 原进程启动身份无效")
		}
		for address, value := range i.Bans {
			ip, err := netip.ParseAddr(address)
			if err != nil || ip.Zone() != "" || ip.Unmap().String() != address || value.Duration < -1 || value.Duration == -1 && value.Expires != 0 || value.Duration != -1 && value.Expires <= 0 {
				return nil, errors.New("已有 jail 原封禁快照无效")
			}
		}
		switch i.Submission {
		case "pending", "confirmed", "unknown":
		default:
			return nil, errors.New("已有 jail reload 提交状态未知")
		}
	} else if i.Submission != "" || i.Pending != nil || len(i.Bans) != 0 {
		return nil, errors.New("未提交的已有 jail 参数操作包含运行结果")
	}
	raw, err := listenerRead(fail2banExistingPolicyPath(data, "policy-captures", r.OperationID), fail2banExistingCaptureLimit)
	if err != nil {
		return nil, err
	}
	if secure.Hash(raw) != i.CaptureHash {
		return nil, errors.New("已有 jail 参数快照发生变化")
	}
	var c fail2banExistingPolicyCapture
	if err = json.Unmarshal(raw, &c); err != nil {
		return nil, err
	}
	if err = c.valid(); err != nil {
		return nil, err
	}
	if c.Plan.AdoptionID != i.AdoptionID || c.Plan.Target != i.Target || c.After.ID != r.OperationID {
		return nil, errors.New("已有 jail 参数操作与快照不一致")
	}
	if job := r.Fail2banExistingPolicyJob; job != nil {
		in := job.Request
		if in.Action != "apply" || in.AdoptionID != c.Plan.AdoptionID || in.Target != c.Plan.Target || !equalFail2banExistingPolicy(in.Policy, c.Plan.After) || in.ConfirmStop != c.Plan.StopConfirmation || job.Plan != nil {
			return nil, errors.New("排队参数请求与执行快照不一致")
		}
	}
	return &c, nil
}

func fail2banExistingPolicyOperation(r Record, c *fail2banExistingPolicyCapture) Fail2banExistingPolicyOperation {
	i := r.Fail2banExistingPolicy
	out := Fail2banExistingPolicyOperation{ID: r.OperationID, RequestHash: r.RequestHash, Action: "apply", State: r.State, Stage: r.Stage, AdoptionID: i.AdoptionID, Target: i.Target, Sent: i.Sent, Submission: i.Submission, CancelRequested: i.CancelRequested, Error: r.Error}
	plan := c.Plan
	out.Plan = &plan
	if job := r.Fail2banExistingPolicyJob; job != nil {
		out.CancelRequested = out.CancelRequested || job.CancelRequested
		out.CancelError = job.CancelError
	}
	return out
}

func prepareFail2banExistingPolicy(data string) error {
	if err := prepareFail2banExistingOwnership(data); err != nil {
		return err
	}
	for _, kind := range []string{"policy-captures", "policy-events", "policy-current"} {
		path := filepath.Join(fail2banExistingDir(data), kind)
		if err := secure.RootDirectory(path, 0700); err != nil {
			return err
		}
		if err := syncDir(path); err != nil {
			return err
		}
	}
	return syncDir(fail2banExistingDir(data))
}

func publishFail2banExistingPolicy(data string, c *fail2banExistingPolicyCapture) error {
	path := fail2banExistingPolicyPath(data, "policy-events", c.After.ID)
	raw, _ := json.Marshal(c.After)
	if err := writeFail2banJailImmutable(path, raw, 8192); err != nil {
		return err
	}
	if err := syncDir(filepath.Dir(path)); err != nil {
		return err
	}
	return rootJSONWrite(fail2banExistingPolicyPath(data, "policy-current", c.Plan.AdoptionID), struct {
		ID string `json:"id"`
	}{c.After.ID}, 1024)
}
