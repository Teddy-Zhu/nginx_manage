package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"nginxpanel/internal/firewall"
	"nginxpanel/internal/secure"
)

const ufwChangeBytes = 64 << 20

// This is local recovery material, never an exported policy or an ownership
// claim inferred from comments. Only the accepted root parent can dispatch it.
type ufwPolicyTransition struct {
	Owner, MachineHash, RegistrationOperationID          string
	ConfigurationHash, NativeHash, DryRunHash, BatchHash string
	IPv6                                                 bool
	Files                                                []ufwFileSnapshot
	Tools                                                ufwToolBinding
	Reload                                               ufwReloadBaseline
	Materials                                            []ufwReloadMaterial
	Previous                                             *firewallPolicyRecord
}

type ufwChangeStep struct {
	ID, Family, Target string
}

type ufwChangeCheckpoint struct {
	Schema      int                   `json:"schema"`
	RequestHash string                `json:"request_hash"`
	Policy      firewallPolicyRecord  `json:"policy"`
	Operation   firewall.Operation    `json:"operation"`
	Transition  ufwPolicyTransition   `json:"transition"`
	Steps       []ufwChangeStep       `json:"steps"`
	Rollback    bool                  `json:"rollback"`
	Confirmed   *firewallPolicyRecord `json:"confirmed"`
	Files       []ufwFileCommit       `json:"files"`
	LastRescue  string                `json:"last_rescue"`
}

func ufwChangePath(dataDir string) string {
	return filepath.Join(dataDir, "agent", "firewall", "ufw-change.json")
}

func ufwChangeHash(v *ufwChangeCheckpoint) string {
	raw, _ := json.Marshal(v)
	return secure.Hash(append([]byte("ufw:change:v3:\x00"), raw...))
}

func ufwChangeIntentHash(v *ufwChangeCheckpoint) string {
	value := *v
	value.Operation.State, value.Operation.Stage, value.Operation.Error, value.Operation.ConfirmedSource = "", "", "", ""
	value.Operation.UpdatedAt, value.Rollback = 0, false
	value.Confirmed = nil
	value.LastRescue = ""
	value.Files = append([]ufwFileCommit{}, v.Files...)
	for index := range value.Files {
		value.Files[index].Candidate, value.Files[index].Previous = nil, nil
		value.Files[index].Phase = ""
	}
	return ufwChangeHash(&value)
}

func newUFWTransition(registration *ufwRegistrationCheckpoint, baseline ufwConfigurationSnapshot, proof ufwDryRunProof, ipv6 bool, record firewallPolicyRecord, previous *firewallPolicyRecord) (*ufwPolicyTransition, error) {
	v := &ufwPolicyTransition{Owner: registration.NextClaim.Owner, MachineHash: registration.NextClaim.MachineHash, RegistrationOperationID: registration.NextClaim.OperationID, ConfigurationHash: baseline.Hash, NativeHash: proof.NativeHash, DryRunHash: proof.Hash, BatchHash: proof.BatchHash, IPv6: ipv6, Files: baseline.Files, Tools: proof.Tools, Reload: proof.Reload, Materials: proof.Materials, Previous: previous}
	if err := validateUFWTransition(v, record); err != nil {
		return nil, err
	}
	return v, nil
}

func validUFWFileSnapshot(f ufwFileSnapshot, executable bool, limit int64) bool {
	if !filepath.IsAbs(f.Path) || filepath.Clean(f.Path) != f.Path || len(f.Path) > 4096 || strings.ContainsAny(f.Path, "\x00\r\n") {
		return false
	}
	if !f.Present {
		return f == (ufwFileSnapshot{Path: f.Path})
	}
	mode := os.FileMode(f.Mode)
	return firewalldDigest(f.Hash) && f.Bytes >= 0 && f.Bytes <= limit && f.Inode != 0 && mode&(os.ModeType|os.ModeSetuid|os.ModeSetgid|os.ModeSticky) == 0 && mode.Perm()&0022 == 0 && (!executable || f.Bytes >= 4 && mode.Perm()&0111 != 0)
}

func validateUFWTransition(v *ufwPolicyTransition, record firewallPolicyRecord) error {
	invalid := errors.New("UFW 原业务转换材料无效")
	if v == nil || !validID(v.Owner) || !validID(v.RegistrationOperationID) || !firewalldDigest(v.MachineHash) || !firewalldDigest(v.ConfigurationHash) || !firewalldDigest(v.NativeHash) || !firewalldDigest(v.DryRunHash) || !firewalldDigest(v.BatchHash) || !validID(record.PlanID) || !slices.Contains([]string{"apply", "remove"}, record.Action) || record.Version < 1 || record.Policy.Backend != "ufw" || record.Marker != firewall.UFWCommentPrefix+v.Owner+":"+record.PlanID+":" || validateFirewallProtectionBasis(record.ProtectionBasis) != nil {
		return invalid
	}
	policyHash, err := firewall.PolicyDigest(record.Policy)
	program, programErr := firewall.CompileUFWRuntime(record.Policy, record.Protections, record.Action, v.Owner, record.PlanID)
	if err != nil || policyHash != record.PolicyHash || programErr != nil || program.Hash != record.ProgramHash || len(program.Rules) > ufwDryRunCommands {
		return invalid
	}
	previous, err := ufwPolicyProgram(v.Previous, v.Owner)
	if err != nil {
		return err
	}
	owned, err := ufwNativeProgram(previous)
	if err != nil {
		return err
	}
	for _, rule := range owned {
		if rule.Family == "ipv6" && !v.IPv6 {
			return invalid
		}
	}
	if record.Action == "remove" && (v.Previous == nil || v.Previous.Action != "apply" || v.Previous.Version != record.Version || v.Previous.PolicyHash != record.PolicyHash) {
		return errors.New("UFW 待移除策略与原确认回执不一致")
	}
	roles := append([]string{"cli", "python"}, ufwSourceModules...)
	roles = append(roles, "iptables", "ip6tables", "iptables-restore", "ip6tables-restore", "iptables-save", "ip6tables-save", "ufw-init", "cat", "false")
	if len(v.Tools.Files) != len(roles) {
		return invalid
	}
	var total int64
	for index, role := range roles {
		tool := v.Tools.Files[index]
		executable := !slices.Contains(ufwSourceModules, role)
		limit := int64(firewall.UFWReadBytes)
		if executable && role != "cli" {
			limit = 16 << 20
		}
		if tool.Role != role || tool.Executable != executable || len(tool.Raw) != 0 || !filepath.IsAbs(tool.Invoked) || filepath.Clean(tool.Invoked) != tool.Invoked || len(tool.Invoked) > 4096 || strings.ContainsAny(tool.Invoked, "\x00\r\n") || !tool.File.Present || !validUFWFileSnapshot(tool.File, executable, limit) {
			return invalid
		}
		total += tool.File.Bytes
	}
	description := v.Tools.Description
	if total > 64<<20 || description.Protocol != 1 || !strings.HasPrefix(description.Python, "3.") || len(description.Python) > 64 || description.Program != "ufw" || !description.Checks || description.ConfigDir != "/etc" || !slices.Contains([]string{"/lib/ufw", "/usr/lib/ufw"}, description.StateDir) || !slices.Contains([]string{"/sbin", "/usr/sbin"}, description.IptablesDir) {
		return invalid
	}
	toolsHash, err := ufwToolsDigest(&v.Tools)
	if err != nil || toolsHash != v.Tools.Hash {
		return invalid
	}
	sources := ufwConfigurationSources(v.Tools.Files[0].File.Path, v.IPv6)
	if len(v.Files) != len(sources) {
		return invalid
	}
	files := map[string]ufwFileSnapshot{}
	total = 0
	for index, source := range sources {
		file := v.Files[index]
		if file.Path != source.path || source.required && !file.Present || !validUFWFileSnapshot(file, index == 0, firewall.UFWReadBytes) {
			return invalid
		}
		files[file.Path], total = file, total+file.Bytes
	}
	raw, err := json.Marshal(v.Files)
	if err != nil || secure.Hash(raw) != v.ConfigurationHash || total > 4<<20 || v.Files[0] != v.Tools.Files[0].File {
		return invalid
	}
	expected := []ufwNativeRule{}
	for index, rule := range program.Rules {
		entry, err := expectedUFWNative(rule, program.Entries[index])
		if err != nil || entry.Family == "ipv6" && !v.IPv6 {
			return invalid
		}
		expected = append(expected, entry)
	}
	raw, err = json.Marshal(expected)
	if err != nil || secure.Hash(append([]byte("ufw:native-host:v1:\x00"), raw...)) != v.NativeHash {
		return invalid
	}
	count := 1
	if v.IPv6 {
		count = 2
	}
	if len(v.Materials) != count || len(v.Reload.Families) != count || !slices.Contains([]string{"nftables", "legacy"}, v.Reload.Backend) {
		return invalid
	}
	beforeFiles, afterFiles := map[string]*ufwNativeFile{}, map[string]*ufwNativeFile{}
	chains, rules, afterRules, tuples := 0, 0, 0, 0
	for index, material := range v.Materials {
		family, path, restoreRole := "ipv4", "/etc/ufw/user.rules", "iptables-restore"
		if index == 1 {
			family, path, restoreRole = "ipv6", "/etc/ufw/user6.rules", "ip6tables-restore"
		}
		observed := v.Reload.Families[index]
		if material.Family != family || observed.Family != family || observed.Backend != v.Reload.Backend || observed.ToolVersion == "" || observed.SaveVersion == "" || observed.RestoreVersion == "" || len(observed.ToolVersion)+len(observed.SaveVersion)+len(observed.RestoreVersion) > 768 || !sameUFWReloadImage(observed.Chains, material.BeforeKernel) || material.BeforeHash != files[path].Hash || len(material.Before) != int(files[path].Bytes) {
			return invalid
		}
		for _, role := range []string{"python", restoreRole, "false"} {
			tool, err := v.Tools.tool(role)
			if err != nil {
				return invalid
			}
			actual := material.Python
			if role == restoreRole {
				actual = material.Restore
			} else if role == "false" {
				actual = material.Blocker
			}
			if actual.Role != tool.Role || actual.Invoked != tool.Invoked || actual.Executable != tool.Executable || actual.File != tool.File || len(actual.Raw) != 0 {
				return invalid
			}
		}
		for _, target := range []string{"candidate", "previous"} {
			if _, err = ufwRestorePayload(material, target); err != nil {
				return err
			}
		}
		projected, err := projectUFWAuxiliaries(material.Before, material.After, family)
		if err != nil || !bytes.Equal(projected, material.After) {
			return errors.New("UFW 候选改变了原日志或限速辅助配置")
		}
		beforeFiles[family], err = parseUFWNative(material.Before, family, true)
		if err != nil {
			return err
		}
		beforeFiles[family], err = ufwUnownedRules(beforeFiles[family], family, owned)
		if err != nil {
			return err
		}
		afterFiles[family], err = parseUFWNative(material.After, family, true)
		if err != nil {
			return err
		}
		tuples += len(afterFiles[family].Rules)
		for _, chain := range observed.Chains {
			if chain.Present {
				chains++
			}
			rules += len(chain.Rules)
		}
		for _, chain := range material.AfterKernel {
			afterRules += len(chain.Rules)
		}
	}
	if tuples > firewall.MaxEntries || rules > firewall.MaxEntries || afterRules > firewall.MaxEntries || chains != v.Reload.Chains || rules != v.Reload.Rules || verifyUFWBatchOrder(beforeFiles, afterFiles, expected) != nil {
		return invalid
	}
	raw, err = json.Marshal(v.Reload.Families)
	if err != nil || secure.Hash(append([]byte("ufw:reload-kernel:v2:\x00"), raw...)) != v.Reload.Hash {
		return invalid
	}
	batchFiles := []ufwBatchFile{}
	for _, path := range []string{"/etc/ufw/user.rules", "/etc/ufw/user6.rules"} {
		if file := files[path]; file.Present {
			entry := ufwBatchFile{Path: path, Hash: file.Hash, Bytes: int(file.Bytes)}
			for _, material := range v.Materials {
				if material.Family == "ipv4" && path == "/etc/ufw/user.rules" || material.Family == "ipv6" && path == "/etc/ufw/user6.rules" {
					entry.Hash, entry.Bytes = material.AfterHash, len(material.After)
				}
			}
			batchFiles = append(batchFiles, entry)
		}
	}
	batchHash, err := ufwBatchDigest(v.ConfigurationHash, v.NativeHash, v.DryRunHash, v.Tools.Hash, batchFiles)
	if err != nil || batchHash != v.BatchHash {
		return invalid
	}
	return nil
}

func validateUFWChange(v *ufwChangeCheckpoint) error {
	invalid := errors.New("UFW 原业务操作恢复快照无效")
	if v == nil || v.Schema != 3 || !validID(v.Operation.ID) || v.Policy.OperationID != v.Operation.ID || v.RequestHash != firewallRequestHash(v.Policy.PlanID, v.Policy.Action) || v.Operation.PlanID != v.Policy.PlanID || v.Operation.Action != v.Policy.Action || v.Operation.Version != v.Policy.Version || v.Operation.PolicyHash != v.Policy.PolicyHash || v.Operation.ProgramHash != v.Policy.ProgramHash || v.Operation.Deadline <= 0 || v.Operation.UpdatedAt <= 0 || len(v.Operation.Error) > 512 || v.LastRescue != "" && !validID(v.LastRescue) || !slices.Contains([]string{"running", "waiting_confirmation", "compensating", "recovery_required", "succeeded", "rolled_back", "failed"}, v.Operation.State) {
		return invalid
	}
	if err := validateUFWTransition(&v.Transition, v.Policy); err != nil {
		return err
	}
	confirmed := v.Transition.Previous
	if v.Operation.State == "succeeded" {
		confirmed = &v.Policy
	}
	if !sameUFWPolicyRecord(v.Confirmed, confirmed) {
		return errors.New("UFW 已确认选择与原业务结果不一致")
	}
	if v.Operation.ID == v.Policy.PlanID || v.Operation.ID == v.Transition.Owner || v.Operation.ID == v.Transition.RegistrationOperationID || v.Operation.VerificationScope != "controlled-listener" || len(v.Operation.Stage) == 0 || len(v.Operation.Stage) > 128 || v.Rollback != slices.Contains([]string{"compensating", "recovery_required", "rolled_back"}, v.Operation.State) {
		return invalid
	}
	if v.Operation.ConfirmedSource != "" && !validUFWConfirmationSource(v.Operation.ConfirmedSource) || v.Operation.State == "succeeded" && v.Operation.ConfirmedSource == "" {
		return invalid
	}
	if len(v.Steps) != len(v.Transition.Materials)*2 {
		return invalid
	}
	seen := map[string]bool{v.Operation.ID: true, v.Policy.PlanID: true, v.Transition.Owner: true, v.Transition.RegistrationOperationID: true}
	for index, step := range v.Steps {
		target := "candidate"
		if index%2 == 1 {
			target = "previous"
		}
		if !validID(step.ID) || seen[step.ID] || step.Target != target || step.Family != v.Transition.Materials[index/2].Family {
			return invalid
		}
		seen[step.ID] = true
	}
	return validateUFWFileCommits(v, seen)
}

func loadUFWChange(dataDir string) (*ufwChangeCheckpoint, error) {
	raw, err := listenerRead(ufwChangePath(dataDir), ufwChangeBytes)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var v ufwChangeCheckpoint
	if err = ufwToolJSON(raw, &v); err != nil {
		return nil, err
	}
	if err = validateUFWChange(&v); err != nil {
		return nil, err
	}
	return &v, nil
}

func ufwChangeReceiptMatches(record Record, v *ufwChangeCheckpoint) bool {
	if record.Kind != firewallOperationKind || record.OperationID != v.Operation.ID || record.RequestHash != v.RequestHash || record.CandidateHash != ufwChangeHash(v) || record.State != v.Operation.State || record.Stage != v.Operation.Stage || record.Deadline != v.Operation.Deadline || record.Error != v.Operation.Error || record.Firewall == nil {
		return false
	}
	a, _ := json.Marshal(record.Firewall)
	b, _ := json.Marshal(v.Operation)
	return bytes.Equal(a, b)
}

func ufwChangePending(dataDir string) bool {
	v, err := loadUFWChange(dataDir)
	if err != nil || v == nil {
		return err != nil
	}
	r, err := loadUFWReceipt(dataDir, v.Operation.ID)
	return err != nil || !ufwChangeReceiptMatches(r, v) || !ufwChangeTerminal(v)
}

func ufwChangeTerminal(v *ufwChangeCheckpoint) bool {
	return v != nil && slices.Contains([]string{"succeeded", "rolled_back", "failed"}, v.Operation.State)
}

func saveUFWChange(dataDir string, v *ufwChangeCheckpoint) error {
	if err := validateUFWChange(v); err != nil {
		return err
	}
	if current, err := loadUFWChange(dataDir); err != nil {
		return err
	} else if current != nil {
		if current.Operation.ID == v.Operation.ID {
			if ufwChangeIntentHash(current) != ufwChangeIntentHash(v) {
				return errors.New("UFW 原业务快照或执行许可发生变化，禁止覆盖")
			}
			if current.Rollback && !v.Rollback || slices.Contains([]string{"succeeded", "rolled_back", "failed"}, current.Operation.State) && current.Operation.State != v.Operation.State {
				return errors.New("UFW 原业务已进入恢复或终态，禁止改变执行方向")
			}
			if current.Operation.ConfirmedSource != "" && current.Operation.ConfirmedSource != v.Operation.ConfirmedSource {
				return errors.New("UFW 原新连接确认来源发生变化，禁止覆盖")
			}
			for index, file := range current.Files {
				for position, image := range []*dnsFile{file.Candidate, file.Previous} {
					next := v.Files[index].Candidate
					if position == 1 {
						next = v.Files[index].Previous
					}
					if image != nil && (next == nil || image.hash() != next.hash()) {
						return errors.New("UFW 原持久文件准备回执发生变化，禁止覆盖")
					}
				}
			}
		} else if !slices.Contains([]string{"succeeded", "rolled_back", "failed"}, current.Operation.State) {
			return errors.New("UFW 原业务操作尚未结束，禁止替换恢复快照")
		}
	}
	if old, err := loadUFWReceipt(dataDir, v.Operation.ID); err == nil {
		if old.Kind != firewallOperationKind || old.RequestHash != v.RequestHash || old.Firewall == nil || old.Firewall.ID != v.Operation.ID || old.Firewall.PlanID != v.Policy.PlanID || old.Firewall.Version != v.Policy.Version || old.Firewall.PolicyHash != v.Policy.PolicyHash || old.Firewall.ProgramHash != v.Policy.ProgramHash {
			return errors.New("UFW 原业务操作身份冲突，禁止覆盖")
		}
		if slices.Contains([]string{"succeeded", "rolled_back", "failed"}, old.State) && old.State != v.Operation.State {
			return errors.New("UFW 原业务终态与恢复快照冲突，禁止重开操作")
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := secure.RootDirectory(filepath.Dir(ufwChangePath(dataDir)), 0700); err != nil {
		return err
	}
	if err := rootJSONWrite(ufwChangePath(dataDir), v, ufwChangeBytes); err != nil {
		return err
	}
	op := &v.Operation
	return ufwRegistrationJournal(dataDir).Put(Record{OperationID: op.ID, RequestHash: v.RequestHash, Kind: firewallOperationKind, State: op.State, Stage: op.Stage, Deadline: op.Deadline, Error: op.Error, Firewall: op, CandidateHash: ufwChangeHash(v)})
}

// Caller holds ufw-business.lock through submission and publication.
func acceptUFWChangeLocked(ctx context.Context, dataDir, id string, plan firewallPrivatePlan) (*ufwChangeCheckpoint, error) {
	if os.Geteuid() != 0 || !filepath.IsAbs(dataDir) || filepath.Clean(dataDir) != dataDir || !validID(id) || plan.record == nil || plan.ufw == nil || plan.view.Backend != "ufw" || plan.view.ID != plan.record.PlanID || plan.view.UFW == nil || plan.view.UFW.BatchHash != plan.ufw.BatchHash || plan.view.UFW.ToolchainHash != plan.ufw.Tools.Hash || plan.view.UFW.ReloadHash != plan.ufw.Reload.Hash || plan.view.PolicyHash != plan.record.PolicyHash || plan.view.ProgramHash != plan.record.ProgramHash || plan.view.Version != plan.record.Version || plan.view.Action != plan.record.Action || time.Now().Unix() >= plan.view.ExpiresAt {
		return nil, errors.New("UFW 业务操作尚不具备完整受理条件")
	}
	unlock, err := (&Journal{Dir: "/run/nginxpanel-host"}).rootLock("firewall-registration.lock")
	if err != nil {
		return nil, err
	}
	defer unlock()
	if ufwRestorePending(dataDir) {
		return nil, errors.New("原 UFW 业务操作或子进程尚未完成，禁止新受理")
	}
	if err = validateUFWTransition(plan.ufw, *plan.record); err != nil {
		return nil, err
	}
	confirmed, err := ufwCurrentConfirmed(dataDir, plan.ufw.Owner)
	if err != nil || !sameUFWPolicyRecord(confirmed, plan.ufw.Previous) {
		return nil, errors.New("UFW 原确认策略在受理前变化，请重新计划")
	}
	previous, err := loadUFWChange(dataDir)
	if err != nil {
		return nil, err
	}
	if _, err := loadUFWReceipt(dataDir, id); !os.IsNotExist(err) {
		return nil, errors.New("UFW 新业务操作 ID 已使用或无法核对")
	}
	lock, err := lockUFWManager()
	if err != nil {
		return nil, err
	}
	defer lock.Close()
	if err = checkUFWTransitionSources(ctx, dataDir, plan.ufw); err != nil {
		return nil, err
	}
	for _, material := range plan.ufw.Materials {
		image, err := readUFWTransitionKernel(ctx, plan.ufw, material.Family, dataDir)
		if err != nil || !sameUFWReloadImage(image, material.BeforeKernel) {
			return nil, errors.New("UFW 受理前的原内核基线变化，请重新计划")
		}
	}
	policy := *plan.record
	policy.OperationID = id
	op := firewall.Operation{ID: id, PlanID: policy.PlanID, Action: policy.Action, Version: policy.Version, PolicyHash: policy.PolicyHash, ProgramHash: policy.ProgramHash, State: "running", Stage: "submitting_runtime", Deadline: time.Now().Unix() + firewall.ConfirmationSeconds, UpdatedAt: time.Now().Unix(), VerificationScope: "controlled-listener"}
	v := &ufwChangeCheckpoint{Schema: 3, RequestHash: firewallRequestHash(op.PlanID, op.Action), Policy: policy, Operation: op, Transition: *plan.ufw, Confirmed: confirmed}
	if previous != nil {
		v.LastRescue = previous.LastRescue
	}
	for _, material := range v.Transition.Materials {
		for _, target := range []string{"candidate", "previous"} {
			v.Steps = append(v.Steps, ufwChangeStep{ID: secure.ID(), Family: material.Family, Target: target})
		}
	}
	if err = captureUFWFileCommits(ctx, v); err != nil {
		return nil, err
	}
	if err = checkUFWTransitionSources(ctx, dataDir, plan.ufw); err != nil {
		return nil, err
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	if time.Now().Unix() >= plan.view.ExpiresAt {
		return nil, errors.New("UFW 原计划已过期，未受理业务操作")
	}
	if err = verifyUFWManagerLock(lock); err != nil {
		return nil, err
	}
	return v, saveUFWChange(dataDir, v)
}

func checkUFWTransitionSources(ctx context.Context, dataDir string, v *ufwPolicyTransition) error {
	authority, err := ufwRegistrationAuthority(dataDir)
	if err != nil || authority.NextClaim.Owner != v.Owner || authority.NextClaim.MachineHash != v.MachineHash || authority.NextClaim.OperationID != v.RegistrationOperationID {
		return errors.New("UFW 业务操作的原本机登记已变化")
	}
	binary, err := ufwTool()
	if err != nil || binary != v.Tools.Files[0].File.Path {
		return errors.New("UFW 业务操作的 CLI 路径已变化")
	}
	configuration, err := readUFWConfiguration(ctx, binary, v.IPv6)
	if err != nil || configuration.Hash != v.ConfigurationHash {
		return errors.New("UFW 业务操作的固定源配置已变化，禁止覆盖")
	}
	previous, err := ufwPolicyProgram(v.Previous, v.Owner)
	if err != nil {
		return err
	}
	owned, err := ufwNativeProgram(previous)
	if err != nil {
		return err
	}
	if err = verifyUFWOwnedConfiguration(configuration, v.IPv6, owned); err != nil {
		return err
	}
	return v.Tools.verify(ctx)
}

func readUFWTransitionKernel(ctx context.Context, v *ufwPolicyTransition, family, dataDir string) ([]ufwReloadChain, error) {
	role := "iptables-save"
	if family == "ipv6" && v.IPv6 {
		role = "ip6tables-save"
	} else if family != "ipv4" {
		return nil, errors.New("UFW 内核核对地址族无效")
	}
	raw, err := v.Tools.read(ctx, role, "rules", filepath.Dir(ufwChangePath(dataDir)))
	if err != nil {
		return nil, err
	}
	return ufwReloadKernel(raw, family)
}
