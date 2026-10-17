package agent

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	"nginxpanel/internal/firewall"
	"nginxpanel/internal/secure"
)

type ufwConfirmedObservation struct {
	Configuration ufwConfigurationSnapshot
	Families      []ufwRepairFamily
	Missing       bool
	Hash          string
}

func checkUFWConfirmedAnchor(dataDir string, source *ufwChangeCheckpoint) error {
	current, err := loadUFWChange(dataDir)
	if err != nil || current == nil || !ufwChangeTerminal(current) || ufwChangeHash(current) != ufwChangeHash(source) {
		return errors.New("UFW 原确认业务检查点已变化")
	}
	r, err := loadUFWReceipt(dataDir, current.Operation.ID)
	if err != nil || !ufwChangeReceiptMatches(r, current) {
		return errors.New("UFW 原确认业务独立回执无法核对")
	}
	authority, err := ufwRegistrationAuthority(dataDir)
	if err != nil || authority.NextClaim.Owner != current.Transition.Owner || authority.NextClaim.MachineHash != current.Transition.MachineHash || authority.NextClaim.OperationID != current.Transition.RegistrationOperationID {
		return errors.New("UFW 原确认策略不属于当前本机授权")
	}
	return nil
}

func checkUFWRepairAnchor(dataDir string, v *ufwRepairCheckpoint) (*ufwChangeCheckpoint, error) {
	source, err := loadUFWChange(dataDir)
	if err != nil || source == nil || source.Operation.ID != v.Status.SourceOperationID || ufwChangeHash(source) != v.Status.SourceHash || !sameUFWPolicyRecord(source.Confirmed, &v.Policy) || source.Transition.Owner != v.Owner || source.Transition.IPv6 != v.IPv6 || source.Transition.Tools.Hash != v.ToolchainHash || v.Files[0] != source.Transition.Tools.Files[0].File {
		return nil, errors.New("UFW 修复缺少原本机确认及工具依据，禁止重放")
	}
	if err = checkUFWConfirmedAnchor(dataDir, source); err != nil {
		return nil, err
	}
	return source, nil
}

// Caller holds ufw-business.lock. Official status takes the POSIX UFW lock,
// so it must finish before our conflicting OFD lock is acquired. The callback
// publishes or executes while the registration and manager locks remain held.
func withUFWConfirmedObservation(ctx context.Context, dataDir string, source *ufwChangeCheckpoint, execution bool, action func(ufwConfirmedObservation, *os.File) error) error {
	unlock, err := (&Journal{Dir: "/run/nginxpanel-host"}).rootLock("firewall-registration.lock")
	if err != nil {
		return err
	}
	defer unlock()
	if execution {
		executionUnlock, err := (&Journal{Dir: "/run/nginxpanel-host"}).rootLock("ufw-execution.lock")
		if err != nil {
			return err
		}
		defer executionUnlock()
	}
	if err = checkUFWConfirmedAnchor(dataDir, source); err != nil {
		return err
	}
	if ufwRestoreProcessPending(dataDir) {
		return errors.New("UFW 原子进程尚未结束并完成独立回执")
	}
	if _, err = checkUFWEnvironment(ctx, dataDir, source.Transition.IPv6, source.Transition.Reload.Backend); err != nil {
		return err
	}
	manager, err := lockUFWManager()
	if err != nil {
		return err
	}
	defer manager.Close()
	enabled, enabledErr := ufwConfigured()
	ipv6, ipv6Err := ufwConfigurationFlag("/etc/default/ufw", "IPV6")
	if enabledErr != nil || ipv6Err != nil || enabled == nil || !*enabled || ipv6 == nil || *ipv6 != source.Transition.IPv6 {
		return errors.New("UFW 持久启用状态或地址族在核对期间变化")
	}
	if err = source.Transition.Tools.verify(ctx); err != nil {
		return err
	}
	binary, err := ufwTool()
	if err != nil || binary != source.Transition.Tools.Files[0].File.Path {
		return errors.New("已确认 UFW 的 CLI 选择发生变化")
	}
	configuration, err := readUFWConfiguration(ctx, binary, *ipv6)
	if err != nil {
		return err
	}
	program, err := ufwPolicyProgram(source.Confirmed, source.Transition.Owner)
	if err != nil {
		return err
	}
	owned, err := ufwNativeProgram(program)
	if err != nil {
		return err
	}
	if err = verifyUFWOwnedConfiguration(configuration, *ipv6, owned); err != nil {
		return err
	}
	observed := ufwConfirmedObservation{Configuration: configuration, Families: []ufwRepairFamily{}}
	families := []string{"ipv4"}
	if *ipv6 {
		families = append(families, "ipv6")
	}
	count := 0
	for _, family := range families {
		image, err := readUFWTransitionKernel(ctx, &source.Transition, family, dataDir)
		if err != nil {
			return err
		}
		raw := configuration.Contents[ufwRepairUserPath(family)]
		after, payload, err := ufwRepairProjection(raw, family, image, owned)
		if err != nil {
			return err
		}
		for _, chain := range after {
			count += len(chain.Rules)
		}
		if count > firewall.MaxEntries {
			return errors.New("UFW 确认规则核对范围合计超过 8192 条")
		}
		observed.Families = append(observed.Families, ufwRepairFamily{Family: family, Raw: raw, Before: image})
		observed.Missing = observed.Missing || len(payload) != 0
	}
	after, err := readUFWConfiguration(ctx, binary, *ipv6)
	if err != nil || after.Hash != configuration.Hash {
		return errors.New("UFW 固定配置在确认规则核对期间变化")
	}
	if err = source.Transition.Tools.verify(ctx); err != nil {
		return err
	}
	current, err := ufwTool()
	if err != nil || current != binary {
		return errors.New("UFW CLI 选择在确认规则核对期间变化")
	}
	if err = checkUFWConfirmedAnchor(dataDir, source); err != nil {
		return err
	}
	if err = verifyUFWManagerLock(manager); err != nil {
		return err
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	proof, _ := json.Marshal(struct {
		Source, Configuration, Tools string
		Families                     []ufwRepairFamily
	}{ufwChangeHash(source), configuration.Hash, source.Transition.Tools.Hash, observed.Families})
	observed.Hash = secure.Hash(append([]byte("ufw:confirmed-observation:v1:\x00"), proof...))
	return action(observed, manager)
}

func newUFWRepair(dataDir string, source *ufwChangeCheckpoint, observed ufwConfirmedObservation) error {
	if source.Confirmed == nil || source.Confirmed.Action != "apply" || !observed.Missing || ufwRestorePending(dataDir) {
		return errors.New("UFW 没有可由原确认策略证明的缺失规则")
	}
	v := &ufwRepairCheckpoint{Schema: 1, Owner: source.Transition.Owner, Policy: *source.Confirmed, IPv6: source.Transition.IPv6, ToolchainHash: source.Transition.Tools.Hash, ConfigurationHash: observed.Configuration.Hash, Files: observed.Configuration.Files, Families: observed.Families,
		Status: ufwRepairStatus{ID: secure.ID(), SourceOperationID: source.Operation.ID, SourceHash: ufwChangeHash(source), ProgramHash: source.Confirmed.ProgramHash, State: "running"}}
	for index := range v.Families {
		v.Families[index].CallIDs = []string{secure.ID(), secure.ID(), secure.ID()}
	}
	v.Status.IntentHash = ufwRepairIntentHash(v)
	return saveUFWRepair(dataDir, v)
}

func reconcileUFWConfirmed(ctx context.Context, dataDir string) error {
	if os.Geteuid() != 0 || !filepath.IsAbs(dataDir) || filepath.Clean(dataDir) != dataDir || (&HostDNS{Scope: "host"}).hostScopeReason() != "" {
		return errors.New("UFW 确认规则核对与修复须真实宿主机 root 范围")
	}
	unlock, err := (&Journal{Dir: "/run/nginxpanel-host"}).rootLock("ufw-business.lock")
	if err != nil {
		return err
	}
	defer unlock()
	if err = recoverUFWRepairLocked(ctx, dataDir); err != nil {
		return err
	}
	source, err := loadUFWChange(dataDir)
	if err != nil || source == nil {
		return err
	}
	parent, err := loadUFWReceipt(dataDir, source.Operation.ID)
	if err != nil || !ufwChangeReceiptMatches(parent, source) || !ufwChangeTerminal(source) || ufwRestorePending(dataDir) {
		return errors.New("UFW 原业务、确认规则修复或子进程尚未完成核对")
	}
	if source.Confirmed == nil || source.Confirmed.Action == "remove" {
		return nil
	}
	// At most two fresh intents per reconciliation. A continuously changing
	// foreign configuration remains read-only until a later stable observation.
	for attempt := 0; attempt < 3; attempt++ {
		created := false
		err = withUFWConfirmedObservation(ctx, dataDir, source, false, func(observed ufwConfirmedObservation, _ *os.File) error {
			if !observed.Missing {
				return nil
			}
			if attempt == 2 {
				return errors.New("UFW 确认修复基线持续变化，等待重新核对")
			}
			created = true
			return newUFWRepair(dataDir, source, observed)
		})
		if err != nil || !created {
			return err
		}
		// Release the observation's manager and registration locks before
		// entering the independently locked process transport.
		if err = recoverUFWRepairLocked(ctx, dataDir); err != nil {
			return err
		}
	}
	return errors.New("UFW 确认规则尚未取得稳定核对结果")
}

// Terminal repair checkpoints remain valid after a subsequent policy replaces
// the source checkpoint. Only active repair requires that exact source anchor.
func recoverUFWRepair(ctx context.Context, dataDir string) error {
	if os.Geteuid() != 0 || !filepath.IsAbs(dataDir) || filepath.Clean(dataDir) != dataDir || (&HostDNS{Scope: "host"}).hostScopeReason() != "" {
		return errors.New("UFW 确认规则修复须真实宿主机 root 范围")
	}
	unlock, err := (&Journal{Dir: "/run/nginxpanel-host"}).rootLock("ufw-business.lock")
	if err != nil {
		return err
	}
	defer unlock()
	return recoverUFWRepairLocked(ctx, dataDir)
}
