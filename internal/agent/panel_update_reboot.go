package agent

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"nginxpanel/internal/panelruntime"
	"nginxpanel/internal/secure"
)

const maxPanelUpdateReboots = 4

// A root-approved boot rescue adds new control receipts. Completed starts and
// their process evidence remain immutable, including those from earlier boots.
type PanelUpdateReboot struct {
	PreviousStartID string                  `json:"previous_start_id"`
	StopID          string                  `json:"stop_id"`
	StartID         string                  `json:"start_id"`
	Rescue          CoordinatedAgentRescue  `json:"rescue"`
	Before          PanelServiceObservation `json:"before"`
	Stop            *Record                 `json:"stop,omitempty"`
	Start           *Record                 `json:"start,omitempty"`
}

func (p *PanelUpdateOperation) rollbackStarted() *Record {
	if len(p.Reboots) > 0 {
		return p.Reboots[len(p.Reboots)-1].Start
	}
	return p.RollbackStart
}

func validCoordinatedRescue(rescue CoordinatedAgentRescue, intent *CoordinatedAgentIntent) bool {
	return intent != nil && (rescue.Program == intent.Before || rescue.Program == intent.Target) && agentProcessValid(rescue.Process) && rescue.Process.State == "running" && rescue.Process.BootID != intent.BeforeProcess.BootID && rescue.AuthorizedAt > 0 && rescue.AuthorizedAt <= time.Now().Unix()+300
}

func (s *CoordinatedAgentState) knowsRescue(rescue CoordinatedAgentRescue) bool {
	if s.Rescue != nil && *s.Rescue == rescue {
		return true
	}
	for _, approved := range s.RescueHistory {
		if approved == rescue {
			return true
		}
	}
	return false
}

func validPanelUpdateReboots(r Record, originalIDs []string) error {
	p, i := r.PanelUpdate, r.PanelUpdate.Intent
	if len(p.Reboots) == 0 {
		return nil
	}
	if len(p.Reboots) > maxPanelUpdateReboots || i.Agent == nil || p.Agent.Rescue == nil || !p.RollbackSelected || p.Restore == nil || p.Restore.State != "succeeded" || p.Failure == "" {
		return errors.New("跨启动回滚缺少本机救援、原恢复或容量依据")
	}
	seen := make(map[string]bool, len(originalIDs)+2*len(p.Reboots))
	for _, id := range originalIDs {
		seen[id] = true
	}
	previous := p.RollbackStart
	for _, reboot := range p.Reboots {
		for _, id := range []string{reboot.StopID, reboot.StartID} {
			if !validID(id) || seen[id] {
				return errors.New("跨启动回滚的子操作身份无效或重复")
			}
			seen[id] = true
		}
		rescue := reboot.Rescue
		before := reboot.Before
		if previous == nil || previous.State != "succeeded" || reboot.PreviousStartID != previous.OperationID || !validCoordinatedRescue(rescue, i.Agent) || !p.Agent.knowsRescue(rescue) || !validServiceObservation(before) || before.Mode != i.Before.Mode || before.ReleaseID != i.BeforeID || before.BootID == previous.PanelService.After.BootID || before.Mode == "native" && before.BootID != rescue.Process.BootID {
			return errors.New("跨启动回滚与原启动、本机救援不一致")
		}
		if reboot.Stop != nil && reboot.Stop.PanelService.Intent.Before != before {
			return errors.New("跨启动回滚停机不属于批准的启动代次")
		}
		if reboot.Start != nil && (reboot.Stop == nil || reboot.Stop.State != "succeeded" || reboot.Start.PanelService.Intent.Input.StopID != reboot.StopID || reboot.Start.PanelService.Intent.StopSHA256 != reboot.Stop.RequestHash) {
			return errors.New("跨启动回滚的启动未关联新停机回执")
		}
		previous = reboot.Start
	}
	return nil
}

func (w *panelUpdateWorker) rollbackReadinessStart(ctx context.Context, s panelruntime.Snapshot) (*Record, error) {
	p := w.r.PanelUpdate
	boot, bootErr := panelProcFile("/proc/sys/kernel/random/boot_id", 64)
	hostBoot := strings.TrimSpace(string(boot))
	started := p.rollbackStarted()
	if started != nil && started.State == "succeeded" {
		observed, err := observeUpdatePanelService(ctx, s)
		if err != nil {
			return nil, err
		}
		if observed == *started.PanelService.After {
			return started, nil
		}
		rescue := p.Agent
		if bootErr != nil || rescue == nil || rescue.Rescue == nil || !validServiceObservation(observed) || hostBoot != rescue.Rescue.Process.BootID || observed.Mode == "native" && observed.BootID != hostBoot || observed.BootID == started.PanelService.After.BootID || s.Release.ID != p.Intent.BeforeID {
			return nil, errors.Join(bootErr, errors.New("原回滚启动实例已变化，须本机 root 批准当前启动代次"))
		}
		if len(p.Reboots) >= maxPanelUpdateReboots {
			return nil, errors.New("跨启动回滚次数已达上限，须本机维护")
		}
		access, err := w.access(ctx, true)
		if err != nil {
			return nil, err
		}
		// Docker's boot ID identifies the authenticated launcher, while the
		// approval identifies the host kernel boot. Persist both identities.
		p.Reboots = append(p.Reboots, PanelUpdateReboot{PreviousStartID: started.OperationID, StopID: secure.ID(), StartID: secure.ID(), Rescue: *rescue.Rescue, Before: observed})
		// Reserve space for both completed service receipts before controlling
		// any process; the parent record has a fixed 128 KiB read budget.
		raw, marshal := json.Marshal(w.r)
		if marshal != nil || len(raw) > (128<<10)-(16<<10) {
			p.Reboots = p.Reboots[:len(p.Reboots)-1]
			access()
			return nil, errors.Join(marshal, errors.New("跨启动回滚记录的剩余容量不足"))
		}
		err = w.save()
		access()
		if err != nil {
			return nil, err
		}
	}
	if len(p.Reboots) == 0 {
		return nil, errors.New("原回滚启动回执缺失或尚未完成")
	}
	reboot := &p.Reboots[len(p.Reboots)-1]
	if bootErr != nil || hostBoot != reboot.Rescue.Process.BootID {
		return nil, errors.Join(bootErr, errors.New("跨启动的未确认进程控制结果需要本机维护，禁止重放原派发"))
	}
	if reboot.Start != nil {
		// A pending start can be reconciled only in its recorded boot. A later
		// boot cannot establish whether that original dispatch took effect.
		if reboot.Start.PanelService.Intent.Before.BootID != reboot.Before.BootID {
			return nil, errors.New("跨启动的未确认启动结果需要本机维护，禁止重放原派发")
		}
		if err := w.service(ctx, &reboot.Start, reboot.StartID, "start", s, reboot.Stop); err != nil {
			return nil, err
		}
		return reboot.Start, nil
	}
	if err := w.service(ctx, &reboot.Stop, reboot.StopID, "stop", s, nil); err != nil {
		return nil, err
	}
	if err := w.coordinateAgent(ctx, true); err != nil {
		return nil, err
	}
	if err := w.service(ctx, &reboot.Start, reboot.StartID, "start", s, reboot.Stop); err != nil {
		return nil, err
	}
	return reboot.Start, nil
}
