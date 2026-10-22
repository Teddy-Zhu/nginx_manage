package agent

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"nginxpanel/internal/fault"
)

// Only targets of validated, settled upgrades establish ownership. Current and
// unfinished upgrade/rollback programs remain pinned regardless of retention.
func (n *Nginx) agentProgramHistory(ctx context.Context, maintenanceID string, records []Record) (string, map[string]bool, []historyCandidate, error) {
	current, err := readAgentProgram()
	if err != nil {
		return "", nil, nil, err
	}
	process, err := agentUpgradeObserve(ctx, n.DataDir, maintenanceID, current)
	if err != nil || process.State != "running" {
		return "", nil, nil, errors.Join(err, fault.Conflict("无法确认当前节点的 Agent 程序与实际进程"))
	}
	pinned := map[string]bool{current.Link: true}
	owned := map[string]int64{}
	addTarget := func(p AgentProgram, at int64) {
		if strings.HasPrefix(p.Link, "agent-releases/") && at > owned[p.Link] {
			owned[p.Link] = at
		}
	}
	for _, r := range records {
		if err = ctx.Err(); err != nil {
			return "", nil, nil, err
		}
		switch r.Kind {
		case agentUpgradeKind:
			if err = validAgentUpgrade(r); err != nil {
				return "", nil, nil, err
			}
			i := r.AgentUpgrade.Intent
			if i.Input.Stage.DataDir != n.DataDir {
				return "", nil, nil, ErrExternalChange
			}
			if agentUpgradeTerminal(r) {
				addTarget(i.Target, r.UpdatedAt)
			} else {
				pinned[i.Before.Link], pinned[i.Target.Link] = true, true
			}
		case panelUpdateKind:
			if err = validPanelUpdate(r); err != nil {
				return "", nil, nil, err
			}
			i := r.PanelUpdate.Intent
			if i.Input.Stage.DataDir != n.DataDir {
				return "", nil, nil, ErrExternalChange
			}
			if i.Agent == nil {
				continue
			}
			if panelUpdateTerminal(r) {
				addTarget(i.Agent.Target, r.UpdatedAt)
			} else {
				pinned[i.Agent.Before.Link], pinned[i.Agent.Target.Link] = true, true
				if rescue := r.PanelUpdate.Agent.Rescue; rescue != nil {
					pinned[rescue.Program.Link] = true
				}
				for _, rescue := range r.PanelUpdate.Agent.RescueHistory {
					pinned[rescue.Program.Link] = true
				}
			}
		case nginxImageKind:
			if err = validNginxImage(r); err != nil {
				return "", nil, nil, err
			}
			if r.NginxImage.Intent.Input.Stage.DataDir != n.DataDir {
				return "", nil, nil, ErrExternalChange
			}
			if !nginxImageTerminal(r) {
				pinned[r.NginxImage.Intent.Agent.Link] = true
			}
		}
	}
	root := filepath.Join(agentBootstrapRoot, "agent-releases")
	if err = existingRootDirectory(root); os.IsNotExist(err) {
		return current.Link, pinned, nil, nil
	} else if err != nil {
		return "", nil, nil, err
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return "", nil, nil, err
	}
	if len(entries) > 8 {
		return "", nil, nil, fault.Conflict("Agent 发布目录超出登记容量，须先核对未知材料")
	}
	candidates := []historyCandidate{}
	for _, entry := range entries {
		target := "agent-releases/" + entry.Name()
		at, known := owned[target]
		if !known {
			continue
		}
		if err = existingRootDirectory(filepath.Join(root, entry.Name())); err != nil {
			return "", nil, nil, err
		}
		candidates = append(candidates, historyCandidate{target: target, at: at, manifest: manifest{Files: map[string]string{"nginxpanel": entry.Name()}}})
	}
	return current.Link, pinned, candidates, nil
}
