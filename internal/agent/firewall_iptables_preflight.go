package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"

	"nginxpanel/internal/secure"
)

type iptablesDryRunCall struct {
	Family, Mode, Tool, InputHash, OutputHash, DiagnosticHash string
	InputBytes, ExitCode                                      int
}

type iptablesDryRunProof struct {
	ToolchainHash, ConfigurationHash, ProgramHash, Hash string
	Calls                                               []iptablesDryRunCall
}

func iptablesRoundTrip(material iptablesInitialMaterial) ([]byte, error) {
	header, commit := []byte("*filter\n"), []byte("COMMIT\n")
	if !bytes.HasPrefix(material.Candidate, header) || !bytes.HasPrefix(material.Previous, header) || !bytes.HasSuffix(material.Candidate, commit) || !bytes.HasSuffix(material.Previous, commit) || bytes.Count(material.Candidate, commit) != 1 || bytes.Count(material.Previous, commit) != 1 {
		return nil, errors.New("iptables 正反向批次边界无效")
	}
	// Both directions must be parsed in one table image. Testing a standalone
	// reverse batch against the still-empty live namespace would prove nothing.
	batch := append([]byte{}, bytes.TrimSuffix(material.Candidate, commit)...)
	batch = append(batch, bytes.TrimPrefix(material.Previous, header)...)
	if len(batch) > 4<<20 {
		return nil, errors.New("iptables 正反向预演批次超过 4 MiB")
	}
	return batch, nil
}

func preflightIPTables(ctx context.Context, transition *iptablesInitialTransition) (*iptablesDryRunProof, error) {
	if transition == nil || transition.Program == nil || transition.Tools == nil || len(transition.Materials) == 0 || len(transition.Materials) > 2 {
		return nil, errors.New("iptables 官方预演缺少完整代际计划或工具绑定")
	}
	if err := transition.Tools.verify(ctx); err != nil {
		return nil, err
	}
	proof := &iptablesDryRunProof{ToolchainHash: transition.Tools.Hash, ConfigurationHash: transition.ConfigurationHash, ProgramHash: transition.Program.Hash, Calls: []iptablesDryRunCall{}}
	blocker, err := transition.Tools.tool("false")
	if err != nil {
		return nil, err
	}
	for _, material := range transition.Materials {
		before, err := transition.Tools.image(ctx, material.Family)
		if err != nil || before.hash() != material.BeforeHash || proveIPTablesGeneration(before, nil) != nil {
			return nil, errors.New("iptables 固定工具的完整导出与计划原始基线不一致")
		}
		restore, err := transition.Tools.tool(material.Binary + "-restore")
		if err != nil {
			return nil, err
		}
		roundTrip, err := iptablesRoundTrip(material)
		if err != nil {
			return nil, err
		}
		for _, item := range []struct {
			Mode  string
			Input []byte
		}{{"candidate", material.Candidate}, {"round_trip", roundTrip}} {
			output, err := runIPTablesBound(ctx, restore, blocker, "test", item.Input)
			if err != nil {
				return nil, err
			}
			proof.Calls = append(proof.Calls, iptablesDryRunCall{Family: material.Family, Mode: item.Mode, Tool: restore.Role, InputHash: secure.Hash(item.Input), InputBytes: len(item.Input), ExitCode: 0, OutputHash: secure.Hash(output), DiagnosticHash: secure.Hash(nil)})
		}
	}
	// Re-read every used family after all official tests, not merely after its
	// own pair, so later work cannot hide a change to an earlier family.
	for _, material := range transition.Materials {
		after, err := transition.Tools.image(ctx, material.Family)
		if err != nil || after.hash() != material.BeforeHash || proveIPTablesGeneration(after, nil) != nil {
			return nil, errors.New("iptables 官方预演后原完整规则不一致，未生成计划")
		}
	}
	if err = transition.Tools.verify(ctx); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(proof)
	if err != nil {
		return nil, err
	}
	proof.Hash = secure.Hash(append([]byte("iptables:dry-run:v1:\x00"), raw...))
	return proof, nil
}
