package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"

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

func iptablesRoundTrip(material iptablesChangeMaterial) ([]byte, error) {
	header, commit := []byte("*filter\n"), []byte("COMMIT\n")
	if !bytes.HasPrefix(material.Candidate, header) || !bytes.HasPrefix(material.Previous, header) || !bytes.HasSuffix(material.Candidate, commit) || !bytes.HasSuffix(material.Previous, commit) || bytes.Count(material.Candidate, commit) != 1 || bytes.Count(material.Previous, commit) != 1 {
		return nil, errors.New("iptables 正反向批次边界无效")
	}
	// Both directions must be parsed in one table image. Testing a standalone
	// reverse batch against the unchanged live namespace would prove nothing.
	batch := append([]byte{}, bytes.TrimSuffix(material.Candidate, commit)...)
	batch = append(batch, bytes.TrimPrefix(material.Previous, header)...)
	if len(batch) > 4<<20 {
		return nil, errors.New("iptables 正反向预演批次超过 4 MiB")
	}
	return batch, nil
}

func preflightIPTables(ctx context.Context, transition *iptablesTransition) (*iptablesDryRunProof, error) {
	if transition == nil || transition.Program == nil {
		return nil, errors.New("iptables 官方预演缺少完整代际计划或工具绑定")
	}
	return preflightIPTablesMaterials(ctx, transition.Tools, transition.ConfigurationHash, transition.Program.Hash, transition.Materials, func(image iptablesImage) error {
		return proveIPTablesGeneration(image, iptablesGeneration(iptablesPreviousProgram(transition), image.Family))
	})
}

// Both scopes use this closed --test transport. Scope-specific authority and
// material construction stay with their own planners and never accept text
// supplied by an API client as a restore input.
func preflightIPTablesMaterials(ctx context.Context, tools *iptablesToolBinding, configurationHash, programHash string, materials []iptablesChangeMaterial, prove func(iptablesImage) error) (*iptablesDryRunProof, error) {
	if tools == nil || !firewalldDigest(configurationHash) || !firewalldDigest(programHash) || len(materials) == 0 || len(materials) > 2 || prove == nil {
		return nil, errors.New("iptables 官方预演缺少完整材料、范围或工具绑定")
	}
	if err := tools.verify(ctx); err != nil {
		return nil, err
	}
	proof := &iptablesDryRunProof{ToolchainHash: tools.Hash, ConfigurationHash: configurationHash, ProgramHash: programHash, Calls: []iptablesDryRunCall{}}
	blocker, err := tools.tool("false")
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	for _, material := range materials {
		binary := tools.Backend
		if material.Family == "ipv6" {
			binary = "ip6tables-" + strings.TrimPrefix(binary, "iptables-")
		} else if material.Family != "ipv4" {
			return nil, errors.New("iptables 官方预演材料地址族无效")
		}
		if seen[material.Family] || material.Binary != binary || material.Before.Family != material.Family || material.After.Family != material.Family || material.BeforeHash != material.Before.hash() || material.AfterHash != material.After.hash() || material.CandidateHash != secure.Hash(material.Candidate) || material.PreviousHash != secure.Hash(material.Previous) {
			return nil, errors.New("iptables 官方预演材料与原始摘要不一致")
		}
		seen[material.Family] = true
		before, err := tools.image(ctx, material.Family)
		if err != nil || before.hash() != material.BeforeHash || prove(before) != nil {
			return nil, errors.New("iptables 固定工具的完整导出与计划原始基线不一致")
		}
		restore, err := tools.tool(material.Binary + "-restore")
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
	for _, material := range materials {
		after, err := tools.image(ctx, material.Family)
		if err != nil || after.hash() != material.BeforeHash || prove(after) != nil {
			return nil, errors.New("iptables 官方预演后原完整规则不一致，未生成计划")
		}
	}
	if err = tools.verify(ctx); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(proof)
	if err != nil {
		return nil, err
	}
	proof.Hash = secure.Hash(append([]byte("iptables:dry-run:v1:\x00"), raw...))
	return proof, nil
}
