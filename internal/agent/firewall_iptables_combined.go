package agent

import (
	"bytes"
	"errors"

	"nginxpanel/internal/firewall"
	"nginxpanel/internal/secure"
)

// Physical Docker identity is local to this intent and its bounded confirmed
// source. Portable policy never contains grants, resolved endpoints or paths.
type dockerIPTablesPolicyRecord struct {
	Registration dockerRegistrationCheckpoint
	Targets      firewall.DockerTargets
	Bindings     []firewall.DockerResolvedBinding
	Program      *firewall.DockerIPTablesRuntimeProgram
}

type iptablesProgramPair struct {
	Host   *firewall.IPTablesRuntimeProgram
	Docker *dockerIPTablesPolicyRecord
}

func (pair iptablesProgramPair) families() []string {
	out := []string{}
	for _, family := range []string{"ipv4", "ipv6"} {
		if iptablesGeneration(pair.Host, family) != nil || dockerIPTablesGeneration(pair.Docker, family) != nil {
			out = append(out, family)
		}
	}
	return out
}

func validateDockerIPTablesPolicy(v *dockerIPTablesPolicyRecord, policy firewallPolicyRecord, owner, machineHash, registrationID, registrationHash string) error {
	if v == nil {
		if policy.Action == "apply" && firewall.HasDockerRules(policy.Policy) {
			return errors.New("Docker 业务意图缺少独立授权和完整目标绑定")
		}
		return nil
	}
	grant := &v.Registration
	if policy.Action != "apply" || !firewall.HasDockerRules(policy.Policy) || !validDockerRegistration(grant) || grant.State != "registered" || grant.ParentOwner != owner || grant.MachineHash != machineHash || grant.ParentOperationID != registrationID || grant.ParentRequestHash != registrationHash || grant.Backend != policy.Policy.Backend || grant.EngineHash != v.Targets.EngineHash || policy.PlanID == grant.OperationID || policy.PlanID == grant.Owner || policy.PlanID == grant.ParentOperationID || policy.OperationID == grant.Owner || policy.OperationID == grant.OperationID {
		return errors.New("Docker 业务意图的父子授权、实例或策略身份不一致")
	}
	targets, err := v.Targets.Normalize(policy.Policy)
	if err != nil || !sameIPTablesValue(targets, v.Targets) {
		return errors.New("Docker 业务意图的完整目标绑定无效")
	}
	program, err := firewall.CompileDockerIPTablesRuntime(policy.Policy, targets, v.Bindings, grant.Owner, policy.PlanID)
	if err != nil || !sameIPTablesValue(program, v.Program) {
		return errors.New("Docker 业务意图与完整重编译程序不一致")
	}
	return nil
}

func dockerIPTablesGeneration(v *dockerIPTablesPolicyRecord, family string) *firewall.IPTablesGeneration {
	if v != nil && v.Program != nil {
		for index := range v.Program.Families {
			if v.Program.Families[index].Family == family {
				return &v.Program.Families[index]
			}
		}
	}
	return nil
}

func iptablesPreviousDocker(v *iptablesTransition) *dockerIPTablesPolicyRecord {
	if v != nil && v.Previous != nil {
		return v.Previous.Docker
	}
	return nil
}

func iptablesTransitionProgramHash(v *iptablesTransition) string {
	if v == nil || v.Program == nil || v.Docker != nil && v.Docker.Program == nil {
		return ""
	}
	dockerHash := ""
	if v.Docker != nil {
		dockerHash = v.Docker.Program.Hash
	}
	return firewall.IPTablesCombinedProgramHash(v.Program.Hash, dockerHash)
}

func iptablesCombinedForeignImage(image iptablesImage, host, docker *firewall.IPTablesGeneration) (iptablesImage, error) {
	if err := proveIPTablesGeneration(image, host); err != nil {
		return iptablesImage{}, err
	}
	foreign, _, err := iptablesForeignImage(image, host)
	if err != nil {
		return iptablesImage{}, err
	}
	return dockerIPTablesForeignImage(foreign, docker)
}

// Each family has one filter COMMIT. The reverse batch undoes Docker before
// INPUT, matching the inverse of construction, without copying foreign rules.
func makeIPTablesCombinedChangeMaterial(before iptablesImage, oldHost, nextHost, oldDocker, nextDocker *firewall.IPTablesGeneration) (iptablesChangeMaterial, error) {
	foreign, err := iptablesCombinedForeignImage(before, oldHost, oldDocker)
	if err != nil {
		return iptablesChangeMaterial{}, err
	}
	if oldDocker == nil && nextDocker == nil {
		return makeIPTablesChangeMaterial(before, oldHost, nextHost)
	}
	current := before
	materials := []iptablesChangeMaterial{}
	if oldHost != nil || nextHost != nil {
		host, err := makeIPTablesChangeMaterial(current, oldHost, nextHost)
		if err != nil {
			return iptablesChangeMaterial{}, err
		}
		materials, current = append(materials, host), host.After
	}
	docker, err := makeDockerIPTablesChangeMaterial(current, oldDocker, nextDocker)
	if err != nil {
		return iptablesChangeMaterial{}, err
	}
	materials, current = append(materials, docker), docker.After
	forward, reverse := [][]byte{}, [][]byte{}
	for index, material := range materials {
		if material.Binary != docker.Binary {
			return iptablesChangeMaterial{}, errors.New("INPUT 与 Docker 切换的显式工具不一致")
		}
		forward = append(forward, material.Candidate)
		reverse = append(reverse, materials[len(materials)-1-index].Previous)
	}
	candidate, err := joinIPTablesFilterBatches(forward, firewall.IPTablesProgramBytes)
	if err != nil {
		return iptablesChangeMaterial{}, err
	}
	previous, err := joinIPTablesFilterBatches(reverse, firewall.IPTablesProgramBytes)
	if err != nil {
		return iptablesChangeMaterial{}, err
	}
	projected, err := iptablesCombinedForeignImage(current, nextHost, nextDocker)
	if err != nil || projected.hash() != foreign.hash() {
		return iptablesChangeMaterial{}, errors.New("INPUT 与 Docker 联合切换改变其他规则")
	}
	return iptablesChangeMaterial{Family: before.Family, Binary: docker.Binary, BeforeHash: before.hash(), AfterHash: current.hash(), CandidateHash: secure.Hash(candidate), PreviousHash: secure.Hash(previous), Before: before, After: current, Candidate: candidate, Previous: previous}, nil
}

func joinIPTablesFilterBatches(batches [][]byte, limit int) ([]byte, error) {
	header, commit := []byte("*filter\n"), []byte("COMMIT\n")
	out := append([]byte{}, header...)
	for _, batch := range batches {
		if !bytes.HasPrefix(batch, header) || !bytes.HasSuffix(batch, commit) || bytes.Count(batch, header) != 1 || bytes.Count(batch, commit) != 1 {
			return nil, errors.New("iptables 联合批次不是单一 filter 事务")
		}
		out = append(out, batch[len(header):len(batch)-len(commit)]...)
	}
	out = append(out, commit...)
	if len(batches) == 0 || limit != firewall.IPTablesProgramBytes && limit != 2*firewall.IPTablesProgramBytes || len(out) > limit {
		return nil, errors.New("iptables 联合批次为空或超过事务容量")
	}
	return out, nil
}

func makeIPTablesTransitionMaterial(image iptablesImage, v *iptablesTransition) (iptablesChangeMaterial, error) {
	return makeIPTablesCombinedChangeMaterial(image, iptablesGeneration(iptablesPreviousProgram(v), image.Family), iptablesGeneration(v.Program, image.Family), dockerIPTablesGeneration(iptablesPreviousDocker(v), image.Family), dockerIPTablesGeneration(v.Docker, image.Family))
}
