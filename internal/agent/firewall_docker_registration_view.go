package agent

import (
	"slices"
	"time"

	"nginxpanel/internal/firewall"
)

func dockerRegistrationView(dataDir string, observed firewall.Observation) firewall.DockerRegistrationView {
	out := firewall.DockerRegistrationView{Registration: firewall.RegistrationView{State: "unavailable", ObservedAt: time.Now().Unix()}}
	v, err := loadDockerRegistration(dataDir)
	if err != nil {
		out.Registration.Reason = "Docker 本机授权记录无法读取"
		return out
	}
	if v == nil {
		out.Registration.State, out.Registration.Reason = "unregistered", "Docker 转发尚未独立授权"
		return out
	}
	out.Backend, out.EngineHash, out.ParentOperationID, out.Registration.OperationID = v.Backend, v.EngineHash, v.ParentOperationID, v.OperationID
	if v.State == "preparing" || dockerRegistrationReceipt(dataDir, v) != nil {
		out.Registration.State, out.Registration.Reason = "recovery_required", "Docker 原授权意图或回执尚未核对完成，请本机恢复或释放"
		return out
	}
	machine, _, err := iptablesHostIdentity()
	if err != nil || machine != v.MachineHash {
		out.Registration.State, out.Registration.Reason = "drifted", "Docker 授权的本机身份无法核对，禁止迁移 root 授权"
		return out
	}
	if v.State == "released" {
		out.Registration.State, out.Registration.Reason = "released", "Docker 转发授权已释放，未安装或移除第三方规则"
		return out
	}
	parent, err := iptablesRegistrationAuthority(dataDir)
	if err != nil || !dockerRegistrationParent(v, parent) {
		out.Registration.State, out.Registration.Reason = "drifted", "Docker 授权绑定的原 iptables 宿主机登记无法核对"
		return out
	}
	runtime := observed.Docker.Runtime
	if !observed.IPTablesRegistration.Registration.Verified || observed.IPTablesRegistration.Backend != v.Backend || observed.IPTablesRegistration.Registration.OperationID != v.ParentOperationID || !runtime.Available || runtime.Rootless || runtime.Swarm != "inactive" || runtime.EngineHash != v.EngineHash || observed.Docker.BackendHint != "iptables" || !slices.ContainsFunc(observed.Docker.Capabilities, func(capability firewall.DockerCapability) bool {
		return capability.Backend == v.Backend && capability.Observed
	}) {
		out.Registration.State, out.Registration.Reason = "drifted", "当前 Docker 实例、挂接或完整空命名空间无法核对"
		return out
	}
	out.Registration.State, out.Registration.Verified, out.Registration.Reason = "registered", true, "Docker 本机空命名空间授权已核对；业务规则执行尚未开放"
	return out
}

func validDockerRegistrationView(v firewall.DockerRegistrationView) bool {
	r := v.Registration
	if v.Backend != "" && !validIPTablesBackend(v.Backend) || v.EngineHash != "" && !firewalldDigest(v.EngineHash) || v.ParentOperationID != "" && !validID(v.ParentOperationID) || r.OperationID != "" && !validID(r.OperationID) || r.ObservedAt < 0 || len(r.Reason) > 4096 {
		return false
	}
	switch r.State {
	case "unavailable", "unregistered":
	case "registered", "released", "drifted", "recovery_required":
		if !validIPTablesBackend(v.Backend) || !firewalldDigest(v.EngineHash) || !validID(v.ParentOperationID) || !validID(r.OperationID) || r.ObservedAt <= 0 {
			return false
		}
	default:
		return false
	}
	return !r.Verified || r.State == "registered" && validIPTablesBackend(v.Backend) && firewalldDigest(v.EngineHash) && validID(v.ParentOperationID) && validID(r.OperationID) && r.ObservedAt > 0
}
