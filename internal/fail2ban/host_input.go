package fail2ban

import (
	"context"
	"time"

	"nginxpanel/internal/firewall"
)

// HostInputPreview reports a read-only, empty-set preparation. It neither
// authorizes a table nor proves that an engine ban reached host traffic.
type HostInputPreview struct {
	At                int64               `json:"at"`
	Scope             string              `json:"scope"`
	Available         bool                `json:"available"`
	Manager           string              `json:"manager"`
	ManagerObservedAt int64               `json:"manager_observed_at"`
	Backend           string              `json:"backend"`
	Table             string              `json:"table"`
	Hook              string              `json:"hook"`
	Priority          int                 `json:"priority"`
	CanPrepare        bool                `json:"can_prepare"`
	CanApply          bool                `json:"can_apply"`
	Kernel            firewall.KernelView `json:"kernel"`
	ProtectedSources  []string            `json:"protected_sources"`
	ProgramHash       string              `json:"program_hash"`
	TransactionHash   string              `json:"transaction_hash"`
	TransactionBytes  int                 `json:"transaction_bytes"`
	GeneratedRules    int                 `json:"generated_rules"`
	Reason            string              `json:"reason"`
}

func EmptyHostInput(scope, reason string) HostInputPreview {
	return HostInputPreview{At: time.Now().Unix(), Scope: scope, Manager: "unknown", Backend: "direct-nftables", Table: firewall.NFTFail2banTable, Hook: "input", Priority: firewall.NFTFail2banPriority, Kernel: firewall.KernelView{Reason: "尚未读取独立目标表"}, ProtectedSources: []string{}, Reason: reason}
}
func (v HostInputPreview) Valid() bool {
	if v.At <= 0 || v.ManagerObservedAt < 0 || v.Table != firewall.NFTFail2banTable || v.Hook != "input" || v.Priority != firewall.NFTFail2banPriority || v.Backend != "direct-nftables" || v.CanApply || v.ProtectedSources == nil || len(v.ProtectedSources) > firewall.NFTBanProtectionLimit || v.TransactionBytes < 0 || v.TransactionBytes > firewall.NFTBatchBytes || v.GeneratedRules < 0 || v.GeneratedRules > firewall.NFTBanProtectionLimit+2 || v.Available && (v.Scope != "host" || v.ManagerObservedAt == 0) {
		return false
	}
	set, err := (firewall.NFTBanSet{Addresses: []string{}, Protected: v.ProtectedSources}).Normalize()
	if err != nil || len(set.Protected) != len(v.ProtectedSources) {
		return false
	}
	for i, source := range set.Protected {
		if source != v.ProtectedSources[i] {
			return false
		}
	}
	k := v.Kernel
	if k.Available && (k.Generation == 0 || len(k.NamespaceID) != 64 || len(k.Fingerprint) != 64 || k.ObservedAt <= 0 || k.Bytes < 0 || k.Bytes > firewall.NFTBatchBytes || k.Chains < 0 || k.Chains > 128 || k.Rules < 0 || k.Rules > firewall.MaxEntries) {
		return false
	}
	if v.CanPrepare {
		return v.Available && v.Scope == "host" && v.Manager == "direct-candidate" && k.Available && !k.TableExists && len(v.ProgramHash) == 64 && len(v.TransactionHash) == 64 && v.TransactionBytes > 0 && v.GeneratedRules == len(v.ProtectedSources)+2 && v.Reason == ""
	}
	return v.Reason != "" && v.ProgramHash == "" && v.TransactionHash == "" && v.TransactionBytes == 0 && v.GeneratedRules == 0
}

type HostInputReader interface {
	ReadFail2banHostInput(context.Context) (HostInputPreview, error)
}

func (s *PolicyService) HostInput(ctx context.Context) (HostInputPreview, error) {
	reader, ok := s.Agent.(HostInputReader)
	if !ok {
		return EmptyHostInput("unconfirmed", "未连接宿主机动作预检"), nil
	}
	return reader.ReadFail2banHostInput(ctx)
}
