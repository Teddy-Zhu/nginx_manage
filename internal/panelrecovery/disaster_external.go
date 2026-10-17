package panelrecovery

import (
	"encoding/json"
	"errors"
	"strings"
	"unicode"
	"unicode/utf8"

	"nginxpanel/internal/secure"
)

// Groups bind a manual review to all selected source rows, including opaque
// execution material. The evidence is an operator reference, never a command.
type DisasterExternalGroup struct {
	Kind   string `json:"kind"`
	Count  int64  `json:"count"`
	SHA256 string `json:"sha256"`
}

type DisasterExternalDecision struct {
	DisasterExternalGroup
	Resolution string `json:"resolution"`
	Evidence   string `json:"evidence"`
}

type DisasterExternalReview struct {
	InventorySHA256 string                     `json:"inventory_sha256"`
	Decisions       []DisasterExternalDecision `json:"decisions"`
}

func ValidDisasterExternalKind(kind string) bool {
	switch kind {
	case "acme_accounts", "acme_orders", "acme_profiles", "dns_records", "migration_plans", "migration_pushes", "node_grants", "notification_deliveries", "pairing_grants", "source_tasks":
		return true
	}
	return false
}

func DisasterExternalInventorySHA256(id, reconciliation string, groups []DisasterExternalGroup) string {
	// Empty inventories have the same canonical representation in the CLI,
	// immutable root intent and both independent database helpers.
	if groups == nil {
		groups = []DisasterExternalGroup{}
	}
	raw, _ := json.Marshal(struct {
		OperationID string                  `json:"operation_id"`
		Reconciled  string                  `json:"reconciliation_sha256"`
		Groups      []DisasterExternalGroup `json:"groups"`
	}{id, reconciliation, groups})
	return secure.Hash(raw)
}

func (r DisasterExternalReview) Validate(id, reconciliation string) error {
	if !idValue.MatchString(id) || !hashValue.MatchString(reconciliation) || !hashValue.MatchString(r.InventorySHA256) || r.Decisions == nil || len(r.Decisions) > 10 {
		return errors.New("外部结果复核须指定原完整清单摘要和逐类处理依据")
	}
	groups := make([]DisasterExternalGroup, 0, len(r.Decisions))
	previous := ""
	for _, d := range r.Decisions {
		if !ValidDisasterExternalKind(d.Kind) || d.Kind <= previous || d.Count < 1 || d.Count > 1000000 || !hashValue.MatchString(d.SHA256) || d.Resolution != "verified" && d.Resolution != "remediated" && d.Resolution != "no_effect" || len(d.Evidence) < 1 || len(d.Evidence) > 512 || !utf8.ValidString(d.Evidence) || strings.TrimSpace(d.Evidence) != d.Evidence || strings.IndexFunc(d.Evidence, unicode.IsControl) >= 0 {
			return errors.New("外部复核类别、记录数、摘要、处理结论或依据无效；待核对结果不能批准激活")
		}
		previous = d.Kind
		groups = append(groups, d.DisasterExternalGroup)
	}
	if r.InventorySHA256 != DisasterExternalInventorySHA256(id, reconciliation, groups) {
		return errors.New("外部复核未覆盖指定恢复的完整清单")
	}
	return nil
}

func (r DisasterExternalReview) Matches(id, reconciliation string, groups []DisasterExternalGroup) error {
	if err := r.Validate(id, reconciliation); err != nil {
		return err
	}
	if r.InventorySHA256 != DisasterExternalInventorySHA256(id, reconciliation, groups) || len(r.Decisions) != len(groups) {
		return errors.New("外部复核与原数据库中的实际待核对记录不一致")
	}
	for n, group := range groups {
		if r.Decisions[n].DisasterExternalGroup != group {
			return errors.New("外部复核遗漏或替换了源记录")
		}
	}
	return nil
}
