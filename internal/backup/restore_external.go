package backup

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"unicode"
	"unicode/utf8"

	"nginxpanel/internal/agent"
	"nginxpanel/internal/panelrecovery"
	"nginxpanel/internal/secure"
)

type RestoreExternalInput struct {
	AdoptionSHA256       string `json:"adoption_sha256"`
	PlanID               string `json:"plan_id"`
	PlanSHA256           string `json:"plan_sha256"`
	ReconciliationSHA256 string `json:"reconciliation_sha256"`
	Kind                 string `json:"kind"`
	After                string `json:"after"`
}

type RestoreExternalMaterialInput struct {
	RestoreReconcileMaterialInput
	Kind  string `json:"kind"`
	After string `json:"after"`
}

type RestoreExternalItem struct {
	Kind      string `json:"kind"`
	ID        string `json:"id"`
	RelatedID string `json:"related_id"`
	State     string `json:"state"`
	Stage     string `json:"stage"`
	SHA256    string `json:"sha256"`
}

type RestoreExternalInventory struct {
	OperationID          string                                `json:"operation_id"`
	ReconciliationSHA256 string                                `json:"reconciliation_sha256"`
	InventorySHA256      string                                `json:"inventory_sha256"`
	Groups               []panelrecovery.DisasterExternalGroup `json:"groups"`
	Kind                 string                                `json:"kind"`
	After                string                                `json:"after"`
	Items                []RestoreExternalItem                 `json:"items"`
	NextAfter            string                                `json:"next_after"`
}

func externalPageValid(kind, after string) bool {
	return (kind == "" && after == "" || panelrecovery.ValidDisasterExternalKind(kind)) && len(after) <= 128 && utf8.ValidString(after) && strings.IndexFunc(after, unicode.IsControl) < 0
}

// QueryRestorationExternal reads only the already authenticated, unpublished
// source projection. It does not contact a CA, provider or another node.
func QueryRestorationExternal(ctx context.Context, data, id string, in RestoreExternalInput) (out RestoreExternalInventory, err error) {
	if os.Geteuid() != 0 || !validID.MatchString(id) || !validHash.MatchString(in.AdoptionSHA256) || !validID.MatchString(in.PlanID) || !validHash.MatchString(in.PlanSHA256) || !validHash.MatchString(in.ReconciliationSHA256) || !externalPageValid(in.Kind, in.After) {
		return out, errors.New("外部结果清单须由本机 root 指定原恢复批准、对账摘要及有效分页")
	}
	unlock, _, err := lockAdoptionStore(data, false)
	if err != nil {
		return out, err
	}
	defer unlock()
	i, err := panelrecovery.ReadDisasterIntent(data, id)
	if err != nil {
		return out, err
	}
	if i.AdoptionSHA256 != in.AdoptionSHA256 || i.PlanID != in.PlanID || i.PlanSHA256 != in.PlanSHA256 {
		return out, errors.New("外部结果清单指定了其他恢复批准")
	}
	r, err := panelrecovery.ReadDisasterReconciliation(i)
	if err != nil {
		return out, err
	}
	if r.SHA256() != in.ReconciliationSHA256 {
		return out, errors.New("外部结果清单指定了其他对账批准")
	}
	if _, err = panelrecovery.ReadDisasterReconciliationProof(i, r); err != nil {
		return out, err
	}
	status, err := agent.DisasterRuntime(data, id)
	if err != nil {
		return out, err
	}
	if status.Restore.Stage != "data_reconciled" || status.Restore.State != "recovery_required" {
		return out, errors.New("外部结果清单须在数据对账完成且激活提交之前读取")
	}
	a, err := readAdoptionStatus(ctx, data, id)
	if err != nil {
		return out, err
	}
	if a.State != "adopted" || a.Adoption == nil {
		return out, errors.New("外部结果清单缺少原固定接入")
	}
	p, err := readRestorePlan(data, i.PlanID)
	if err != nil {
		return out, err
	}
	if err = matchRestorePlan(p, *a.Adoption); err != nil {
		return out, err
	}
	if p.SHA256 != i.PlanSHA256 || a.Adoption.SHA256 != i.AdoptionSHA256 || p.Preview.Publication == nil {
		return out, errors.New("外部结果清单的原计划或接入发生变化")
	}
	input := RestoreExternalMaterialInput{RestoreReconcileMaterialInput: RestoreReconcileMaterialInput{Preparation: a.Adoption.Intent.Preparation, Plan: p, Reconciliation: r}, Kind: in.Kind, After: in.After}
	pub := p.Preview.Publication
	err = callRestorationMaterialHelper(ctx, data, id, filepath.Join(data, "agent", "disaster-recovery", id), a.Adoption.Intent, "backup-restore-external-data", input, &out, &pub.File, restorePublicationPath(data, p.ID), "")
	if err != nil {
		return out, err
	}
	if out.OperationID != id || out.ReconciliationSHA256 != r.SHA256() || out.InventorySHA256 != panelrecovery.DisasterExternalInventorySHA256(id, r.SHA256(), out.Groups) || out.Kind != in.Kind || out.After != in.After || len(out.Items) > 64 || len(out.Groups) > 10 {
		return out, errors.New("外部结果助手未返回原恢复的有界完整清单")
	}
	return out, nil
}

func ReadRestorationExternalDescriptors(ctx context.Context, data, id string, in RestoreExternalMaterialInput, files []*os.File) (out RestoreExternalInventory, err error) {
	if err = validateReconcileMaterial(id, in.RestoreReconcileMaterialInput); err != nil {
		return out, err
	}
	if !externalPageValid(in.Kind, in.After) {
		return out, errors.New("外部结果分页无效")
	}
	_, err = verifyRestorationDescriptors(ctx, data, id, in.Preparation, files, in.Plan.Preview.Publication, func(call context.Context, db *sql.DB, vault *secure.Vault) error {
		if e := verifyReconciliationBasis(call, db, vault, in.RestoreReconcileMaterialInput); e != nil {
			return e
		}
		var e error
		out, e = restorationExternalInventory(call, db, in)
		return e
	})
	return out, err
}

// The source publication precedes reconciliation, so these predicates retain
// the original in-flight states. Full rows participate in each digest; only
// bounded identifiers/states and opaque hashes leave the helper.
func restorationExternalQueries() []struct{ kind, query string } {
	return []struct{ kind, query string }{
		{"acme_accounts", `SELECT id,'',state,'',a.* FROM acme_accounts a WHERE state IN ('pending','registering') ORDER BY id`},
		{"acme_orders", `SELECT id,profile_id,'pending',http01_state,a.* FROM acme_orders a WHERE terminal=0 OR http01_state IN ('unknown','active') OR EXISTS(SELECT 1 FROM acme_dns_records d WHERE d.order_id=a.id AND d.state<>'cleaned') ORDER BY id`},
		{"acme_profiles", `SELECT id,current_order_id,state,'',a.* FROM acme_profiles a WHERE state IN ('issuing','recovery_required') ORDER BY id`},
		{"dns_records", `SELECT id,order_id,state,'',a.* FROM acme_dns_records a WHERE state<>'cleaned' ORDER BY id`},
		{"migration_plans", `SELECT id,'',state,'',a.* FROM migration_plans a WHERE state IN ('applying','recovery_required') ORDER BY id`},
		{"migration_pushes", `SELECT task_id,'',CASE remote_started WHEN 1 THEN 'submission_started' ELSE 'not_sent' END,'',a.* FROM migration_pushes a WHERE remote_started=1 AND EXISTS(SELECT 1 FROM tasks t WHERE t.id=a.task_id AND t.state NOT IN ('succeeded','rolled_back')) OR EXISTS(SELECT 1 FROM restore_quarantined_tasks q WHERE q.task_id=a.task_id AND q.restore_id=?) ORDER BY task_id`},
		{"node_grants", `SELECT id,credential_id,revocation,'',a.* FROM nodes a WHERE revocation<>'revoked' ORDER BY id`},
		{"notification_deliveries", `SELECT id,event_id,state,'',a.* FROM notification_deliveries a WHERE state='cancelled' AND attempts>0 AND completed_at=? AND last_error='源通知投递已隔离，不在恢复目标重放' ORDER BY id`},
		{"pairing_grants", `SELECT id,pairing_id,revocation,stage,a.* FROM node_pairing_jobs a WHERE revocation<>'revoked' ORDER BY id`},
		{"source_tasks", `SELECT t.id,t.resource_id,q.original_state,q.original_stage,t.*,q.* FROM tasks t JOIN restore_quarantined_tasks q ON q.task_id=t.id WHERE q.restore_id=? ORDER BY t.id`},
	}
}

func restorationExternalInventory(ctx context.Context, db *sql.DB, in RestoreExternalMaterialInput) (out RestoreExternalInventory, err error) {
	out = RestoreExternalInventory{OperationID: in.Preparation.OperationID, ReconciliationSHA256: in.Reconciliation.SHA256(), Groups: []panelrecovery.DisasterExternalGroup{}, Kind: in.Kind, After: in.After, Items: []RestoreExternalItem{}}
	var total int64
	for _, source := range restorationExternalQueries() {
		var args []any
		if strings.Contains(source.query, "?") {
			if source.kind == "notification_deliveries" {
				args = []any{in.Preparation.PreparedAt}
			} else {
				args = []any{in.Preparation.OperationID}
			}
		}
		rows, e := db.QueryContext(ctx, source.query, args...)
		if e != nil {
			return out, e
		}
		group, page, next, e := readExternalRows(ctx, rows, source.kind, in.Kind, in.After, &total)
		closeErr := rows.Close()
		if e != nil || closeErr != nil {
			return out, errors.Join(e, closeErr)
		}
		if group.Count > 0 {
			out.Groups = append(out.Groups, group)
		}
		if source.kind == in.Kind {
			out.Items, out.NextAfter = page, next
		}
	}
	out.InventorySHA256 = panelrecovery.DisasterExternalInventorySHA256(out.OperationID, out.ReconciliationSHA256, out.Groups)
	return out, nil
}

func verifyRestorationExternalReview(ctx context.Context, db *sql.DB, in RestoreActivateMaterialInput) error {
	actual, err := restorationExternalInventory(ctx, db, RestoreExternalMaterialInput{RestoreReconcileMaterialInput: in.RestoreReconcileMaterialInput})
	if err != nil {
		return err
	}
	return in.Activation.ExternalReview.Matches(in.Preparation.OperationID, in.Reconciliation.SHA256(), actual.Groups)
}

func readExternalRows(ctx context.Context, rows *sql.Rows, kind, selected, after string, total *int64) (group panelrecovery.DisasterExternalGroup, page []RestoreExternalItem, next string, err error) {
	group.Kind, page = kind, []RestoreExternalItem{}
	columns, err := rows.Columns()
	if err != nil {
		return group, page, next, err
	}
	if len(columns) < 5 || len(columns) > 68 {
		return group, page, next, errors.New("外部结果源列数超过限制")
	}
	h := sha256.New()
	previous := ""
	for rows.Next() {
		if err = ctx.Err(); err != nil {
			return group, page, next, err
		}
		values, pointers := make([]any, len(columns)), make([]any, len(columns))
		for n := range values {
			pointers[n] = &values[n]
		}
		if err = rows.Scan(pointers...); err != nil {
			return group, page, next, err
		}
		public := [4]string{}
		for n := range public {
			value, ok := values[n].(string)
			if !ok || len(value) > 128 || !utf8.ValidString(value) || strings.IndexFunc(value, unicode.IsControl) >= 0 {
				return group, page, next, errors.New("外部结果标识或状态无效")
			}
			public[n] = value
		}
		if public[0] == "" || public[0] <= previous {
			return group, page, next, errors.New("外部结果标识重复或顺序无效")
		}
		previous = public[0]
		rowHash := sha256.New()
		for n, value := range values {
			var raw []byte
			switch v := value.(type) {
			case []byte:
				raw = v
			case string:
				raw = []byte(v)
			default:
				raw, err = json.Marshal(v)
				if err != nil {
					return group, page, next, err
				}
			}
			*total += int64(len(raw))
			if len(raw) > 16<<20 || *total > 2<<30 {
				return group, page, next, errors.New("外部结果源材料超过预算")
			}
			sum := sha256.Sum256(raw)
			fmt.Fprintf(rowHash, "%d:%s:%v:%d:%x\n", n, columns[n], reflect.TypeOf(value), len(raw), sum)
		}
		digest := hex.EncodeToString(rowHash.Sum(nil))
		fmt.Fprintf(h, "%s\n", digest)
		group.Count++
		if group.Count > 1000000 {
			return group, page, next, errors.New("外部结果源记录数超过预算")
		}
		if kind == selected && public[0] > after {
			if len(page) < 64 {
				page = append(page, RestoreExternalItem{kind, public[0], public[1], public[2], public[3], digest})
			} else {
				next = page[len(page)-1].ID
			}
		}
	}
	group.SHA256 = hex.EncodeToString(h.Sum(nil))
	return group, page, next, rows.Err()
}
