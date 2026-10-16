package backup

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"time"

	"nginxpanel/internal/agent"
	"nginxpanel/internal/nginxconfig"
	"nginxpanel/internal/panelrecovery"
	"nginxpanel/internal/secure"
	"nginxpanel/internal/storage"
)

type RestoreReconcileMaterialInput struct {
	Preparation    Preparation                          `json:"preparation"`
	Plan           RestorePlan                          `json:"plan"`
	Reconciliation panelrecovery.DisasterReconciliation `json:"reconciliation"`
}

func reconciliationReport(in RestoreReconcileMaterialInput) ([]byte, error) {
	return json.Marshal(struct {
		Isolation    RestoreIsolation             `json:"isolation"`
		Disabled     []string                     `json:"disabled_modules"`
		Review       panelrecovery.DisasterReview `json:"review"`
		RevisionID   string                       `json:"revision_id"`
		ReconciledAt int64                        `json:"reconciled_at"`
		Pending      []string                     `json:"pending_checks"`
	}{in.Preparation.Isolation, in.Preparation.DisabledModules, in.Reconciliation.Review, in.Plan.ID, in.Reconciliation.PreparedAt, []string{"external_effects_require_review", "automation_disabled", "activation_required"}})
}

func validateReconcileMaterial(id string, in RestoreReconcileMaterialInput) error {
	if os.Geteuid() == 0 || id != in.Preparation.OperationID || id != in.Plan.OperationID || id != in.Reconciliation.OperationID {
		return errors.New("恢复对账助手身份无效")
	}
	if err := in.Preparation.Validate(); err != nil {
		return err
	}
	if err := in.Plan.validate(); err != nil {
		return err
	}
	if err := in.Reconciliation.Review.Validate(); err != nil {
		return err
	}
	p, r := in.Plan, in.Reconciliation
	hash, err := preparationHash(in.Preparation)
	if err != nil {
		return err
	}
	if !p.Preview.CanInstall || p.Preview.Publication == nil || p.PreparationSHA256 != hash || p.SHA256 != r.PlanSHA256 || !validHash.MatchString(r.IntentSHA256) || !validID.MatchString(r.Epoch) || r.PreparedAt < p.CreatedAt || r.PreparedAt > time.Now().Unix()+300 || r.Schema != 1 || r.File.Name != "app/panel.db" {
		return errors.New("恢复对账助手输入与原计划不一致")
	}
	return nil
}

func observeReconciledRuntime(ctx context.Context, data string, in RestoreReconcileMaterialInput) error {
	c := agent.NewClient(filepath.Join(data, "run", "agent", "agent.sock"))
	r, err := c.Operation(ctx, in.Plan.ID)
	if err != nil {
		return err
	}
	if r.Kind != "nginx.apply" || r.DisasterRestoreID != in.Preparation.OperationID || r.RequestHash != in.Plan.Preview.Publication.NginxRequest.SHA256 || r.State != "succeeded" || r.Stage != "runtime_confirmed" || r.AfterRevision != in.Plan.ID || r.AfterDir != in.Plan.ID || r.ObservedRevision != in.Plan.ID {
		return errors.New("对账前 Nginx 子操作未确认原恢复计划")
	}
	s, err := c.NginxState(ctx)
	if err != nil {
		return err
	}
	if !s.Available || !s.Running || !s.Integrity || s.ExternalChange || s.RevisionID != in.Plan.ID || s.DeploymentID != in.Plan.ID {
		return errors.New("对账前 Nginx 实际运行偏离原计划")
	}
	return nil
}

// ReconcileRestorationDescriptors works on a separate unpublished copy only.
// It never opens the installed database or clears either startup barrier.
func ReconcileRestorationDescriptors(ctx context.Context, data, id string, in RestoreReconcileMaterialInput, files []*os.File) (out panelrecovery.DisasterReconciliation, err error) {
	if err = validateReconcileMaterial(id, in); err != nil {
		return out, err
	}
	if err = observeReconciledRuntime(ctx, data, in); err != nil {
		return out, err
	}
	pub := in.Plan.Preview.Publication
	defer func() {
		if err != nil {
			err = errors.Join(err, CleanupRestorationWork(data, in.Plan.ID))
		}
	}()
	_, err = verifyRestorationDescriptors(ctx, data, id, in.Preparation, files, pub, func(call context.Context, baseline *sql.DB, vault *secure.Vault) error {
		if e := verifyReconciliationBasis(call, baseline, vault, in); e != nil {
			return e
		}
		path, e := copyRestorationDatabase(call, data, in.Plan.ID, files[0], pub.File)
		if e != nil {
			return e
		}
		db, e := writableRestoreDatabase(call, path)
		if e != nil {
			return e
		}
		defer db.Close()
		if e = writeReconciledDatabase(call, db, in); e != nil {
			return e
		}
		meta, e := databaseMetadata(call, db)
		if e != nil {
			return e
		}
		if e = db.Close(); e != nil {
			return e
		}
		file, e := digestFile(call, path, DatabaseMax)
		if e != nil {
			return e
		}
		report, e := reconciliationReport(in)
		if e != nil {
			return e
		}
		out = in.Reconciliation
		out.File = panelrecovery.File{Name: in.Reconciliation.File.Name, Size: file.Size, SHA256: file.SHA256}
		out.Database = panelrecovery.Database{SchemaVersion: meta.SchemaVersion, NodeID: meta.NodeID, DesiredRevision: meta.DesiredRevision, AppliedRevision: meta.AppliedRevision, HeadVersion: meta.HeadVersion}
		out.ReportSHA256 = secure.Hash(report)
		return syncDir(filepath.Dir(path))
	})
	if err != nil {
		return out, err
	}
	return out, observeReconciledRuntime(ctx, data, in)
}

func verifyReconciliationBasis(ctx context.Context, db *sql.DB, vault *secure.Vault, in RestoreReconcileMaterialInput) error {
	files, err := restoreRevisionFiles(ctx, db, vault, in.Plan.ID)
	if err != nil {
		return err
	}
	hash, err := adoptionValueHash(files)
	if err != nil || hash != in.Plan.Preview.CandidateSHA256 {
		return errors.New("对账源配置偏离原计划")
	}
	parsed, err := nginxconfig.Parse(files, in.Plan.Preview.Policy)
	if err != nil || len(parsed.Tree.Diagnostics) != 0 {
		return errors.New("对账源配置无法按原策略解析")
	}
	if err = verifyPublicationProjections(ctx, db, vault, in.Plan.ID, parsed.Tree.Resources); err != nil {
		return err
	}
	return verifyPublicationReferences(ctx, db, in.Preparation, *in.Plan.Preview.Publication, parsed, hash, in.Plan.Preview.PendingChecks)
}

const sourceTaskAbandoned = "源任务已按恢复批准终止，执行结果未推断；外部副作用须另行核对，禁止重放"

// These expressions define the complete allowed delta. The independent
// read-only verifier compares every row of every table against this projection.
func reconciliationDelta() map[string]map[string]string {
	conditional := func(condition, value, original string) string {
		return "CASE WHEN " + condition + " THEN " + value + " ELSE " + original + " END"
	}
	tasks := "state='recovery_required' AND stage='restore_isolated'"
	accounts := "state IN ('pending','registering')"
	profiles := "state IN ('issuing','recovery_required')"
	plans := "state IN ('applying','recovery_required')"
	return map[string]map[string]string{
		"config_head":      {"applied_revision": ":revision"},
		"restore_barriers": {"state": conditional("id=:restore_id", "'reconciling'", "state"), "report": conditional("id=:restore_id", ":report", "report")},
		"tasks":            {"state": conditional(tasks, "'cancelled'", "state"), "stage": conditional(tasks, "'restore_abandoned'", "stage"), "last_error": conditional(tasks, ":task_error", "last_error"), "lease_until": conditional(tasks, "NULL", "lease_until"), "updated_at": conditional(tasks, ":at", "updated_at")},
		"acme_accounts":    {"state": conditional(accounts, "'failed'", "state"), "last_error": conditional(accounts, "'源账户注册已隔离；CA 结果须另行核对，未重新注册'", "last_error"), "updated_at": conditional(accounts, ":at", "updated_at")},
		"acme_profiles":    {"state": conditional(profiles, "'failed'", "state"), "last_error": conditional(profiles, "'源签发流程已终止；CA 订单及挑战值保留待核对'", "last_error"), "updated_at": conditional(profiles, ":at", "updated_at")},
		"migration_plans":  {"state": conditional(plans, "'failed'", "state"), "last_error": conditional(plans, "'源迁移流程已终止；远端结果须另行核对，未补偿或重放'", "last_error"), "updated_at": conditional(plans, ":at", "updated_at")},
	}
}

func reconciliationArgs(query string, in RestoreReconcileMaterialInput, report []byte) []any {
	var args []any
	for _, p := range []struct {
		name  string
		value any
	}{{"restore_id", in.Preparation.OperationID}, {"revision", in.Plan.ID}, {"at", in.Reconciliation.PreparedAt}, {"report", string(report)}, {"task_error", sourceTaskAbandoned}, {"audit_id", "restore.reconcile:" + in.Preparation.OperationID}} {
		if strings.Contains(query, ":"+p.name) {
			args = append(args, sql.Named(p.name, p.value))
		}
	}
	return args
}

func writeReconciledDatabase(ctx context.Context, db *sql.DB, in RestoreReconcileMaterialInput) error {
	report, err := reconciliationReport(in)
	if err != nil {
		return err
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for table, columns := range reconciliationDelta() {
		var assignments []string
		for name, expression := range columns {
			assignments = append(assignments, `"`+name+`"=`+expression)
		}
		sort.Strings(assignments)
		query := `UPDATE "` + table + `" SET ` + strings.Join(assignments, ",")
		if _, err = tx.ExecContext(ctx, query, reconciliationArgs(query, in, report)...); err != nil {
			return err
		}
	}
	query := `INSERT INTO audit_logs(id,request_id,principal,action,resource_id,outcome,created_at) VALUES(:audit_id,:restore_id,'restore:'||:restore_id,'backup.restore.reconcile',:revision,'isolated',:at)`
	if _, err = tx.ExecContext(ctx, query, reconciliationArgs(query, in, report)...); err != nil {
		return err
	}
	return tx.Commit()
}

var reconciliationIdentifier = regexp.MustCompile(`^[a-z_][a-z0-9_]{0,63}$`)

// VerifyReconciledRestorationDescriptors opens root-owned immutable projections.
// SQL runs as the panel account, including the exhaustive comparison to the
// approved source; unchanged secrets, source history and audit rows must match.
func VerifyReconciledRestorationDescriptors(ctx context.Context, data, id string, in RestoreReconcileMaterialInput, files []*os.File) (out panelrecovery.DisasterReconciliationProof, err error) {
	if err = validateReconcileMaterial(id, in); err != nil {
		return out, err
	}
	if err = observeReconciledRuntime(ctx, data, in); err != nil {
		return out, err
	}
	r := in.Reconciliation
	_, err = verifyRestorationDescriptors(ctx, data, id, in.Preparation, files, in.Plan.Preview.Publication, func(call context.Context, baseline *sql.DB, vault *secure.Vault) error {
		if e := verifyReconciliationBasis(call, baseline, vault, in); e != nil {
			return e
		}
		f, info, e := openAdoptionCheck(data, in.Plan.ID, os.Getegid(), File{Name: r.File.Name, Size: r.File.Size, SHA256: r.File.SHA256})
		if e != nil {
			return e
		}
		defer f.Close()
		file, e := digestOpenFile(call, f, info, DatabaseMax)
		if e != nil {
			return e
		}
		if file.SHA256 != r.File.SHA256 {
			return errors.New("对账只读投影偏离原固定材料")
		}
		dsn := (&url.URL{Scheme: "file", Path: f.Name()}).String() + "?mode=ro&immutable=1&_pragma=trusted_schema(OFF)&_pragma=query_only(ON)&_pragma=cache_size(-16384)"
		db, e := sql.Open("sqlite", dsn)
		if e != nil {
			return e
		}
		defer db.Close()
		db.SetMaxOpenConns(1)
		if e = storage.VerifyCurrentSchema(call, db); e != nil {
			return e
		}
		meta, e := databaseMetadata(call, db)
		if e != nil {
			return e
		}
		if meta.NodeID != r.Database.NodeID || meta.SchemaVersion != r.Database.SchemaVersion || meta.HeadVersion != r.Database.HeadVersion || meta.DesiredRevision != r.Database.DesiredRevision || meta.AppliedRevision != r.Database.AppliedRevision {
			return errors.New("对账数据库身份与原批准不一致")
		}
		if e = compareReconciledTables(call, baseline, db, in); e != nil {
			return e
		}
		if !secure.RootFileUnchanged(f, info) {
			return errors.New("对账数据库投影核对期间变化")
		}
		return nil
	})
	if err != nil {
		return out, err
	}
	if err = observeReconciledRuntime(ctx, data, in); err != nil {
		return out, err
	}
	return panelrecovery.DisasterReconciliationProof{ReconciliationSHA256: r.SHA256(), VerifiedAt: time.Now().Unix()}, nil
}

func compareReconciledTables(ctx context.Context, baseline, db *sql.DB, in RestoreReconcileMaterialInput) error {
	report, err := reconciliationReport(in)
	if err != nil {
		return err
	}
	if secure.Hash(report) != in.Reconciliation.ReportSHA256 {
		return errors.New("对账报告摘要不一致")
	}
	return compareRestorationTables(ctx, baseline, db, reconciliationDelta(), map[string][]map[string]string{"audit_logs": {reconciliationAudit()}}, func(query string) []any { return reconciliationArgs(query, in, report) })
}

func reconciliationAudit() map[string]string {
	return map[string]string{"id": ":audit_id", "request_id": ":restore_id", "principal": "'restore:'||:restore_id", "action": "'backup.restore.reconcile'", "resource_id": ":revision", "outcome": "'isolated'", "created_at": ":at"}
}

func compareRestorationTables(ctx context.Context, baseline, db *sql.DB, delta map[string]map[string]string, additions map[string][]map[string]string, args func(string) []any) error {
	rows, err := db.QueryContext(ctx, "SELECT name FROM main.sqlite_schema WHERE type='table' ORDER BY name LIMIT 129")
	if err != nil {
		return err
	}
	var tables []string
	for rows.Next() {
		var name string
		if err = rows.Scan(&name); err != nil {
			break
		}
		if !reconciliationIdentifier.MatchString(name) {
			err = errors.New("恢复核对表标识无效")
			break
		}
		tables = append(tables, name)
	}
	err = errors.Join(err, rows.Err())
	rows.Close()
	if err != nil {
		return err
	}
	if len(tables) > 128 {
		return errors.New("恢复核对表数量超过限制")
	}
	for _, table := range tables {
		rows, err = db.QueryContext(ctx, `SELECT name,pk FROM pragma_table_xinfo(?) ORDER BY cid LIMIT 65`, table)
		if err != nil {
			return err
		}
		var columns, expected []string
		keys := map[int]string{}
		for rows.Next() {
			var name string
			var key int
			if err = rows.Scan(&name, &key); err != nil {
				break
			}
			if !reconciliationIdentifier.MatchString(name) {
				err = errors.New("恢复核对字段标识无效")
				break
			}
			column := `"` + name + `"`
			columns = append(columns, column)
			if key > 0 {
				keys[key] = column
			}
			if expression, ok := delta[table][name]; ok {
				expected = append(expected, expression)
			} else {
				expected = append(expected, column)
			}
		}
		err = errors.Join(err, rows.Err())
		rows.Close()
		if err != nil {
			return err
		}
		if len(columns) == 0 || len(columns) > 64 {
			return errors.New("恢复核对字段数量无效")
		}
		var order []string
		for position := 1; position <= len(keys); position++ {
			column, ok := keys[position]
			if !ok {
				return errors.New("恢复核对主键顺序无效")
			}
			order = append(order, column)
		}
		if table == "sqlite_sequence" {
			order = []string{`"name"`}
		}
		if len(order) == 0 {
			return fmt.Errorf("恢复核对表缺少确定主键：%s", table)
		}
		projection := `SELECT ` + strings.Join(expected, ",") + ` FROM main."` + table + `"`
		for _, values := range additions[table] {
			var audit []string
			for _, column := range columns {
				value, ok := values[strings.Trim(column, `"`)]
				if !ok {
					return errors.New("恢复核对新增记录字段未定义")
				}
				audit = append(audit, value)
			}
			projection += " UNION ALL SELECT " + strings.Join(audit, ",")
		}
		query := `WITH expected(` + strings.Join(columns, ",") + `) AS (` + projection + `) SELECT * FROM expected ORDER BY ` + strings.Join(order, ",")
		expectedRows, e := baseline.QueryContext(ctx, query, args(query)...)
		if e != nil {
			return e
		}
		actualRows, e := db.QueryContext(ctx, `SELECT `+strings.Join(columns, ",")+` FROM main."`+table+`" ORDER BY `+strings.Join(order, ","))
		if e != nil {
			expectedRows.Close()
			return e
		}
		e = compareReconciledRows(expectedRows, actualRows, len(columns))
		e = errors.Join(e, expectedRows.Close(), actualRows.Close())
		if e != nil {
			return fmt.Errorf("恢复对账表 %s 核对失败：%w", table, e)
		}
	}
	return nil
}

func compareReconciledRows(expected, actual *sql.Rows, width int) error {
	left, right := make([]any, width), make([]any, width)
	leftScan, rightScan := make([]any, width), make([]any, width)
	for index := range left {
		leftScan[index] = &left[index]
		rightScan[index] = &right[index]
	}
	for {
		hasLeft, hasRight := expected.Next(), actual.Next()
		if err := errors.Join(expected.Err(), actual.Err()); err != nil {
			return err
		}
		if hasLeft != hasRight {
			return errors.New("记录数量与批准变更不一致")
		}
		if !hasLeft {
			return nil
		}
		if err := expected.Scan(leftScan...); err != nil {
			return err
		}
		if err := actual.Scan(rightScan...); err != nil {
			return err
		}
		if !reflect.DeepEqual(left, right) {
			return errors.New("存在未批准的记录差异")
		}
	}
}
