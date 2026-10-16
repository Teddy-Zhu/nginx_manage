package backup

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"nginxpanel/internal/panelrecovery"
	"nginxpanel/internal/secure"
	"nginxpanel/internal/storage"
)

type RestoreActivateMaterialInput struct {
	RestoreReconcileMaterialInput
	Activation    panelrecovery.DisasterActivation `json:"activation"`
	MaintenanceID string                           `json:"maintenance_id"`
}

func activationReport(in RestoreActivateMaterialInput) ([]byte, error) {
	return json.Marshal(struct {
		ReconciliationSHA256       string   `json:"reconciliation_sha256"`
		ReconciliationReportSHA256 string   `json:"reconciliation_report_sha256"`
		PreparedAt                 int64    `json:"prepared_at"`
		Pending                    []string `json:"pending_checks"`
	}{in.Reconciliation.SHA256(), in.Reconciliation.ReportSHA256, in.Activation.PreparedAt, []string{"external_effects_require_review", "automation_disabled", "readiness_required"}})
}

func validateActivateMaterial(id string, in RestoreActivateMaterialInput) error {
	if err := validateReconcileMaterial(id, in.RestoreReconcileMaterialInput); err != nil {
		return err
	}
	a, r := in.Activation, in.Reconciliation
	if a.Schema != 1 || a.OperationID != id || a.IntentSHA256 != r.IntentSHA256 || a.ReconciliationSHA256 != r.SHA256() || !validID.MatchString(a.Epoch) || !validID.MatchString(a.StartID) || !validID.MatchString(in.MaintenanceID) || a.PreparedAt < r.PreparedAt || a.PreparedAt > time.Now().Unix()+300 || a.File.Name != r.File.Name {
		return errors.New("激活助手输入与原对账不一致")
	}
	return nil
}

func activationArgs(query string, in RestoreActivateMaterialInput, report []byte) []any {
	args := reconciliationArgs(query, in.RestoreReconcileMaterialInput, nil)
	// The reconciliation expressions use :report only in restore_barriers;
	// activation replaces that expression with its own named binding.
	for _, v := range []struct {
		name  string
		value any
	}{
		{"activation_report", string(report)}, {"activation_at", in.Activation.PreparedAt}, {"maintenance_id", in.MaintenanceID}, {"activation_epoch", in.Activation.Epoch}, {"activation_audit_id", "restore.activate:" + in.Preparation.OperationID},
	} {
		if strings.Contains(query, ":"+v.name) {
			args = append(args, sql.Named(v.name, v.value))
		}
	}
	return args
}

func activationAdditions() map[string][]map[string]string {
	return map[string][]map[string]string{
		"audit_logs":           {reconciliationAudit(), {"id": ":activation_audit_id", "request_id": ":restore_id", "principal": "'restore:'||:restore_id", "action": "'backup.restore.activate'", "resource_id": ":revision", "outcome": "'prepared'", "created_at": ":activation_at"}},
		"tasks":                {{"id": ":maintenance_id", "kind": "'maintenance.enter'", "resource_id": "'host'", "revision_id": "NULL", "expected_revision": "''", "observed_revision": "''", "submit_started": "0", "agent_accepted": "0", "state": "'running'", "stage": "'held'", "operation_id": ":maintenance_id", "attempts": "0", "lease_until": "NULL", "last_error": "''", "created_at": ":activation_at", "updated_at": ":activation_at", "restore_snapshot": "''"}},
		"maintenance_sessions": {{"task_id": ":maintenance_id", "principal": "'restore:'||:restore_id", "phase": "'held'", "deadline": ":activation_at", "root_requested": "1", "root_epoch": ":activation_epoch", "last_error": "''", "created_at": ":activation_at", "updated_at": ":activation_at", "owner_task_id": "NULL"}},
	}
}

func activationDelta() map[string]map[string]string {
	delta := reconciliationDelta()
	delta["restore_barriers"] = map[string]string{"state": "CASE WHEN id=:restore_id THEN 'completed' ELSE state END", "report": "CASE WHEN id=:restore_id THEN :activation_report ELSE report END"}
	return delta
}

func writeActivatedDatabase(ctx context.Context, db *sql.DB, in RestoreActivateMaterialInput) error {
	if err := writeReconciledDatabase(ctx, db, in.RestoreReconcileMaterialInput); err != nil {
		return err
	}
	report, err := activationReport(in)
	if err != nil {
		return err
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	query := `UPDATE restore_barriers SET state='completed',report=:activation_report WHERE id=:restore_id AND state='reconciling'`
	result, err := tx.ExecContext(ctx, query, activationArgs(query, in, report)...)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil || count != 1 {
		return errors.Join(err, errors.New("激活数据库缺少唯一原恢复屏障"))
	}
	// Only target maintenance coordination is added; source sessions and tasks
	// retain their quarantined history. A UUID collision fails the transaction.
	additions := activationAdditions()
	for _, table := range []string{"tasks", "maintenance_sessions", "audit_logs"} {
		for n, values := range additions[table] {
			if table == "audit_logs" && n == 0 {
				continue
			}
			var columns []string
			for column := range values {
				columns = append(columns, column)
			}
			sort.Strings(columns)
			var expressions []string
			for _, column := range columns {
				expressions = append(expressions, values[column])
			}
			query = `INSERT INTO "` + table + `"("` + strings.Join(columns, `","`) + `") VALUES(` + strings.Join(expressions, ",") + `)`
			if _, err = tx.ExecContext(ctx, query, activationArgs(query, in, report)...); err != nil {
				return err
			}
		}
	}
	return tx.Commit()
}

func PrepareActivatedRestorationDescriptors(ctx context.Context, data, id string, in RestoreActivateMaterialInput, files []*os.File) (out panelrecovery.DisasterActivation, err error) {
	if err = validateActivateMaterial(id, in); err != nil {
		return out, err
	}
	if err = observeReconciledRuntime(ctx, data, in.RestoreReconcileMaterialInput); err != nil {
		return out, err
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, CleanupRestorationWork(data, in.Plan.ID))
		}
	}()
	pub := in.Plan.Preview.Publication
	_, err = verifyRestorationDescriptors(ctx, data, id, in.Preparation, files, pub, func(call context.Context, baseline *sql.DB, vault *secure.Vault) error {
		if e := verifyReconciliationBasis(call, baseline, vault, in.RestoreReconcileMaterialInput); e != nil {
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
		if e = writeActivatedDatabase(call, db, in); e != nil {
			return e
		}
		meta, e := databaseMetadata(call, db)
		if e != nil {
			return e
		}
		r := in.Reconciliation.Database
		if meta.SchemaVersion != r.SchemaVersion || meta.NodeID != r.NodeID || meta.DesiredRevision != r.DesiredRevision || meta.AppliedRevision != r.AppliedRevision || meta.HeadVersion != r.HeadVersion {
			return errors.New("激活改变了原对账数据库身份")
		}
		if e = db.Close(); e != nil {
			return e
		}
		file, e := digestFile(call, path, DatabaseMax)
		if e != nil {
			return e
		}
		report, e := activationReport(in)
		if e != nil {
			return e
		}
		out = in.Activation
		out.File = panelrecovery.File{Name: in.Activation.File.Name, Size: file.Size, SHA256: file.SHA256}
		out.ReportSHA256 = secure.Hash(report)
		return syncDir(filepath.Dir(path))
	})
	if err != nil {
		return out, err
	}
	return out, observeReconciledRuntime(ctx, data, in.RestoreReconcileMaterialInput)
}

func VerifyActivatedRestorationDescriptors(ctx context.Context, data, id string, in RestoreActivateMaterialInput, files []*os.File) (out panelrecovery.DisasterActivationProof, err error) {
	if err = validateActivateMaterial(id, in); err != nil {
		return out, err
	}
	if err = observeReconciledRuntime(ctx, data, in.RestoreReconcileMaterialInput); err != nil {
		return out, err
	}
	a := in.Activation
	_, err = verifyRestorationDescriptors(ctx, data, id, in.Preparation, files, in.Plan.Preview.Publication, func(call context.Context, baseline *sql.DB, vault *secure.Vault) error {
		if e := verifyReconciliationBasis(call, baseline, vault, in.RestoreReconcileMaterialInput); e != nil {
			return e
		}
		f, info, e := openAdoptionCheck(data, in.Plan.ID, os.Getegid(), File{Name: a.File.Name, Size: a.File.Size, SHA256: a.File.SHA256})
		if e != nil {
			return e
		}
		defer f.Close()
		file, e := digestOpenFile(call, f, info, DatabaseMax)
		if e != nil {
			return e
		}
		if file.SHA256 != a.File.SHA256 {
			return errors.New("激活只读投影偏离原固定材料")
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
		report, e := activationReport(in)
		if e != nil {
			return e
		}
		if secure.Hash(report) != a.ReportSHA256 {
			return errors.New("激活报告摘要不一致")
		}
		if e = compareRestorationTables(call, baseline, db, activationDelta(), activationAdditions(), func(query string) []any { return activationArgs(query, in, report) }); e != nil {
			return e
		}
		if !secure.RootFileUnchanged(f, info) {
			return errors.New("激活投影核对期间变化")
		}
		return nil
	})
	if err != nil {
		return out, err
	}
	if err = observeReconciledRuntime(ctx, data, in.RestoreReconcileMaterialInput); err != nil {
		return out, err
	}
	return panelrecovery.DisasterActivationProof{ActivationSHA256: a.SHA256(), VerifiedAt: time.Now().Unix()}, nil
}
