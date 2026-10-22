package auditlog_test

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"nginxpanel/internal/auditlog"
	"nginxpanel/internal/secure"
	"nginxpanel/internal/storage"
)

func TestRecoveryEventsRemainReadable(t *testing.T) {
	db, err := storage.Open(t.Context(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	operationID := secure.ID()
	ids := []string{"restore.reconcile:" + operationID, "restore.activate:" + operationID, secure.ID()}
	at := time.Now().Unix() - 5
	for _, id := range ids {
		_, err = db.ExecContext(t.Context(), "INSERT INTO audit_logs(id,request_id,principal,action,resource_id,outcome,created_at) VALUES(?,?,?,?,?,?,?)", id, operationID, "local-root", "backup.restore", "revision", "succeeded", at)
		if err != nil {
			t.Fatal(err)
		}
	}
	service := auditlog.New(db, secure.ID())
	filter := auditlog.Filter{From: at - 1, Until: at + 1}
	query := auditlog.Query{Filter: filter, Limit: 1}
	for index, id := range ids {
		page, err := service.Query(t.Context(), query)
		if err != nil {
			t.Fatal(err)
		}
		if len(page.Rows) != 1 || page.Rows[0].ID != id {
			t.Fatalf("page %d lost or reordered a recovery event: %+v", index, page.Rows)
		}
		if more := index < len(ids)-1; page.More != more || (page.Cursor != "") != more {
			t.Fatalf("page %d has an incorrect continuation", index)
		}
		query.Cursor = page.Cursor
	}
	export, err := service.Export(t.Context(), filter)
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(bytes.TrimSuffix(export.Bytes, []byte("\n")), []byte("\n"))
	if export.Manifest.Count != len(ids) || len(lines) != len(ids)+1 {
		t.Fatal("export omitted recovery events")
	}
	for index, line := range lines[1:] {
		var entry struct {
			Type string       `json:"type"`
			Row  auditlog.Row `json:"row"`
		}
		if err := json.Unmarshal(line, &entry); err != nil {
			t.Fatal(err)
		}
		if entry.Type != "entry" || entry.Row.ID != ids[index] {
			t.Fatalf("export entry %d lost the original event identity", index)
		}
	}
}
