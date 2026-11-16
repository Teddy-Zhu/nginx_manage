package components

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
	"nginxpanel/internal/auth"
)

func TestUpdateChannelPersistsAndRejectsInvalidChanges(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "settings.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err = db.Exec("CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)"); err != nil {
		t.Fatal(err)
	}
	s := Service{DB: db}
	ctx := context.Background()
	got, err := s.GetUpdateChannel(ctx)
	if err != nil || got.Channel != "stable" {
		t.Fatalf("default channel: %+v %v", got, err)
	}
	p := auth.Principal{Scopes: []string{"components.manage", "system.write"}}
	if _, err = s.SetUpdateChannel(ctx, p, UpdateChannel{Channel: "beta"}); err != nil {
		t.Fatal(err)
	}
	other := Service{DB: db}
	got, err = other.GetUpdateChannel(ctx)
	if err != nil || got.Channel != "beta" {
		t.Fatalf("saved channel: %+v %v", got, err)
	}
	if _, err = s.SetUpdateChannel(ctx, p, UpdateChannel{Channel: "main"}); err == nil {
		t.Fatal("invalid channel accepted")
	}
	if _, err = s.SetUpdateChannel(ctx, auth.Principal{Scopes: []string{"components.manage"}}, UpdateChannel{Channel: "stable"}); err == nil {
		t.Fatal("read-only operator changed channel")
	}
	got, err = other.GetUpdateChannel(ctx)
	if err != nil || got.Channel != "beta" {
		t.Fatalf("rejected change modified settings: %+v %v", got, err)
	}
	if _, err = s.SetUpdateChannel(ctx, p, UpdateChannel{Channel: "stable"}); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec("UPDATE settings SET value='corrupted' WHERE key='update_channel'"); err != nil {
		t.Fatal(err)
	}
	if _, err = s.GetUpdateChannel(ctx); err == nil {
		t.Fatal("corrupt channel silently defaulted")
	}
}
