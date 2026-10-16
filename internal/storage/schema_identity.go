package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"

	"github.com/pressly/goose/v3"
	"nginxpanel/internal/secure"
	"nginxpanel/migrations"
)

// SchemaIdentity is bounded even when the input SQLite file is hostile. Restore
// mutation requires the exact embedded schema, including its trusted triggers.
func SchemaIdentity(ctx context.Context, db *sql.DB) (string, error) {
	rows, err := db.QueryContext(ctx, "SELECT substr(type,1,33),substr(name,1,257),substr(tbl_name,1,257),CASE WHEN length(sql)<=262144 THEN sql ELSE NULL END FROM sqlite_schema WHERE sql IS NOT NULL ORDER BY type,name")
	if err != nil {
		return "", err
	}
	defer rows.Close()
	var entries [][4]string
	total := 0
	for rows.Next() {
		var kind, name, table string
		var statement sql.NullString
		if err = rows.Scan(&kind, &name, &table, &statement); err != nil {
			return "", err
		}
		if !statement.Valid || len(kind) > 32 || len(name) > 256 || len(table) > 256 || len(entries) >= 256 {
			return "", errors.New("恢复数据库结构超过限制")
		}
		total += len(statement.String)
		if total > 2<<20 {
			return "", errors.New("恢复数据库结构超过容量限制")
		}
		entries = append(entries, [4]string{kind, name, table, statement.String})
	}
	if err = rows.Err(); err != nil {
		return "", err
	}
	raw, err := json.Marshal(entries)
	if err != nil {
		return "", err
	}
	return secure.Hash(raw), nil
}
func VerifyCurrentSchema(ctx context.Context, db *sql.DB) error {
	actual, err := SchemaIdentity(ctx, db)
	if err != nil {
		return err
	}
	reference, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		return err
	}
	defer reference.Close()
	reference.SetMaxOpenConns(1)
	provider, err := goose.NewProvider(goose.DialectSQLite3, reference, migrations.FS)
	if err != nil {
		return err
	}
	if _, err = provider.Up(ctx); err != nil {
		return err
	}
	expected, err := SchemaIdentity(ctx, reference)
	if err != nil {
		return err
	}
	if actual != expected {
		return errors.New("恢复数据库结构与当前可信迁移不一致，拒绝执行恢复写入")
	}
	return nil
}
