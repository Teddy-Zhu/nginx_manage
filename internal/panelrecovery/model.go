// Package panelrecovery holds encrypted, local maintenance snapshots. It is
// separate from portable configuration exports and offline disaster recovery.
package panelrecovery

import (
	"encoding/json"
	"errors"
	"io"
	"regexp"

	"nginxpanel/internal/panelruntime"
)

const (
	Schema      = 1
	DatabaseMax = int64(512 << 20)
	ArchiveMax  = DatabaseMax + (2 << 20)
	StoreMax    = int64(2 << 30)
	SnapshotMax = 8
	Lifetime    = int64(24 * 60 * 60)
	manifestMax = 8 << 10
	materialMax = int64(64 << 10)
)

var idValue = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
var hashValue = regexp.MustCompile(`^[0-9a-f]{64}$`)

type Input struct {
	DataDir       string `json:"data_dir"`
	OperationID   string `json:"operation_id"`
	MaintenanceID string `json:"maintenance_id"`
	Epoch         string `json:"epoch"`
	UID           int    `json:"uid"`
	GID           int    `json:"gid"`
}

type Database struct {
	SchemaVersion   int64  `json:"schema_version"`
	NodeID          string `json:"node_id"`
	DesiredRevision string `json:"desired_revision"`
	AppliedRevision string `json:"applied_revision"`
	HeadVersion     int64  `json:"head_version"`
}

type File struct {
	Name   string `json:"name"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

type Manifest struct {
	Schema              int      `json:"schema"`
	DataDir             string   `json:"data_dir"`
	OperationID         string   `json:"operation_id"`
	MaintenanceID       string   `json:"maintenance_id"`
	Epoch               string   `json:"epoch"`
	UID                 int      `json:"uid"`
	GID                 int      `json:"gid"`
	CreatedAt           int64    `json:"created_at"`
	ExpiresAt           int64    `json:"expires_at"`
	CaptureBinarySHA256 string   `json:"capture_binary_sha256"`
	Database            Database `json:"database"`
	Files               []File   `json:"files"`
}

type Receipt struct {
	ManifestSHA256 string   `json:"manifest_sha256"`
	ArchiveSHA256  string   `json:"archive_sha256"`
	ArchiveSize    int64    `json:"archive_size"`
	KeyID          string   `json:"key_id"`
	Manifest       Manifest `json:"manifest"`
}

type Result struct {
	State   string  `json:"state"`
	Receipt Receipt `json:"receipt"`
	Expired bool    `json:"expired"`
}

func Validate(in Input) error {
	if !idValue.MatchString(in.OperationID) || !idValue.MatchString(in.MaintenanceID) || !idValue.MatchString(in.Epoch) || in.UID <= 0 || in.GID <= 0 || uint64(in.UID) > uint64(^uint32(0)) || uint64(in.GID) > uint64(^uint32(0)) {
		return errors.New("本机恢复快照的操作、维护或账户身份无效")
	}
	_, err := panelruntime.Root(in.DataDir)
	return err
}

func decode(r io.Reader, out any) error {
	d := json.NewDecoder(r)
	d.DisallowUnknownFields()
	if err := d.Decode(out); err != nil {
		return err
	}
	if d.Decode(new(any)) != io.EOF {
		return errors.New("本机恢复记录包含额外数据")
	}
	return nil
}

func (d Database) valid() bool {
	return d.SchemaVersion > 0 && idValue.MatchString(d.NodeID) && (d.DesiredRevision == "" || idValue.MatchString(d.DesiredRevision)) && (d.AppliedRevision == "" || idValue.MatchString(d.AppliedRevision)) && d.HeadVersion >= 0
}

var resources = []struct {
	name  string
	limit int64
}{
	{"app/panel.db", DatabaseMax},
	{"secrets/master.key", 32},
	{"secrets/node-tls/cert.pem", materialMax},
	{"secrets/node-tls/key.pem", materialMax},
}
