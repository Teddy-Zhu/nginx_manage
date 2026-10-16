package storage

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"

	"nginxpanel/internal/secure"
)

// ServiceHold survives both serve and launcher restarts. Only the matching
// root maintenance transaction may remove it; ordinary startup checks presence.
type ServiceHold struct {
	Schema        int    `json:"schema"`
	OperationID   string `json:"operation_id"`
	MaintenanceID string `json:"maintenance_id"`
	RequestSHA256 string `json:"request_sha256"`
	ReleaseID     string `json:"release_id"`
	BindingSHA256 string `json:"binding_sha256"`
}

func serviceHoldPath(data string) string {
	return filepath.Join(data, "run", "panel-service-hold.json")
}
func (h ServiceHold) valid() bool {
	return h.Schema == 1 && writerID.MatchString(h.OperationID) && writerID.MatchString(h.MaintenanceID) && writerHash.MatchString(h.RequestSHA256) && writerHash.MatchString(h.ReleaseID) && writerHash.MatchString(h.BindingSHA256)
}
func ServiceHeld(data string) (bool, error) {
	if err := writerDirectory(data); err != nil {
		return false, err
	}
	_, err := os.Lstat(serviceHoldPath(data))
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return err == nil, err
}
func ReadServiceHold(data string) (ServiceHold, error) {
	var out ServiceHold
	if err := writerDirectory(data); err != nil {
		return out, err
	}
	f, info, err := secure.OpenRootFile(serviceHoldPath(data), 4096)
	if err != nil {
		return out, err
	}
	defer f.Close()
	if info.Mode().Perm() != 0400 {
		return out, errors.New("面板停机标记须为 root 只读文件")
	}
	raw, err := io.ReadAll(io.LimitReader(f, 4097))
	if err != nil {
		return out, err
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&out) != nil || d.Decode(new(any)) != io.EOF || !out.valid() || !secure.RootFileUnchanged(f, info) {
		return out, errors.New("面板停机标记内容无效")
	}
	canonical, err := json.Marshal(out)
	if err != nil || !bytes.Equal(canonical, raw) {
		return out, errors.New("面板停机标记不是原始规范记录")
	}
	return out, nil
}
func BindServiceHold(data string, expected ServiceHold) error {
	if os.Geteuid() != 0 || !expected.valid() {
		return errors.New("持久停机需要 root 和原维护事务身份")
	}
	if prior, err := ReadServiceHold(data); err == nil {
		if prior != expected {
			return errors.New("已有其他操作的持久停机标记")
		}
		return syncWriterDirectory(data)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	raw, err := json.Marshal(expected)
	if err != nil {
		return err
	}
	return publishWriterMarker(data, "panel-service-hold.json", raw)
}
func ClearServiceHold(data string, expected ServiceHold) error {
	if os.Geteuid() != 0 || !expected.valid() {
		return errors.New("解除停机标记需要 root 和原维护事务身份")
	}
	prior, err := ReadServiceHold(data)
	if errors.Is(err, os.ErrNotExist) {
		return syncWriterDirectory(data)
	}
	if err != nil {
		return err
	}
	if prior != expected {
		return errors.New("不能解除其他操作的停机标记")
	}
	if err = os.Remove(serviceHoldPath(data)); err != nil {
		return err
	}
	return syncWriterDirectory(data)
}
