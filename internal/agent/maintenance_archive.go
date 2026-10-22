package agent

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
	"nginxpanel/internal/maintenance"
)

const maintenanceArchiveDir = "maintenance-archive"

func releasedMaintenance(r Record) bool {
	return validID(r.OperationID) && r.Kind == "maintenance.lock" && r.State == "succeeded" && r.Stage == "released" && validID(r.MaintenanceEpoch) && r.RequestHash == maintenanceHash(maintenance.RootRequest{OperationID: r.OperationID})
}

func (j *Journal) maintenanceArchivePath(id string) string {
	return filepath.Join(j.Dir, maintenanceArchiveDir, id[:2], id+".json")
}

// Validate every new path component separately: a writable directory or symlink
// must not redirect an immutable root receipt into panel-controlled storage.
func maintenanceArchiveDirectory(path string, create bool) error {
	if create {
		if err := os.Mkdir(path, 0700); err != nil && !os.IsExist(err) {
			return err
		}
	}
	st, err := os.Lstat(path)
	if err != nil {
		return err
	}
	stat, ok := st.Sys().(*syscall.Stat_t)
	if !ok || !st.IsDir() || st.Mode().Perm() != 0700 || stat.Uid != uint32(os.Geteuid()) {
		return errors.New("untrusted maintenance archive directory")
	}
	return nil
}

func (j *Journal) archivedMaintenance(id string) (Record, error) {
	if !validID(id) {
		return Record{}, errors.New("invalid archived operation ID")
	}
	path := j.maintenanceArchivePath(id)
	for _, dir := range []string{filepath.Join(j.Dir, maintenanceArchiveDir), filepath.Dir(path)} {
		if err := maintenanceArchiveDirectory(dir, false); err != nil {
			return Record{}, err
		}
	}
	return readMaintenanceReceipt(path, id)
}

func readMaintenanceReceipt(path, id string) (Record, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return Record{}, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return Record{}, err
	}
	stat, ok := st.Sys().(*syscall.Stat_t)
	if !ok || !st.Mode().IsRegular() || st.Mode().Perm() != 0600 || stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 || st.Size() > 8192 {
		return Record{}, errors.New("untrusted maintenance archive receipt")
	}
	raw, err := io.ReadAll(io.LimitReader(f, 8193))
	if err != nil {
		return Record{}, err
	}
	var r Record
	if len(raw) > 8192 || json.Unmarshal(raw, &r) != nil || r.OperationID != id || r.UpdatedAt <= 0 || !releasedMaintenance(r) {
		return Record{}, errors.New("invalid maintenance archive receipt")
	}
	return r, nil
}

func syncMaintenanceArchive(source, target string) error {
	for _, path := range []string{target, filepath.Dir(target), source} {
		dir, err := os.Open(path)
		if err != nil {
			return err
		}
		err = dir.Sync()
		closeErr := dir.Close()
		if err = errors.Join(err, closeErr); err != nil {
			return err
		}
	}
	return nil
}

func (j *Journal) archiveMaintenance(r Record) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.archiveMaintenanceLocked(r)
}

// A completed lease is only a replay fence; it cannot authorize future work.
// Moving its entire original record leaves no dangling recovery reference.
// Rename is atomic and never overwrites an earlier receipt. A crash before the
// rename leaves the released record in the live directory for startup to retry.
func (j *Journal) archiveMaintenanceLocked(r Record) error {
	if !releasedMaintenance(r) {
		return errors.New("only released maintenance can be archived")
	}
	path := j.maintenanceArchivePath(r.OperationID)
	for _, dir := range []string{filepath.Join(j.Dir, maintenanceArchiveDir), filepath.Dir(path)} {
		if err := maintenanceArchiveDirectory(dir, true); err != nil {
			return err
		}
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		return err
	}
	// 256 fixed UUID prefixes, at most 128 receipts per prefix and 8 KiB per
	// receipt: bounded directory lookup and at most 256 MiB of retained evidence.
	if len(entries) >= 128 {
		return errors.New("maintenance archive capacity reached; receipts must be preserved during local storage maintenance")
	}
	source := filepath.Join(j.Dir, r.OperationID+".json")
	stored, err := readMaintenanceReceipt(source, r.OperationID)
	if err != nil {
		return err
	}
	if stored.RequestHash != r.RequestHash {
		return errors.New("maintenance receipt changed before archival")
	}
	if err = unix.Renameat2(unix.AT_FDCWD, source, unix.AT_FDCWD, path, unix.RENAME_NOREPLACE); err != nil {
		return err
	}
	return syncMaintenanceArchive(j.Dir, filepath.Dir(path))
}
