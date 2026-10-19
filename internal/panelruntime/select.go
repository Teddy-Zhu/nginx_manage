package panelruntime

import (
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"syscall"
)

var selectionID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// SwitchCurrent is the pointer step of a root maintenance transaction. Its
// caller must hold the panel writer lock and persist the exact before/after
// identities first; this function neither authorizes an update nor starts code.
func SwitchCurrent(data, before, after, operation string) error {
	if os.Geteuid() != 0 || !digest.MatchString(before) || !digest.MatchString(after) || before == after || !selectionID.MatchString(operation) {
		return errors.New("面板版本选择需要 root 和原事务的固定版本身份")
	}
	root, err := Root(data)
	if err != nil {
		return err
	}
	unlock, err := publicationLock(root)
	if err != nil {
		return err
	}
	defer unlock()
	current, err := Read(data)
	if err != nil {
		return err
	}
	if current.Release.ID == after {
		return syncDir(root)
	}
	if current.Release.ID != before {
		return errors.New("当前面板版本已偏离原状态及批准目标")
	}
	if _, err = readRelease(filepath.Join(root, "releases", after), after); err != nil {
		return err
	}
	if err = savePreviousProgram(root, before, after, operation); err != nil {
		return err
	}
	name, target := filepath.Join(root, ".select-"+operation), "releases/"+after
	info, err := os.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		if err = os.Symlink(target, name); err != nil {
			return err
		}
	} else if err != nil {
		return err
	} else {
		st, ok := info.Sys().(*syscall.Stat_t)
		value, e := os.Readlink(name)
		if !ok || st.Uid != 0 || info.Mode()&os.ModeSymlink == 0 || e != nil || value != target {
			return errors.New("版本选择临时指针不属于原事务")
		}
	}
	defer os.Remove(name)
	if err = os.Rename(name, filepath.Join(root, "current")); err != nil {
		return err
	}
	return syncDir(root)
}
