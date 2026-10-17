package agent

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"syscall"

	"golang.org/x/sys/unix"
)

const iptablesHelperBytes = 128 << 20

type iptablesGateRequest struct {
	Version int
	Parent  networkdProcess
	Grant   string
	Restore ufwBoundFile
}

// RunIPTablesRestoreGate is an internal entry point of the same pinned binary.
// No API supplies this request: the parent freezes it before starting the child.
// The child keeps its PID across exec and cannot write before the durable grant.
func RunIPTablesRestoreGate(encoded string) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	invalid := errors.New("iptables 固定子进程许可无效")
	var request iptablesGateRequest
	if len(encoded) > 16<<10 || ufwToolJSON([]byte(encoded), &request) != nil || os.Geteuid() != 0 || request.Version != 1 || !validDNSProcess(request.Parent) || !firewalldDigest(request.Grant) || !validIPTablesBoundFile(request.Restore, 16<<20) || !slices.Contains([]string{"iptables-nft-restore", "ip6tables-nft-restore", "iptables-legacy-restore", "ip6tables-legacy-restore"}, request.Restore.Role) || filepath.Base(request.Restore.Invoked) != request.Restore.Role {
		return invalid
	}
	// Install on this locked Go thread as well as at fork. The signal is tied to
	// the creating parent thread; a changed/reparented process grants nothing.
	if err := unix.Prctl(unix.PR_SET_PDEATHSIG, uintptr(unix.SIGKILL), 0, 0, 0); err != nil {
		return err
	}
	parent, err := networkProcess(uint32(os.Getppid()))
	if err != nil || parent != request.Parent {
		return invalid
	}
	gate := os.NewFile(3, "iptables-grant")
	defer gate.Close()
	info, err := gate.Stat()
	if err != nil || info.Mode()&os.ModeNamedPipe == 0 {
		return invalid
	}
	grant, err := io.ReadAll(io.LimitReader(gate, 65))
	if err != nil || len(grant) != 64 || string(grant) != request.Grant {
		return invalid
	}
	parent, err = networkProcess(uint32(os.Getppid()))
	if err != nil || parent != request.Parent {
		return invalid
	}
	// The parent pinned and checked all executable inodes. Recheck the inherited
	// restore descriptor rather than selecting a path again in the child.
	restore := os.NewFile(4, "iptables-restore")
	info, err = restore.Stat()
	if err != nil {
		return invalid
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	wanted := request.Restore.File
	if !ok || stat.Uid != 0 || uint64(stat.Dev) != wanted.Device || stat.Ino != wanted.Inode || info.Size() != wanted.Bytes || uint32(info.Mode()) != wanted.Mode || info.ModTime().UnixNano() != wanted.Modified || stat.Ctim.Sec*1e9+stat.Ctim.Nsec != wanted.Changed {
		return invalid
	}
	if _, err = unix.Fgetxattr(4, "security.capability", nil); !errors.Is(err, unix.ENODATA) && !errors.Is(err, unix.ENOTSUP) {
		return invalid
	}
	gate.Close()
	unix.CloseOnExec(4)
	unix.CloseOnExec(5)
	// 6 is the pinned false ELF; 7 keeps the execution flock alive until the
	// native restore exits. Neither may close during this exec transition.
	return syscall.Exec("/proc/self/fd/4", []string{request.Restore.Invoked, "--noflush", "--wait", "1", "--modprobe", "/proc/self/fd/6"}, []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C"})
}
