package agent

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"nginxpanel/internal/secure"
)

type fail2banUpgradeStartClaimRequest struct{ ID, IntentSHA256, Invocation string }
type fail2banUpgradeStartClaimReply struct {
	ID, IntentSHA256, Invocation string
	Accepted                     bool
}

func (i fail2banUpgradeActivationIntent) startSocket() string {
	return filepath.Join("/run/nginxpanel-host", "f2b-upgrade-"+i.Request.OperationID+".sock")
}

func fail2banUpgradeStartPeer(c *net.UnixConn) (*unix.Ucred, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return nil, err
	}
	var peer *unix.Ucred
	var readErr error
	if err = raw.Control(func(fd uintptr) { peer, readErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) }); err != nil {
		return nil, err
	}
	if readErr != nil {
		return nil, readErr
	}
	if peer == nil || peer.Uid != 0 || peer.Pid < 2 {
		return nil, errors.New("升级启动许可须来自本机 root 进程")
	}
	return peer, nil
}

// The service's read-only sandbox cannot write the root transaction store.
// Its fixed ExecStartPre asks the lock-holding parent to persist one claim.
func armFail2banUpgradeStart(ctx context.Context, i fail2banUpgradeActivationIntent) (func(), error) {
	if err := secure.RootDirectory(filepath.Dir(i.startSocket()), 0700); err != nil {
		return nil, err
	}
	if info, err := os.Lstat(i.startSocket()); err == nil {
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || st.Uid != 0 || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0600 {
			return nil, errors.New("升级启动通道存在未知文件")
		}
		probe, e := net.DialTimeout("unix", i.startSocket(), 250*time.Millisecond)
		if e == nil {
			probe.Close()
			return nil, errors.New("原升级启动通道仍有监听者，不能替换")
		}
		if !errors.Is(e, syscall.ECONNREFUSED) {
			return nil, e
		}
		if err = os.Remove(i.startSocket()); err != nil {
			return nil, err
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: i.startSocket(), Net: "unix"})
	if err != nil {
		return nil, err
	}
	if err = os.Chmod(i.startSocket(), 0600); err != nil {
		listener.Close()
		return nil, err
	}
	done := make(chan struct{})
	var mu sync.Mutex
	var accepted *net.UnixConn
	go func() {
		defer close(done)
		_ = listener.SetDeadline(time.Now().Add(80 * time.Second))
		c, err := listener.AcceptUnix()
		if err != nil {
			return
		}
		mu.Lock()
		accepted = c
		mu.Unlock()
		defer c.Close()
		if c.SetDeadline(time.Now().Add(15*time.Second)) != nil {
			return
		}
		peer, err := fail2banUpgradeStartPeer(c)
		if err != nil {
			return
		}
		raw, err := fail2banReadLimited("/proc/"+strconv.Itoa(int(peer.Pid))+"/cgroup", 8192)
		if err != nil {
			return
		}
		member := false
		for _, line := range strings.Split(string(raw), "\n") {
			fields := strings.SplitN(line, ":", 3)
			if len(fields) == 3 {
				for _, part := range strings.Split(fields[2], "/") {
					member = member || part == fail2banManagedService
				}
			}
		}
		if !member {
			return
		}
		var request fail2banUpgradeStartClaimRequest
		decoder := json.NewDecoder(io.LimitReader(c, 4096))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&request) != nil || request.ID != i.Request.OperationID || request.IntentSHA256 != i.hash() || !fail2banInvocation.MatchString(request.Invocation) {
			return
		}
		f, err := i.facts()
		if err != nil || !f.Execution || f.Claim != nil || f.Started != nil || f.Stop != nil || f.Receipt != nil || time.Now().Unix() > i.deadline() {
			return
		}
		service, invocation, err := lifecycleService(ctx)
		if err != nil && !errors.Is(err, errFail2banLifecycleJobPending) {
			return
		}
		if service.Load != "loaded" || service.Active != "activating" || invocation != request.Invocation {
			return
		}
		audit, err := (&Journal{Dir: filepath.Join(i.Request.DataDir, "agent", "operations")}).Get(i.Request.OperationID)
		if err != nil || !pendingFail2banUpgradeActivationRecord(audit, i.record(nil)) {
			return
		}
		claim := fail2banUpgradeActivationClaim{fail2banUpgradeActivationMarker: i.marker(), At: time.Now().Unix(), Invocation: invocation, Nonce: secure.ID()}
		if writeFail2banUpgradeActivationJSON(filepath.Join(i.dir(), "prestart.json"), claim) != nil {
			return
		}
		_ = json.NewEncoder(c).Encode(fail2banUpgradeStartClaimReply{ID: request.ID, IntentSHA256: request.IntentSHA256, Invocation: invocation, Accepted: true})
	}()
	return func() {
		listener.Close()
		mu.Lock()
		if accepted != nil {
			accepted.Close()
		}
		mu.Unlock()
		<-done
	}, nil
}

func requestFail2banUpgradeStartClaim(ctx context.Context, i fail2banUpgradeActivationIntent, invocation string) error {
	info, err := os.Lstat(i.startSocket())
	if err != nil {
		return err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != 0 || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0600 {
		return errors.New("升级启动许可通道不可核对")
	}
	c, err := (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "unix", i.startSocket())
	if err != nil {
		return err
	}
	defer c.Close()
	conn, ok := c.(*net.UnixConn)
	if !ok {
		return errors.New("升级启动许可须使用本机通道")
	}
	if _, err = fail2banUpgradeStartPeer(conn); err != nil {
		return err
	}
	deadline := time.Now().Add(20 * time.Second)
	if at, ok := ctx.Deadline(); ok && at.Before(deadline) {
		deadline = at
	}
	if err = c.SetDeadline(deadline); err != nil {
		return err
	}
	request := fail2banUpgradeStartClaimRequest{ID: i.Request.OperationID, IntentSHA256: i.hash(), Invocation: invocation}
	if err = json.NewEncoder(c).Encode(request); err != nil {
		return err
	}
	decoder := json.NewDecoder(io.LimitReader(c, 4096))
	decoder.DisallowUnknownFields()
	var reply fail2banUpgradeStartClaimReply
	if decoder.Decode(&reply) != nil || !reply.Accepted || reply.ID != request.ID || reply.IntentSHA256 != request.IntentSHA256 || reply.Invocation != invocation {
		return errors.New("升级启动许可未持久确认")
	}
	return ctx.Err()
}
