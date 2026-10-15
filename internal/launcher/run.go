package launcher

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"nginxpanel/internal/panelruntime"
	"nginxpanel/internal/secure"
)

type child struct{ cmd *exec.Cmd }

func (s *supervisor) start(snapshot panelruntime.Snapshot) (*child, error) {
	if snapshot.Deployment != s.deployment {
		return nil, errors.New("launcher 固定部署登记已变化")
	}
	cmd := exec.Command(filepath.Join(snapshot.Directory, "nginxpanel"), "serve", "--data-dir", s.data, "--listen", s.deployment.Listen, "--web-dir", filepath.Join(snapshot.Directory, "web"), "--nginx-modules", "/etc/nginxpanel/nginx-modules.json", "--panel-runtime", "docker")
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C", "TZ=UTC", "SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt"}
	cmd.Dir = s.data
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.status.State, s.status.PID, s.status.ReleaseID, s.status.Version = "running", cmd.Process.Pid, snapshot.Release.ID, snapshot.Release.Version
	s.mu.Unlock()
	return &child{cmd: cmd}, nil
}

// PID 1 owns wait4 for every descendant. exec.Cmd.Wait is deliberately not used,
// so orphan reaping cannot race with a second waiter for the serve child.
func (s *supervisor) reap(c *child) (bool, bool, error) {
	exited := false
	for {
		var status unix.WaitStatus
		pid, err := unix.Wait4(-1, &status, unix.WNOHANG, nil)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if errors.Is(err, unix.ECHILD) {
			return exited, false, nil
		}
		if pid == 0 {
			return exited, true, nil
		}
		if err != nil {
			return exited, true, err
		}
		if c.cmd != nil && pid == c.cmd.Process.Pid {
			exit := status.ExitStatus()
			if status.Signaled() {
				exit = 128 + int(status.Signal())
			}
			if err = c.cmd.Process.Release(); err != nil {
				return true, true, err
			}
			c.cmd = nil
			s.mu.Lock()
			s.status.PID, s.status.LastExit = 0, exit
			if s.status.State == "running" {
				s.status.State = "failed"
			}
			s.mu.Unlock()
			exited = true
		}
	}
}
func (s *supervisor) stop(c *child) (bool, error) {
	s.mu.Lock()
	s.status.State = "stopping"
	s.mu.Unlock()
	// As isolated PID 1, stop every descendant, including a child that changed
	// process groups. PID 1 itself is excluded by kill(-1).
	if err := unix.Kill(-1, unix.SIGTERM); err != nil && !errors.Is(err, unix.ESRCH) {
		return false, err
	}
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	deadline := time.Now().Add(45 * time.Second)
	forced := false
	for {
		_, children, err := s.reap(c)
		if err != nil {
			return forced, err
		}
		if !children && c.cmd == nil {
			s.mu.Lock()
			s.status.State = "stopped"
			s.mu.Unlock()
			return forced, nil
		}
		if time.Now().After(deadline) {
			if forced {
				return true, errors.New("无法确认旧 serve 进程组已结束，拒绝启动第二个业务写者")
			}
			if err = unix.Kill(-1, unix.SIGKILL); err != nil && !errors.Is(err, unix.ESRCH) {
				return true, err
			}
			forced = true
			deadline = time.Now().Add(5 * time.Second)
		}
		<-ticker.C
	}
}

func Run(ctx context.Context, data string) (runErr error) {
	if os.Getpid() != 1 || os.Geteuid() == 0 {
		return errors.New("launcher 仅允许作为容器非 root PID 1")
	}
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return err
	}
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		return err
	}
	snapshot, err := panelruntime.Read(data)
	if err != nil {
		return err
	}
	if err = checkLayout(snapshot.Deployment); err != nil {
		return err
	}
	guard, err := lock(data)
	if err != nil {
		return err
	}
	defer guard.Close()
	s := &supervisor{data: data, deployment: snapshot.Deployment, status: Status{Protocol: Protocol, BootID: secure.ID(), State: "starting", LastExit: -1}, operations: map[string]Operation{}, queue: make(chan Request, 1)}
	l, err := listen(data)
	if err != nil {
		return err
	}
	defer l.Close()
	server := &http.Server{Handler: s.handler(), ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, IdleTimeout: 15 * time.Second, MaxHeaderBytes: 8192}
	defer server.Close()
	serverErrors := make(chan error, 1)
	go func() { serverErrors <- server.Serve(l) }()
	c, err := s.start(snapshot)
	if err != nil {
		return err
	}
	defer func() {
		if c != nil {
			if _, err := s.stop(c); err != nil {
				runErr = errors.Join(runErr, err)
			}
		}
	}()
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-serverErrors:
			return err
		case <-ticker.C:
			exited, _, err := s.reap(c)
			if err != nil {
				return err
			}
			if exited {
				return fmt.Errorf("serve 已退出，退出码 %d", s.view().LastExit)
			}
		case req := <-s.queue:
			s.operation(req, "validating", "", false)
			next, err := panelruntime.Read(data)
			if err != nil || next.Release.ID != req.ReleaseID || next.Deployment != s.deployment {
				s.operation(req, "failed", "当前受信发布无法核对，保留原 serve", false)
				continue
			}
			s.operation(req, "stopping", "", false)
			previous := c
			c = nil
			forced, err := s.stop(previous)
			if err != nil {
				s.operation(req, "failed", "旧进程结束状态无法确认", forced)
				return err
			}
			if ctx.Err() != nil {
				return nil
			}
			c, err = s.start(next)
			if err != nil {
				s.operation(req, "failed", "新 serve 未启动", forced)
				return err
			}
			s.operation(req, "started", "", forced)
		}
	}
}
