package agent

import (
	"errors"
	"fmt"
	"net"
	"os"
	"runtime"
	"strings"
	"syscall"
)

const (
	socketContextAttribute    = "/proc/thread-self/attr/sockcreate"
	agentSocketSELinuxContext = "system_u:system_r:nginxpanel_agent_socket_t:s0"
)

func writeSocketContext(context string) error {
	f, err := os.OpenFile(socketContextAttribute, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	var data []byte
	if context != "" {
		data = append([]byte(context), 0)
	}
	// A zero-byte kernel write clears the override. os.File.Write may skip it.
	n, writeErr := syscall.Write(int(f.Fd()), data)
	if writeErr == nil && n != len(data) {
		writeErr = errors.New("short SELinux socket context write")
	}
	return errors.Join(writeErr, f.Close())
}

func listenAgentUnix(network, path, context string) (*net.UnixListener, error) {
	address := &net.UnixAddr{Name: path, Net: network}
	if context == "" {
		return net.ListenUnix(network, address)
	}
	if context != agentSocketSELinuxContext {
		return nil, errors.New("Agent socket context does not match the fixed SELinux policy")
	}
	type result struct {
		listener *net.UnixListener
		err      error
	}
	done := make(chan result, 1)
	go func() {
		runtime.LockOSThread()
		restored := true
		defer func() {
			// A failed restore retires this thread when the goroutine exits.
			if restored {
				runtime.UnlockOSThread()
			}
		}()
		previous, err := os.ReadFile(socketContextAttribute)
		if err != nil {
			done <- result{err: fmt.Errorf("read SELinux socket context: %w", err)}
			return
		}
		restored = false
		err = writeSocketContext(context)
		var listener *net.UnixListener
		if err == nil {
			listener, err = net.ListenUnix(network, address)
		}
		restoreErr := writeSocketContext(strings.TrimRight(string(previous), "\x00\n"))
		restored = restoreErr == nil
		if err = errors.Join(err, restoreErr); err != nil {
			if listener != nil {
				err = errors.Join(err, listener.Close())
			}
			done <- result{err: fmt.Errorf("create labeled Agent socket: %w", err)}
			return
		}
		done <- result{listener: listener}
	}()
	r := <-done
	return r.listener, r.err
}
