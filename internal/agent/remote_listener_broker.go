package agent

import (
	"encoding/json"
	"errors"
	"net"
	"os"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"nginxpanel/internal/remotelisten"
	"nginxpanel/internal/secure"
)

func (m *remoteListener) openBroker() error {
	if info, err := os.Lstat(m.socket); err == nil {
		st, ok := info.Sys().(*syscall.Stat_t)
		if info.Mode()&os.ModeSocket == 0 || !ok || st.Uid != 0 {
			return errors.New("远程监听本机 Socket 不可信")
		}
		conn, e := net.DialTimeout("unixpacket", m.socket, time.Second)
		if e == nil {
			conn.Close()
			return errors.New("远程监听已运行")
		}
		if !errors.Is(e, syscall.ECONNREFUSED) {
			return e
		}
		if err = os.Remove(m.socket); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	l, err := listenAgentUnix("unixpacket", m.socket, m.socketSELinuxContext)
	if err != nil {
		return err
	}
	m.broker = l
	if err = os.Chmod(m.socket, 0660); err != nil {
		return err
	}
	m.wg.Add(1)
	go func() { defer m.wg.Done(); m.acceptWeb(l) }()
	return nil
}
func (m *remoteListener) acceptWeb(l *net.UnixListener) {
	for {
		c, err := l.AcceptUnix()
		if err != nil {
			return
		}
		raw, err := c.SyscallConn()
		var cred *unix.Ucred
		var credErr error
		if err == nil {
			err = raw.Control(func(fd uintptr) { cred, credErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) })
		}
		if err != nil || credErr != nil || cred == nil || cred.Uid != m.uid {
			c.Close()
			continue
		}
		m.mu.Lock()
		if m.closed || m.web != nil {
			m.mu.Unlock()
			c.Close()
			continue
		}
		// Hello is delivered before attaching, so the first packet cannot be
		// mistaken for a descriptor when an incoming TCP connection races it.
		hello, _ := json.Marshal(remotelisten.Transfer{Protocol: Protocol})
		_ = c.SetWriteDeadline(time.Now().Add(time.Second))
		_, err = c.Write(hello)
		if err != nil {
			m.mu.Unlock()
			c.Close()
			continue
		}
		m.web = c
		m.wg.Add(1)
		m.mu.Unlock()
		go func() { defer m.wg.Done(); m.readReleases(c) }()
	}
}
func (m *remoteListener) readReleases(c *net.UnixConn) {
	defer func() {
		c.Close()
		m.mu.Lock()
		defer m.mu.Unlock()
		if m.web != c {
			return
		}
		m.web = nil
		m.closeConnections(0)
		if !m.closed && m.pendingLocked() {
			_ = m.rollback("Web 连接中断，恢复已确认入口")
		}
	}()
	buf := make([]byte, 37)
	for {
		n, err := c.Read(buf)
		if err != nil || n != 36 || !validID(string(buf[:n])) {
			return
		}
		id := string(buf[:n])
		m.mu.Lock()
		if m.web != c {
			m.mu.Unlock()
			return
		}
		if socket, ok := m.connections[id]; ok {
			socket.conn.Close()
			delete(m.connections, id)
		}
		m.mu.Unlock()
	}
}
func (m *remoteListener) acceptTCP(l *net.TCPListener) {
	for {
		c, err := l.AcceptTCP()
		if err != nil {
			m.mu.Lock()
			if !m.closed && m.listener == l {
				m.stopListening()
				m.closeConnections(0)
				if m.pendingLocked() {
					_ = m.rollback("候选监听中断，恢复已确认入口")
				} else {
					m.problem = "远程监听已中断；请通过主入口检查并重启 Agent"
				}
			}
			m.mu.Unlock()
			return
		}
		m.mu.Lock()
		if m.expired() {
			_ = m.rollback("确认期限已到，恢复已确认入口")
		}
		config := m.effective()
		if m.closed || m.listener != l || m.problem != "" || m.web == nil || !config.Allows(c.RemoteAddr()) || len(m.connections) >= remotelisten.ConnectionLimit {
			m.mu.Unlock()
			c.Close()
			continue
		}
		id := secure.ID()
		packet, err := json.Marshal(remotelisten.Transfer{Protocol: Protocol, ID: id, Config: config})
		if err != nil || len(packet) > remotelisten.PacketLimit {
			m.mu.Unlock()
			c.Close()
			continue
		}
		c.SetKeepAlive(true)
		_ = m.web.SetWriteDeadline(time.Now().Add(time.Second))
		raw, e := c.SyscallConn()
		var sendErr error
		if e == nil {
			e = raw.Control(func(fd uintptr) {
				n, _, err := m.web.WriteMsgUnix(packet, unix.UnixRights(int(fd)), nil)
				sendErr = err
				if err == nil && n != len(packet) {
					sendErr = errors.New("监听描述符传递不完整")
				}
			})
		}
		if e != nil || sendErr != nil {
			shutdownListenerConn(c)
			m.web.Close()
			m.mu.Unlock()
			continue
		}
		host, _, _ := net.SplitHostPort(c.RemoteAddr().String())
		m.connections[id] = listenerSocket{listener: l, conn: c, version: m.state.Version, source: host}
		m.mu.Unlock()
	}
}
