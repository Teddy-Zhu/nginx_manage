package remotelisten

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"
	"nginxpanel/internal/protocol"
)

const PacketLimit = 48 << 10
const ConnectionLimit = 128

// Transfer travels only on the peer-credential checked local packet socket.
// Agent retains its descriptor so shutdown(SHUT_RDWR) also revokes this copy.
type Transfer struct {
	Protocol int    `json:"protocol"`
	ID       string `json:"id"`
	Config   Config `json:"config"`
}

type connectionKey struct{}

func ConnectionID(ctx context.Context) string {
	id, _ := ctx.Value(connectionKey{}).(string)
	return id
}

type ingressConn struct {
	net.Conn
	id      string
	cert    tls.Certificate
	session *ingressSession
	closed  atomic.Bool
}

func (c *ingressConn) Close() error {
	if c.closed.Swap(true) {
		return nil
	}
	err := c.Conn.Close()
	c.session.mu.Lock()
	delete(c.session.connections, c.id)
	c.session.mu.Unlock()
	c.session.writeMu.Lock()
	writeErr := c.session.conn.SetWriteDeadline(time.Now().Add(250 * time.Millisecond))
	if writeErr == nil {
		var n int
		n, writeErr = c.session.conn.Write([]byte(c.id))
		if writeErr == nil && n != len(c.id) {
			writeErr = io.ErrShortWrite
		}
	}
	c.session.writeMu.Unlock()
	if writeErr != nil {
		c.session.conn.Close()
	}
	return err
}

type ingressSession struct {
	conn        *net.UnixConn
	mu          sync.Mutex
	writeMu     sync.Mutex
	connections map[string]*ingressConn
}

type ingressListener struct {
	ctx     context.Context
	cancel  context.CancelFunc
	queue   chan *ingressConn
	mu      sync.Mutex
	session *ingressSession
	done    chan struct{}
}
type ingressAddr struct{}

func (ingressAddr) Network() string       { return "agent-ingress" }
func (ingressAddr) String() string        { return "agent-ingress" }
func (l *ingressListener) Addr() net.Addr { return ingressAddr{} }
func (l *ingressListener) Accept() (net.Conn, error) {
	for {
		select {
		case <-l.ctx.Done():
			return nil, net.ErrClosed
		case c := <-l.queue:
			if c.closed.Load() {
				continue
			}
			return tls.Server(c, &tls.Config{Certificates: []tls.Certificate{c.cert}, MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}}), nil
		}
	}
}
func (l *ingressListener) Close() error {
	l.cancel()
	l.mu.Lock()
	if l.session != nil {
		l.session.conn.Close()
	}
	l.mu.Unlock()
	return nil
}
func (l *ingressListener) receive(socket string) {
	defer close(l.done)
	for l.ctx.Err() == nil {
		conn, err := (&net.Dialer{Timeout: time.Second}).DialContext(l.ctx, "unixpacket", socket)
		if err == nil {
			uc := conn.(*net.UnixConn)
			raw, e := uc.SyscallConn()
			var cred *unix.Ucred
			var ce error
			if e == nil {
				e = raw.Control(func(fd uintptr) { cred, ce = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) })
			}
			if e == nil && ce == nil && cred != nil && cred.Uid == 0 {
				s := &ingressSession{conn: uc, connections: map[string]*ingressConn{}}
				l.mu.Lock()
				l.session = s
				if l.ctx.Err() != nil {
					uc.Close()
				}
				l.mu.Unlock()
				l.receivePackets(s)
				uc.Close()
				s.mu.Lock()
				for _, c := range s.connections {
					c.closed.Store(true)
					c.Conn.Close()
				}
				s.connections = map[string]*ingressConn{}
				s.mu.Unlock()
				l.mu.Lock()
				if l.session == s {
					l.session = nil
				}
				l.mu.Unlock()
			} else {
				uc.Close()
			}
		}
		timer := time.NewTimer(time.Second)
		select {
		case <-l.ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}
func (l *ingressListener) receivePackets(s *ingressSession) {
	data := make([]byte, PacketLimit)
	oob := make([]byte, unix.CmsgSpace(4*4))
	hello := true
	for {
		n, on, flags, _, err := s.conn.ReadMsgUnix(data, oob)
		if err != nil {
			return
		}
		var fds []int
		messages, err := unix.ParseSocketControlMessage(oob[:on])
		if err == nil {
			for _, msg := range messages {
				rights, e := unix.ParseUnixRights(&msg)
				if e != nil {
					err = e
					break
				}
				fds = append(fds, rights...)
			}
		}
		for _, fd := range fds {
			unix.CloseOnExec(fd)
		}
		closeFDs := func() {
			for _, fd := range fds {
				unix.Close(fd)
			}
		}
		var t Transfer
		if err != nil || flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 || json.Unmarshal(data[:n], &t) != nil || t.Protocol != protocol.Agent {
			closeFDs()
			return
		}
		if hello {
			hello = false
			if t.ID != "" || len(fds) != 0 {
				closeFDs()
				return
			}
			continue
		}
		if len(fds) != 1 || len(t.ID) != 36 || t.Config.Validate(false) != nil {
			closeFDs()
			return
		}
		f := os.NewFile(uintptr(fds[0]), "management-ingress")
		c, err := net.FileConn(f)
		f.Close()
		if err != nil {
			return
		}
		cert, err := tls.X509KeyPair([]byte(t.Config.CertificatePEM), []byte(t.Config.KeyPEM))
		if err != nil {
			c.Close()
			return
		}
		ic := &ingressConn{Conn: c, id: t.ID, cert: cert, session: s}
		s.mu.Lock()
		if len(s.connections) >= ConnectionLimit || s.connections[t.ID] != nil {
			s.mu.Unlock()
			c.Close()
			return
		}
		s.connections[t.ID] = ic
		s.mu.Unlock()
		select {
		case l.queue <- ic:
		case <-l.ctx.Done():
			return
		default:
			ic.Close()
		}
	}
}

// Serve terminates TLS in the application, preserving the real socket peer.
// Loss of the root broker closes all inherited connections before reconnecting.
func Serve(ctx context.Context, socket string, handler http.Handler) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	l := &ingressListener{ctx: ctx, cancel: cancel, queue: make(chan *ingressConn, 16), done: make(chan struct{})}
	go l.receive(socket)
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10, ConnContext: func(ctx context.Context, c net.Conn) context.Context {
		if tc, ok := c.(*tls.Conn); ok {
			if ic, ok := tc.NetConn().(*ingressConn); ok {
				return context.WithValue(ctx, connectionKey{}, ic.id)
			}
		}
		return ctx
	}}
	done := make(chan struct{})
	go func() { defer close(done); <-ctx.Done(); l.Close(); server.Close() }()
	err := server.Serve(l)
	cancel()
	<-done
	<-l.done
	if errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed) || errors.Is(err, io.EOF) {
		return nil
	}
	return err
}
