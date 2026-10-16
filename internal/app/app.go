package app

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
	"nginxpanel/internal/acme"
	"nginxpanel/internal/agent"
	"nginxpanel/internal/auth"
	"nginxpanel/internal/backup"
	"nginxpanel/internal/certificates"
	"nginxpanel/internal/components"
	"nginxpanel/internal/firewall"
	"nginxpanel/internal/hostdns"
	"nginxpanel/internal/maintenance"
	"nginxpanel/internal/migration"
	"nginxpanel/internal/modules"
	"nginxpanel/internal/monitoring"
	"nginxpanel/internal/nginxconfig"
	"nginxpanel/internal/nginxinstall"
	"nginxpanel/internal/nodes"
	"nginxpanel/internal/notifications"
	"nginxpanel/internal/panelready"
	"nginxpanel/internal/panelruntime"
	"nginxpanel/internal/panelupdates"
	"nginxpanel/internal/remotelisten"
	"nginxpanel/internal/secure"
	"nginxpanel/internal/storage"
	"nginxpanel/internal/tasks"
	"nginxpanel/internal/transport"
)

type Options struct {
	DataDir, Listen, Socket, WebDir, TLSCert, TLSKey, Version string
	PanelRuntime                                              string
	Dev                                                       bool
	Policy                                                    nginxconfig.Policy
}

func Init(ctx context.Context, dataDir string, development bool) (string, error) {
	if !filepath.IsAbs(dataDir) {
		return "", errors.New("data directory must be absolute")
	}
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return "", err
	}
	for _, dir := range []string{"app", "bootstrap", "secrets", "staging", "backups", "run"} {
		if err := os.MkdirAll(filepath.Join(dataDir, dir), 0700); err != nil {
			return "", err
		}
	}
	unlock, err := Lock(dataDir, development)
	if err != nil {
		return "", err
	}
	defer unlock()
	if !development {
		if err := panelruntime.CheckInit(dataDir); err != nil {
			return "", err
		}
	}
	keyPath := filepath.Join(dataDir, "secrets", "master.key")
	if _, err := os.Lstat(keyPath); os.IsNotExist(err) {
		if _, err := os.Stat(filepath.Join(dataDir, "app", "panel.db")); !os.IsNotExist(err) {
			return "", errors.New("database exists without a master key; restore the original key")
		}
		if err := secure.CreateKey(keyPath); err != nil {
			return "", err
		}
	} else if err != nil {
		return "", err
	}
	if _, err := secure.LoadKey(keyPath); err != nil {
		return "", err
	}
	db, err := storage.Open(ctx, dataDir)
	if err != nil {
		return "", err
	}
	defer db.Close()
	if err := modules.Init(ctx, db); err != nil {
		return "", err
	}
	if err := monitoring.Ensure(ctx, db); err != nil {
		return "", err
	}
	if err := notifications.Ensure(ctx, db); err != nil {
		return "", err
	}
	if _, err := db.ExecContext(ctx, "INSERT INTO settings(key,value) VALUES('node_id',?) ON CONFLICT(key) DO NOTHING", secure.ID()); err != nil {
		return "", err
	}
	var users int
	if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM users").Scan(&users); err != nil {
		return "", err
	}
	bootstrapPath := ""
	if users == 0 {
		bootstrapPath = filepath.Join(dataDir, "bootstrap", "token")
		var stored string
		err := db.QueryRowContext(ctx, "SELECT value FROM settings WHERE key='bootstrap_hash'").Scan(&stored)
		if errors.Is(err, sql.ErrNoRows) {
			token := secure.Token()
			if err := writeExclusive(bootstrapPath, []byte(token+"\n")); err != nil {
				return "", err
			}
			if _, err := db.ExecContext(ctx, "INSERT INTO settings(key,value) VALUES('bootstrap_hash',?)", secure.Hash([]byte(token))); err != nil {
				return "", err
			}
		} else if err != nil {
			return "", err
		}
	}
	tlsDir := filepath.Join(dataDir, "secrets", "node-tls")
	if _, err := os.Lstat(filepath.Join(tlsDir, "cert.pem")); os.IsNotExist(err) {
		if err := createLocalTLS(tlsDir); err != nil {
			return "", err
		}
	} else if err != nil {
		return "", err
	}
	return bootstrapPath, nil
}

func writeExclusive(name string, b []byte) error {
	f, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write(b); err != nil {
		return err
	}
	return f.Sync()
}

func createLocalTLS(dir string) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return err
	}
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "NginxPanel local management"}, NotBefore: time.Now().Add(-5 * time.Minute), NotAfter: time.Now().Add(365 * 24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	if err := writeExclusive(filepath.Join(dir, "key.pem"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})); err != nil {
		return err
	}
	return writeExclusive(filepath.Join(dir, "cert.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// The process lock prevents a second serve instance, including migration or
// lease recovery, from treating the same node database as shared application state.
func Lock(dataDir string, development bool) (func(), error) {
	if !development {
		return storage.LockWriter(dataDir, os.Getegid())
	}
	f, err := os.OpenFile(filepath.Join(dataDir, "app", ".writer.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		f.Close()
		return nil, errors.New("another panel process owns this data directory")
	}
	return func() { unix.Flock(int(f.Fd()), unix.LOCK_UN); f.Close() }, nil
}

func Run(ctx context.Context, o Options) error {
	if o.PanelRuntime != "native" && o.PanelRuntime != "docker" && o.PanelRuntime != "development" {
		return errors.New("面板运行模式未明确配置")
	}
	if o.Dev != (o.PanelRuntime == "development") {
		return errors.New("面板运行模式与开发开关不一致")
	}
	if !o.Dev && os.Geteuid() == 0 {
		return errors.New("serve must run as a dedicated non-root user")
	}
	host, _, err := net.SplitHostPort(o.Listen)
	if err != nil {
		return err
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return errors.New("主恢复入口必须使用回环地址；远程入口通过受控监听配置")
	}
	unlock, err := Lock(o.DataDir, o.Dev)
	if err != nil {
		return err
	}
	defer unlock()
	var running panelruntime.Snapshot
	if !o.Dev {
		running, err = panelruntime.CheckProcess(o.DataDir, o.PanelRuntime, o.Listen, o.WebDir, o.Version)
		if err != nil {
			return err
		}
	}
	vault, err := secure.LoadKey(filepath.Join(o.DataDir, "secrets", "master.key"))
	if err != nil {
		return err
	}
	db, err := storage.Open(ctx, o.DataDir)
	if err != nil {
		return err
	}
	defer db.Close()
	var nodeID string
	if err := db.QueryRowContext(ctx, "SELECT value FROM settings WHERE key='node_id'").Scan(&nodeID); err != nil {
		return errors.New("data directory is not initialized; run init first")
	}
	certificateStore := &certificates.Service{DB: db, Vault: vault}
	config := &nginxconfig.Service{DB: db, Vault: vault, Policy: o.Policy, Certificates: certificateStore}
	agentClient := agent.NewClient(o.Socket)
	maintenanceService := &maintenance.Service{DB: db, Vault: vault, Agent: agentClient}
	if err := maintenanceService.Init(ctx); err != nil {
		return err
	}
	config.RequireFeatures = agentClient.RequireFeatures
	acmeService := &acme.Service{Maintenance: maintenanceService, DB: db, Vault: vault, Certificates: certificateStore, Config: config, Agent: agentClient}
	if err := monitoring.Ensure(ctx, db); err != nil {
		return err
	}
	monitoringService := &monitoring.Service{DB: db, Vault: vault, Agent: agentClient}
	if err := notifications.Ensure(ctx, db); err != nil {
		return err
	}
	notificationService := &notifications.Service{Maintenance: maintenanceService, DB: db, Vault: vault, NodeID: nodeID, DataDir: o.DataDir}
	dnsService := &hostdns.Service{Maintenance: maintenanceService, DB: db, Vault: vault}
	if agentClient != nil {
		dnsService.Agent = agentClient
	}
	componentService := &components.Service{Maintenance: maintenanceService, DB: db, Vault: vault, Agent: agentClient}
	installationService := &nginxinstall.Service{Maintenance: maintenanceService, DB: db, Vault: vault, Components: componentService, Agent: agentClient}
	updateService := &panelupdates.Service{Maintenance: maintenanceService, DB: db, Vault: vault, Components: componentService, Agent: agentClient}
	firewallService := &firewall.Service{DB: db, Vault: vault, Agent: agentClient}
	migrationService := &migration.Service{Firewall: firewallService, Components: componentService, Installations: installationService, Maintenance: maintenanceService, DB: db, Vault: vault, Config: config, ACME: acmeService, Notifications: notificationService, Agent: agentClient, NodeID: nodeID, Version: o.Version}
	backupService := &backup.Service{DB: db, Vault: vault, Maintenance: maintenanceService, Agent: agentClient, DataDir: o.DataDir, NodeID: nodeID, Version: o.Version, Runtime: o.PanelRuntime, ReleaseID: running.Release.ID}
	api := (&transport.Server{Firewall: firewallService, Maintenance: maintenanceService, DB: db, Auth: auth.New(db, o.Dev), Config: config, ACME: acmeService, Agent: agentClient, Monitoring: monitoringService, Notifications: notificationService, HostDNS: dnsService, Migration: migrationService, Backups: backupService, Components: componentService, Installations: installationService, Updates: updateService, Nodes: &nodes.Service{DB: db, Vault: vault, NodeID: nodeID}, NodeID: nodeID, Dev: o.Dev, Version: o.Version, PanelRuntime: o.PanelRuntime}).Handler()
	static := spa(o.WebDir)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api" || strings.HasPrefix(r.URL.Path, "/api/") {
			api.ServeHTTP(w, r)
			return
		}
		static.ServeHTTP(w, r)
	})
	server := &http.Server{Addr: o.Listen, Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10}
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	result := make(chan error, 14)
	listener, err := net.Listen("tcp", o.Listen)
	if err != nil {
		return err
	}
	defer listener.Close()
	var workers sync.WaitGroup
	workers.Add(12)
	if !o.Dev {
		readyListener, err := panelready.Listen(o.DataDir)
		if err != nil {
			return err
		}
		defer readyListener.Close()
		workers.Add(2)
		go func() { defer workers.Done(); result <- remotelisten.Serve(runCtx, o.Socket+".remote", handler) }()
		go func() {
			defer workers.Done()
			result <- panelready.Serve(runCtx, readyListener, nodeID, func(ctx context.Context) (panelready.Status, error) {
				return readinessStatus(ctx, o, running.Release, db, maintenanceService, agentClient)
			}, func(ctx context.Context, restoreID, maintenanceID string) (panelready.ReleaseStatus, error) {
				return readinessReleaseStatus(ctx, o, running.Release, db, restoreID, maintenanceID)
			})
		}()
	}
	go func() {
		defer workers.Done()
		if o.Dev {
			result <- server.Serve(listener)
		} else {
			result <- server.ServeTLS(listener, o.TLSCert, o.TLSKey)
		}
	}()
	go func() {
		defer workers.Done()
		result <- (&tasks.Runner{Maintenance: maintenanceService, DB: db, Config: config, Agent: agentClient}).Run(runCtx)
	}()
	go func() {
		defer workers.Done()
		result <- acmeService.Run(runCtx)
	}()
	go func() { defer workers.Done(); result <- monitoringService.Run(runCtx) }()
	go func() { defer workers.Done(); result <- notificationService.Run(runCtx) }()
	go func() { defer workers.Done(); result <- dnsService.Run(runCtx) }()
	go func() { defer workers.Done(); result <- migrationService.Run(runCtx) }()
	go func() { defer workers.Done(); result <- backupService.Run(runCtx) }()
	go func() { defer workers.Done(); result <- componentService.Run(runCtx) }()
	go func() { defer workers.Done(); result <- installationService.Run(runCtx) }()
	go func() { defer workers.Done(); result <- updateService.Run(runCtx) }()
	go func() { defer workers.Done(); result <- maintenanceService.Run(runCtx) }()
	select {
	case <-ctx.Done():
		err = nil
	case err = <-result:
	}
	cancel()
	shutdown, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	if shutdownErr := server.Shutdown(shutdown); shutdownErr != nil {
		server.Close()
		if err == nil {
			err = shutdownErr
		}
	}
	workers.Wait()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func spa(dir string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" && r.Method != "HEAD" {
			http.Error(w, "method not allowed", 405)
			return
		}
		name := strings.TrimPrefix(filepath.Clean(r.URL.Path), "/")
		if name == "." || name == "" {
			name = "index.html"
		}
		if !fs.ValidPath(name) {
			http.NotFound(w, r)
			return
		}
		filename := filepath.Join(dir, name)
		if info, err := os.Stat(filename); err != nil || info.IsDir() {
			if filepath.Ext(name) != "" {
				http.NotFound(w, r)
				return
			}
			filename = filepath.Join(dir, "index.html")
		}
		if _, err := os.Stat(filename); err != nil {
			http.Error(w, "前端资源尚未构建；开发时请访问前端开发服务器", 503)
			return
		}
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'")
		http.ServeFile(w, r, filename)
	})
}

func SocketPath(dataDir string) string { return filepath.Join(dataDir, "run", "agent", "agent.sock") }
func Defaults(dataDir string, dev bool) Options {
	listen := "127.0.0.1:9443"
	if dev {
		listen = "127.0.0.1:8080"
	}
	mode := "native"
	if dev {
		mode = "development"
	}
	return Options{DataDir: dataDir, Listen: listen, Socket: SocketPath(dataDir), WebDir: "web/dist", TLSCert: filepath.Join(dataDir, "secrets", "node-tls", "cert.pem"), TLSKey: filepath.Join(dataDir, "secrets", "node-tls", "key.pem"), Dev: dev, Policy: nginxconfig.DefaultPolicy(), PanelRuntime: mode}
}

func Fingerprint(dataDir string) (string, error) {
	b, err := os.ReadFile(filepath.Join(dataDir, "secrets", "node-tls", "cert.pem"))
	if err != nil {
		return "", err
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return "", fmt.Errorf("invalid management certificate")
	}
	return secure.Hash(block.Bytes), nil
}
