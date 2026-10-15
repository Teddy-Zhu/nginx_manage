package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"nginxpanel/internal/agent"
	"nginxpanel/internal/app"
	"nginxpanel/internal/nginxconfig"
	"nginxpanel/internal/nginxmodules"
	"nginxpanel/internal/platform"
)

var version = "0.1.0-dev"

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, nil)))
	if err := run(); err != nil {
		slog.Error("command failed", "error", err)
		os.Exit(1)
	}
}
func run() error {
	if len(os.Args) < 2 {
		return errors.New("usage: nginxpanel <dev|init|serve|agent|nginx-init|doctor|version>")
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	command := os.Args[1]
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	defaultDir := os.Getenv("NGINXPANEL_DATA_DIR")
	if defaultDir == "" {
		defaultDir = "/srv/nginxpanel"
	}
	if command == "dev" {
		defaultDir = ".local"
	}
	dataDir := flags.String("data-dir", defaultDir, "node data directory")
	listen := flags.String("listen", "", "management listener (loopback only)")
	socket := flags.String("agent-socket", "", "local agent Unix socket")
	webDir := flags.String("web-dir", "web/dist", "built frontend directory")
	allowedUID := flags.Int("allowed-uid", -1, "authorized Web process UID (required for production agent)")
	nginxBinary := flags.String("nginx-binary", "", "root-approved Nginx executable (enables execution in the agent)")
	logOwner := flags.String("nginx-log-owner", "unconfirmed", "unique managed log rotation owner: agent, external, or unconfirmed")
	metricsScope := flags.String("metrics-scope", "unconfirmed", "host metrics scope: host or unconfirmed")
	dnsOwner := flags.String("dns-owner", "unconfirmed", "locally confirmed DNS owner: regular-file or unconfirmed")
	dnsScope := flags.String("dns-scope", "unconfirmed", "DNS namespace: host or unconfirmed")
	nginxUser := flags.String("nginx-user", "nginxpanel-nginx", "dedicated Nginx worker account")
	moduleFile := flags.String("nginx-modules", "", "root-owned native module catalog shared by Web and agent")
	devAgent := flags.Bool("dev", false, "non-root read-only development agent")
	if err := flags.Parse(os.Args[2:]); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	catalog, err := nginxmodules.ReadCatalog(*moduleFile)
	if err != nil {
		return fmt.Errorf("read native module catalog: %w", err)
	}
	policy := nginxconfig.DefaultPolicy()
	policy.ModulePaths = nginxmodules.Paths(catalog)
	absDir, err := filepath.Abs(*dataDir)
	if err != nil {
		return err
	}
	switch command {
	case "version":
		return json.NewEncoder(os.Stdout).Encode(map[string]any{"version": version, "agent_protocol": agent.Protocol, "parser_version": nginxconfig.ParserVersion})
	case "doctor":
		return json.NewEncoder(os.Stdout).Encode(platform.Detect())
	case "init", "dev":
		if command == "dev" && os.Geteuid() == 0 {
			return errors.New("development mode must not run as root")
		}
		path, err := app.Init(ctx, absDir)
		if err != nil {
			return err
		}
		if path != "" {
			fmt.Fprintf(os.Stderr, "一次性引导令牌文件：%s\n", path)
		}
		if command == "init" {
			fingerprint, err := app.Fingerprint(absDir)
			if err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "管理 TLS SHA-256：%s\n", fingerprint)
			return nil
		}
		o := app.Defaults(absDir, true)
		o.Policy = policy
		o.Version = version
		o.WebDir = *webDir
		if *listen != "" {
			o.Listen = *listen
		}
		if *socket != "" {
			o.Socket = *socket
		}
		return app.Run(ctx, o)
	case "serve":
		o := app.Defaults(absDir, false)
		o.Policy = policy
		o.Version = version
		o.WebDir = *webDir
		if *listen != "" {
			o.Listen = *listen
		}
		if *socket != "" {
			o.Socket = *socket
		}
		return app.Run(ctx, o)
	case "nginx-init":
		if *nginxBinary == "" {
			return errors.New("nginx-init requires --nginx-binary")
		}
		engine := &agent.Nginx{DataDir: absDir, Binary: *nginxBinary, WorkerUser: *nginxUser, LogOwner: *logOwner, Policy: policy, Modules: catalog, Journal: &agent.Journal{Dir: filepath.Join(absDir, "agent", "operations")}}
		if err := engine.Open(); err != nil {
			return err
		}
		defer engine.Close()
		return engine.Initialize()
	case "agent":
		if (*dnsOwner != "unconfirmed" && *dnsOwner != "regular-file") || (*dnsScope != "unconfirmed" && *dnsScope != "host") {
			return errors.New("unsupported DNS owner or namespace")
		}
		if *metricsScope != "host" && *metricsScope != "unconfirmed" {
			return errors.New("metrics-scope must be host or unconfirmed")
		}
		uid := *allowedUID
		if *devAgent && uid < 0 {
			uid = os.Getuid()
		}
		if uid < 0 {
			return errors.New("agent requires --allowed-uid")
		}
		path := app.SocketPath(absDir)
		if *socket != "" {
			path = *socket
		}
		journal := &agent.Journal{Dir: filepath.Join(absDir, "agent", "operations")}
		var engine *agent.Nginx
		if *nginxBinary != "" {
			engine = &agent.Nginx{DataDir: absDir, Binary: *nginxBinary, WorkerUser: *nginxUser, LogOwner: *logOwner, Policy: policy, Modules: catalog, Journal: journal}
		}
		return (&agent.Server{Socket: path, AllowedUID: uint32(uid), Policy: policy, Journal: journal, Nginx: engine, Dev: *devAgent, MetricsScope: *metricsScope, DataDir: absDir, DNSOwner: *dnsOwner, DNSScope: *dnsScope}).Run(ctx)
	default:
		return fmt.Errorf("unknown subcommand %q", command)
	}
}
