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
	"runtime"
	"strings"
	"syscall"
	"time"

	"nginxpanel/internal/agent"
	"nginxpanel/internal/app"
	"nginxpanel/internal/nginxconfig"
	"nginxpanel/internal/nginxmodules"
	"nginxpanel/internal/nginxruntime"
	"nginxpanel/internal/platform"
	"nginxpanel/internal/releases"
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
		return errors.New("usage: nginxpanel <dev|init|serve|agent|nginx-init|nginx-runtime|component-path|component-bind|doctor|version|release-verify|release-prepare|release-check|release-fetch>")
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
	nginxBinding := flags.Bool("nginx-binding", false, "use the immutable native Nginx installation binding")
	nginxRuntimeCheck := flags.Bool("nginx-runtime-check", false, "only validate the bound native Nginx configuration")
	logOwner := flags.String("nginx-log-owner", "unconfirmed", "unique managed log rotation owner: agent, external, or unconfirmed")
	metricsScope := flags.String("metrics-scope", "unconfirmed", "host metrics scope: host or unconfirmed")
	componentScope := flags.String("component-scope", "unconfirmed", "native component scope: host or unconfirmed")
	maintenanceScope := flags.String("maintenance-scope", "unconfirmed", "host configuration maintenance scope: host or unconfirmed")
	dnsOwner := flags.String("dns-owner", "unconfirmed", "locally confirmed DNS owner: regular-file, networkmanager, networkd or unconfirmed")
	dnsScope := flags.String("dns-scope", "unconfirmed", "DNS namespace: host or unconfirmed")
	nginxUser := flags.String("nginx-user", "nginxpanel-nginx", "dedicated Nginx worker account")
	moduleFile := flags.String("nginx-modules", "", "root-owned native module catalog shared by Web and agent")
	devAgent := flags.Bool("dev", false, "non-root read-only development agent")
	releaseTrust := flags.String("release-trust", "/etc/nginxpanel/release-trust.json", "root-owned publisher trust configuration")
	releaseManifest := flags.String("release-manifest", "", "root-owned signed release manifest")
	releaseSignature := flags.String("release-signature", "", "root-owned detached release signature")
	releaseAssets := flags.String("release-assets", "", "root-owned directory of offline release archives")
	releaseSelect := flags.String("release-select", "", "explicit comma-separated asset IDs")
	releasePlan := flags.String("release-plan", "", "exact immutable prepared release plan ID")
	releasePrerelease := flags.Bool("release-prerelease", false, "permit authenticated prerelease assets")
	releaseTag := flags.String("release-tag", "", "exact v-prefixed GitHub release tag; empty selects latest stable")
	releaseToken := flags.String("release-token-file", "", "root-owned 0600 GitHub read-only token file; public releases need no token")
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
	if *nginxRuntimeCheck && command != "nginx-runtime" {
		return errors.New("nginx-runtime-check is only valid for nginx-runtime")
	}
	var installation *nginxruntime.Installation
	if *nginxBinding {
		if (command != "agent" && command != "nginx-init") || *nginxBinary != "" || *devAgent || *releasePlan != "" || *releaseSelect != "" {
			return errors.New("nginx-binding requires a native agent or initializer without another binary selection")
		}
		call, cancel := context.WithTimeout(ctx, 2*time.Minute)
		binding, info, e := nginxruntime.Read(call, absDir)
		cancel()
		if e != nil {
			return e
		}
		*nginxBinary = binding.Binary
		installation = &info
	}
	switch command {
	case "component-path", "component-bind":
		call, cancel := context.WithTimeout(ctx, 2*time.Minute)
		defer cancel()
		in := nginxruntime.Input{DataDir: absDir, Binary: *nginxBinary, PlanID: *releasePlan, AssetID: *releaseSelect, TrustPath: *releaseTrust, Prerelease: *releasePrerelease}
		if command == "component-path" {
			binding, e := nginxruntime.Inspect(call, in)
			if e != nil {
				return e
			}
			_, e = fmt.Fprintln(os.Stdout, binding.Binary)
			return e
		}
		binding, e := nginxruntime.Bind(call, in)
		if e != nil {
			return e
		}
		return json.NewEncoder(os.Stdout).Encode(binding)
	case "nginx-runtime":
		if *nginxBinary != "" || *releasePlan != "" || *releaseSelect != "" || *devAgent {
			return errors.New("nginx-runtime only uses the installed local binding")
		}
		call, cancel := context.WithTimeout(ctx, 2*time.Minute)
		defer cancel()
		return nginxruntime.Launch(call, absDir, *nginxRuntimeCheck)
	case "release-verify", "release-prepare", "release-check", "release-fetch":
		if *releaseSelect == "" {
			return errors.New("release commands require --release-select")
		}
		host := platform.Detect()
		target := releases.Host{OS: runtime.GOOS, Architecture: runtime.GOARCH, Distribution: host.OS, Version: host.Version}
		receiver := releases.Receiver{APIMajor: 1, AgentProtocol: agent.Protocol, Launcher: releases.LauncherVersion}
		if command == "release-check" || command == "release-fetch" {
			if *releaseManifest != "" || *releaseSignature != "" || *releaseAssets != "" {
				return errors.New("online release commands do not accept offline file arguments")
			}
			result, err := releases.Online(ctx, releases.OnlineInput{TrustPath: *releaseTrust, TokenPath: *releaseToken, Tag: *releaseTag, Assets: strings.Split(*releaseSelect, ","), AllowPrerelease: *releasePrerelease, Prepare: command == "release-fetch", Host: target, Receiver: receiver})
			if err != nil {
				return err
			}
			return json.NewEncoder(os.Stdout).Encode(result)
		}
		if *releaseManifest == "" || *releaseSignature == "" {
			return errors.New("offline release commands require --release-manifest and --release-signature")
		}
		verified, err := releases.Verify(releases.Input{TrustPath: *releaseTrust, ManifestPath: *releaseManifest, SignaturePath: *releaseSignature, Assets: strings.Split(*releaseSelect, ","), AllowPrerelease: *releasePrerelease, Host: target, Receiver: receiver})
		if err != nil {
			return err
		}
		if command == "release-verify" {
			return json.NewEncoder(os.Stdout).Encode(verified.Plan())
		}
		prepared, err := releases.Prepare(ctx, verified, *releaseAssets)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(prepared)
	case "version":
		return json.NewEncoder(os.Stdout).Encode(map[string]any{"version": version, "agent_protocol": agent.Protocol, "parser_version": nginxconfig.ParserVersion, "launcher_version": releases.LauncherVersion})
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
		if *maintenanceScope != "host" && *maintenanceScope != "unconfirmed" {
			return errors.New("maintenance-scope must be host or unconfirmed")
		}
		if *componentScope != "host" && *componentScope != "unconfirmed" {
			return errors.New("component-scope must be host or unconfirmed")
		}
		if (*dnsOwner != "unconfirmed" && *dnsOwner != "regular-file" && *dnsOwner != "networkmanager" && *dnsOwner != "networkd") || (*dnsScope != "unconfirmed" && *dnsScope != "host") {
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
		return (&agent.Server{Socket: path, AllowedUID: uint32(uid), Policy: policy, Journal: journal, Nginx: engine, Dev: *devAgent, MetricsScope: *metricsScope, DataDir: absDir, DNSOwner: *dnsOwner, DNSScope: *dnsScope, ComponentScope: *componentScope, MaintenanceScope: *maintenanceScope, ReleaseTrust: *releaseTrust, ReleaseToken: *releaseToken, Installation: installation}).Run(ctx)
	default:
		return fmt.Errorf("unknown subcommand %q", command)
	}
}
