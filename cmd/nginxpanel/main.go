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
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"nginxpanel/internal/agent"
	"nginxpanel/internal/app"
	"nginxpanel/internal/launcher"
	"nginxpanel/internal/nginxconfig"
	"nginxpanel/internal/nginxcontainer"
	"nginxpanel/internal/nginxmodules"
	"nginxpanel/internal/nginxruntime"
	"nginxpanel/internal/panelruntime"
	"nginxpanel/internal/platform"
	"nginxpanel/internal/releases"
)

var version = "0.1.0-dev"

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, nil)))
	if err := run(); err != nil {
		if len(os.Args) > 1 && os.Args[1] == "nginx-runtime-status" {
			// systemd skips ExecCondition for 1..254, but treats 255 as a
			// failure. Only an explicit uninstalled record may skip Nginx.
			if errors.Is(err, nginxruntime.ErrNotInstalled) {
				os.Exit(1)
			}
			slog.Error("Nginx installation status failed", "error", err)
			os.Exit(255)
		}
		slog.Error("command failed", "error", err)
		os.Exit(1)
	}
}
func run() error {
	if len(os.Args) < 2 {
		return errors.New("usage: nginxpanel <dev|init|serve|agent|launcher|panel-runtime-bind|panel-runtime-verify|panel-runtime-status|panel-runtime-compose|launcher-status|launcher-operation|launcher-restart|nginx-container-bind|nginx-container-verify|nginx-container-status|nginx-container-launch|nginx-init|nginx-runtime|nginx-runtime-status|component-path|component-bind|component-install|nginx-install-worker|nginx-install-probe|doctor|version|release-verify|release-prepare|release-check|release-fetch|release-images>")
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
	panelBinary := flags.String("panel-binary", "", "locally root-approved panel binary for persistent bootstrap")
	launcherBinary := flags.String("launcher-binary", "", "exact fixed-image launcher binary approved on the host")
	panelImage := flags.String("panel-image", "", "explicit immutable panel image reference with sha256 digest")
	panelGID := flags.Int("panel-gid", -1, "dedicated panel primary group")
	ipcGID := flags.Int("ipc-gid", -1, "host Agent socket group")
	panelRuntime := flags.String("panel-runtime", "native", "serve deployment: native or docker")
	launcherOperation := flags.String("launcher-operation", "", "fixed launcher operation UUID")
	launcherBoot := flags.String("launcher-boot", "", "observed launcher boot UUID")
	launcherRelease := flags.String("launcher-release", "", "exact root-approved current panel release digest")
	allowedUID := flags.Int("allowed-uid", -1, "authorized Web process UID (required for production agent)")
	nginxBinary := flags.String("nginx-binary", "", "root-approved Nginx executable (enables execution in the agent)")
	nginxBinding := flags.Bool("nginx-binding", false, "use the immutable native Nginx installation binding")
	nginxContainer := flags.Bool("nginx-container", false, "use the immutable fixed-image Nginx container binding")
	nginxImage := flags.String("nginx-image", "", "already-local fixed Nginx image reference with sha256 digest")
	nginxUninstalled := flags.Bool("nginx-uninstalled", false, "register an explicitly uninstalled native Nginx slot (component-bind only)")
	installOperation := flags.String("install-operation", "", "durable native Nginx installation UUID")
	installMaintenance := flags.String("maintenance-id", "", "held maintenance session UUID for installation")
	installEpoch := flags.String("maintenance-epoch", "", "confirmed root maintenance epoch")
	installStart := flags.Bool("install-start", false, "start the newly installed dedicated Nginx")
	installEnable := flags.Bool("install-enable", false, "enable the dedicated Nginx service on boot")
	installResume := flags.Bool("resume-install", false, "resume the original installation after checking its receipt")
	installAbort := flags.Bool("abort-install", false, "cancel the original installation only before binding publication")
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
	releaseManifestSHA := flags.String("release-manifest-sha256", "", "expected authenticated manifest digest for image admission")
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
	runtimeFlags := map[string]map[string]bool{
		"launcher":               {"data-dir": true},
		"panel-runtime-bind":     {"data-dir": true, "panel-binary": true, "web-dir": true, "launcher-binary": true, "panel-image": true, "listen": true, "allowed-uid": true, "panel-gid": true, "ipc-gid": true, "release-trust": true, "release-manifest": true, "release-manifest-sha256": true, "release-signature": true, "release-prerelease": true},
		"panel-runtime-verify":   {"data-dir": true, "panel-binary": true, "web-dir": true, "launcher-binary": true, "panel-image": true, "release-trust": true, "release-manifest": true, "release-manifest-sha256": true, "release-signature": true, "release-prerelease": true},
		"panel-runtime-status":   {"data-dir": true},
		"panel-runtime-compose":  {"data-dir": true},
		"launcher-status":        {"data-dir": true},
		"launcher-operation":     {"data-dir": true, "launcher-operation": true},
		"launcher-restart":       {"data-dir": true, "launcher-operation": true, "launcher-boot": true, "launcher-release": true},
		"nginx-container-bind":   {"data-dir": true, "nginx-image": true, "launcher-binary": true, "nginx-user": true, "release-trust": true, "release-manifest": true, "release-manifest-sha256": true, "release-signature": true, "release-prerelease": true},
		"nginx-container-verify": {"data-dir": true, "nginx-image": true, "launcher-binary": true, "release-trust": true, "release-manifest": true, "release-manifest-sha256": true, "release-signature": true, "release-prerelease": true},
		"nginx-container-status": {"data-dir": true},
		"nginx-container-launch": {"data-dir": true},
		"release-images":         {"release-trust": true, "release-manifest": true, "release-signature": true, "release-prerelease": true},
	}
	var invalidFlag string
	flags.Visit(func(f *flag.Flag) {
		if allowed, ok := runtimeFlags[command]; ok && !allowed[f.Name] {
			invalidFlag = f.Name
		}
		if f.Name == "panel-runtime" && command != "serve" {
			invalidFlag = f.Name
		}
		switch f.Name {
		case "launcher-binary":
			if command != "panel-runtime-bind" && command != "nginx-container-bind" && command != "panel-runtime-verify" && command != "nginx-container-verify" {
				invalidFlag = f.Name
			}
		case "nginx-image":
			if command != "nginx-container-bind" && command != "nginx-container-verify" {
				invalidFlag = f.Name
			}
		case "nginx-container":
			if command != "agent" && command != "nginx-init" {
				invalidFlag = f.Name
			}
		case "panel-binary", "panel-image", "panel-gid", "ipc-gid":
			if command != "panel-runtime-bind" && command != "panel-runtime-verify" {
				invalidFlag = f.Name
			}
		case "launcher-boot", "launcher-release":
			if command != "launcher-restart" {
				invalidFlag = f.Name
			}
		case "launcher-operation":
			if command != "launcher-restart" && command != "launcher-operation" {
				invalidFlag = f.Name
			}
		case "release-manifest-sha256":
			if command != "panel-runtime-bind" && command != "panel-runtime-verify" && command != "nginx-container-bind" && command != "nginx-container-verify" {
				invalidFlag = f.Name
			}
		}
	})
	if invalidFlag != "" {
		return fmt.Errorf("%s does not accept --%s", command, invalidFlag)
	}
	if *nginxUninstalled && command != "component-bind" {
		return errors.New("nginx-uninstalled is only valid for component-bind")
	}
	if command == "component-install" && *moduleFile == "" {
		*moduleFile = "/etc/nginxpanel/nginx-modules.json"
	}
	if command != "component-install" && ((command != "nginx-install-worker" && *installOperation != "") || *installMaintenance != "" || *installEpoch != "" || *installStart || *installEnable || *installResume || *installAbort) {
		return errors.New("installation options are only valid for component-install")
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
	var containerRuntime *nginxcontainer.Runtime
	if *nginxContainer {
		if *nginxBinding || *nginxBinary != "" || *devAgent || *releasePlan != "" || *releaseSelect != "" || len(catalog) != 0 {
			return errors.New("Nginx 容器不能混用原生运行或模块选择")
		}
		binding, err := nginxcontainer.Read(absDir)
		if err != nil {
			return err
		}
		containerRuntime = &nginxcontainer.Runtime{Binding: binding}
		installation = binding.Installation()
	}
	if *nginxBinding {
		if (command != "agent" && command != "nginx-init") || *nginxBinary != "" || *devAgent || *releasePlan != "" || *releaseSelect != "" {
			return errors.New("nginx-binding requires a native agent or initializer without another binary selection")
		}
		call, cancel := context.WithTimeout(ctx, 2*time.Minute)
		binding, info, e := nginxruntime.Selection(call, absDir)
		cancel()
		if e != nil {
			return e
		}
		if info == nil && command == "nginx-init" {
			return nginxruntime.ErrNotInstalled
		}
		*nginxBinary = binding.Binary
		installation = info
	}
	switch command {
	case "nginx-container-verify":
		out, err := nginxcontainer.VerifySource(ctx, nginxcontainer.BindInput{DataDir: absDir, Image: *nginxImage, LauncherBinary: *launcherBinary,
			Signature: releases.ImageInput{TrustPath: *releaseTrust, ManifestPath: *releaseManifest, SignaturePath: *releaseSignature, AllowPrerelease: *releasePrerelease, ExpectedManifestSHA256: *releaseManifestSHA}})
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(out)
	case "nginx-container-bind":
		identity, err := user.Lookup(*nginxUser)
		if err != nil {
			return err
		}
		uid, err := strconv.Atoi(identity.Uid)
		if err != nil {
			return err
		}
		gid, err := strconv.Atoi(identity.Gid)
		if err != nil {
			return err
		}
		out, err := nginxcontainer.Bind(ctx, nginxcontainer.BindInput{DataDir: absDir, Image: *nginxImage, LauncherBinary: *launcherBinary, UID: uid, GID: gid,
			Signature: releases.ImageInput{TrustPath: *releaseTrust, ManifestPath: *releaseManifest, SignaturePath: *releaseSignature, AllowPrerelease: *releasePrerelease, ExpectedManifestSHA256: *releaseManifestSHA}})
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(out)
	case "nginx-container-status":
		out, err := nginxcontainer.Read(absDir)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(out)
	case "nginx-container-launch":
		return nginxcontainer.Launch(absDir)
	case "launcher":
		return launcher.Run(ctx, absDir)
	case "panel-runtime-bind", "panel-runtime-verify":
		input := panelruntime.BindInput{DataDir: absDir, Binary: *panelBinary, WebDir: *webDir, LauncherBinary: *launcherBinary, Listen: *listen, UID: *allowedUID, GID: *panelGID, IPCGID: *ipcGID, Image: *panelImage,
			Signature: releases.ImageInput{TrustPath: *releaseTrust, ManifestPath: *releaseManifest, SignaturePath: *releaseSignature, AllowPrerelease: *releasePrerelease, ExpectedManifestSHA256: *releaseManifestSHA}}
		if command == "panel-runtime-verify" {
			out, err := panelruntime.VerifySource(ctx, input)
			if err != nil {
				return err
			}
			return json.NewEncoder(os.Stdout).Encode(out)
		}
		out, err := panelruntime.Bind(ctx, input)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(out)
	case "panel-runtime-status":
		out, err := panelruntime.Read(absDir)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(out)
	case "panel-runtime-compose":
		return panelruntime.WriteCompose(os.Stdout, absDir)
	case "launcher-status":
		out, err := (launcher.Client{DataDir: absDir}).Status(ctx)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(out)
	case "launcher-operation":
		out, err := (launcher.Client{DataDir: absDir}).Operation(ctx, *launcherOperation)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(out)
	case "launcher-restart":
		out, err := (launcher.Client{DataDir: absDir}).Restart(ctx, launcher.Request{Protocol: launcher.Protocol, BootID: *launcherBoot, OperationID: *launcherOperation, ReleaseID: *launcherRelease})
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(out)
	case "nginx-install-worker":
		_, err := agent.RunNginxInstallation(ctx, absDir, *installOperation)
		return err
	case "component-install":
		if *nginxBinary != "" || *nginxBinding || *devAgent || *moduleFile != "/etc/nginxpanel/nginx-modules.json" {
			return errors.New("component-install only accepts a prepared signed native Nginx asset")
		}
		out, err := agent.InstallNginx(ctx, agent.NginxInstallOptions{
			OperationID: *installOperation, Epoch: *installEpoch, Resume: *installResume, Abort: *installAbort,
			Input: agent.NginxInstallInput{MaintenanceID: *installMaintenance, WorkerUser: *nginxUser, Policy: policy, Modules: catalog, Start: *installStart, Enable: *installEnable,
				Source: nginxruntime.Input{DataDir: absDir, PlanID: *releasePlan, AssetID: *releaseSelect, TrustPath: *releaseTrust, Prerelease: *releasePrerelease}},
		})
		if out.OperationID != "" {
			if e := json.NewEncoder(os.Stdout).Encode(out); e != nil {
				return e
			}
		}
		return err
	case "nginx-install-probe":
		call, cancel := context.WithTimeout(ctx, 6*time.Second)
		defer cancel()
		out, err := agent.InstallationProbe(call, absDir)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(out)
	case "component-path", "component-bind":
		call, cancel := context.WithTimeout(ctx, 2*time.Minute)
		defer cancel()
		in := nginxruntime.Input{DataDir: absDir, Binary: *nginxBinary, PlanID: *releasePlan, AssetID: *releaseSelect, TrustPath: *releaseTrust, Prerelease: *releasePrerelease, Uninstalled: *nginxUninstalled}
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
	case "nginx-runtime", "nginx-runtime-status":
		if *nginxBinary != "" || *releasePlan != "" || *releaseSelect != "" || *devAgent {
			return errors.New("nginx-runtime only uses the installed local binding")
		}
		call, cancel := context.WithTimeout(ctx, 2*time.Minute)
		defer cancel()
		if command == "nginx-runtime-status" {
			_, _, err := nginxruntime.Read(call, absDir)
			return err
		}
		return nginxruntime.Launch(call, absDir, *nginxRuntimeCheck)
	case "release-verify", "release-prepare", "release-check", "release-fetch", "release-images":
		if *releaseSelect == "" && command != "release-images" {
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
		if command == "release-images" {
			if *releaseSelect != "" || *releaseAssets != "" || *releaseToken != "" || *releaseTag != "" {
				return errors.New("release-images only accepts the offline manifest, signature and local trust")
			}
			result, err := releases.VerifyImages(releases.Input{TrustPath: *releaseTrust, ManifestPath: *releaseManifest, SignaturePath: *releaseSignature, AllowPrerelease: *releasePrerelease, Host: target, Receiver: receiver})
			if err != nil {
				return err
			}
			return json.NewEncoder(os.Stdout).Encode(result)
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
		if *panelRuntime != "native" && *panelRuntime != "docker" {
			return errors.New("panel-runtime must be native or docker")
		}
		o := app.Defaults(absDir, false)
		o.PanelRuntime = *panelRuntime
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
		if *nginxBinary == "" && containerRuntime == nil {
			return errors.New("nginx-init requires a native binary or fixed container binding")
		}
		engine := &agent.Nginx{DataDir: absDir, Binary: *nginxBinary, WorkerUser: *nginxUser, LogOwner: *logOwner, Policy: policy, Modules: catalog, Container: containerRuntime, Journal: &agent.Journal{Dir: filepath.Join(absDir, "agent", "operations")}}
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
		if *nginxBinary != "" || containerRuntime != nil {
			engine = &agent.Nginx{DataDir: absDir, Binary: *nginxBinary, WorkerUser: *nginxUser, LogOwner: *logOwner, Policy: policy, Modules: catalog, Container: containerRuntime, Journal: journal}
		}
		return (&agent.Server{Socket: path, AllowedUID: uint32(uid), Policy: policy, Journal: journal, Nginx: engine, Dev: *devAgent, MetricsScope: *metricsScope, DataDir: absDir, DNSOwner: *dnsOwner, DNSScope: *dnsScope, ComponentScope: *componentScope, MaintenanceScope: *maintenanceScope, ReleaseTrust: *releaseTrust, ReleaseToken: *releaseToken, Installation: installation}).Run(ctx)
	default:
		return fmt.Errorf("unknown subcommand %q", command)
	}
}
