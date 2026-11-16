package main

import (
	"context"
	"errors"
	"flag"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
	"nginxpanel/internal/agent"
	"nginxpanel/internal/panelruntime"
)

// Every installed entry resolves the approved current program before opening
// state, including an explicitly invoked older executable.
func selectCoreExecutable(data, command string, flags []string) error {
	if os.Geteuid() != 0 {
		return errors.New("核心服务需要宿主机 root 权限")
	}
	s, err := panelruntime.Read(data)
	if err != nil {
		return err
	}
	if s.Deployment.Mode != "native" || s.Deployment.UID != 0 || s.Deployment.GID != 0 {
		return errors.New("核心服务未登记为宿主机单服务")
	}
	binary := filepath.Join(s.Directory, "nginxpanel")
	live, err := os.Stat("/proc/self/exe")
	if err != nil {
		return err
	}
	target, err := os.Stat(binary)
	if err != nil {
		return err
	}
	if os.SameFile(live, target) {
		return nil
	}
	return unix.Exec(binary, append([]string{binary, command}, flags...), os.Environ())
}

func runCoreUpdateCLI(ctx context.Context, args []string) error {
	f := flag.NewFlagSet("core-update-worker", flag.ContinueOnError)
	data := f.String("data-dir", "/srv/nginxpanel", "installed data directory")
	id := f.String("core-update", "", "registered update operation")
	if err := f.Parse(args); err != nil {
		return err
	}
	if f.NArg() != 0 {
		return errors.New("核心更新不接受额外参数")
	}
	if err := selectCoreExecutable(*data, "core-update-worker", args); err != nil {
		return err
	}
	return agent.RunCoreUpdate(ctx, *data, *id)
}
