package app

import (
	"context"
	"errors"
	"fmt"
	"time"

	"nginxpanel/internal/agent"
)

type coreServiceResult struct {
	name string
	err  error
}

// RunCore starts the privileged host Agent and management API from the same
// process and binary. The API is exposed only after the Agent socket responds.
func RunCore(ctx context.Context, o Options, host *agent.Server) error {
	if o.Dev || o.PanelRuntime != "native" || host == nil || host.Dev || host.AllowedUID != 0 ||
		host.Socket != o.Socket || host.DataDir != o.DataDir {
		return errors.New("production core must bind one root Agent and management service to the same data directory")
	}
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	agentDone := make(chan error, 1)
	go func() { agentDone <- host.Run(runCtx) }()
	client := agent.NewClient(o.Socket)
	ready := time.NewTimer(20 * time.Second)
	defer ready.Stop()
	probe := time.NewTicker(100 * time.Millisecond)
	defer probe.Stop()
	for {
		call, stop := context.WithTimeout(runCtx, time.Second)
		_, probeErr := client.MaintenanceStatus(call)
		stop()
		if probeErr == nil {
			break
		}
		select {
		case err := <-agentDone:
			cancel()
			if ctx.Err() != nil {
				return nil
			}
			if err == nil {
				return errors.New("host Agent stopped before becoming ready")
			}
			return fmt.Errorf("host Agent failed before becoming ready: %w", err)
		case <-runCtx.Done():
			cancel()
			<-agentDone
			if ctx.Err() != nil {
				return nil
			}
			return runCtx.Err()
		case <-ready.C:
			cancel()
			<-agentDone
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("host Agent did not become ready: %w", probeErr)
		case <-probe.C:
		}
	}
	managementDone := make(chan error, 1)
	go func() { managementDone <- Run(runCtx, o) }()
	var first coreServiceResult
	select {
	case err := <-agentDone:
		first = coreServiceResult{name: "agent", err: err}
	case err := <-managementDone:
		first = coreServiceResult{name: "management", err: err}
	case <-ctx.Done():
		cancel()
		agentErr, managementErr := <-agentDone, <-managementDone
		return joinedCoreErrors(ctx, coreServiceResult{name: "agent", err: agentErr}, coreServiceResult{name: "management", err: managementErr})
	}
	if ctx.Err() == nil && first.err == nil {
		first.err = errors.New("service stopped unexpectedly")
	}
	cancel()
	var second coreServiceResult
	if first.name == "agent" {
		second = coreServiceResult{name: "management", err: <-managementDone}
	} else {
		second = coreServiceResult{name: "agent", err: <-agentDone}
	}
	return joinedCoreErrors(ctx, first, second)
}

func joinedCoreErrors(ctx context.Context, results ...coreServiceResult) error {
	var errs []error
	for _, result := range results {
		if result.err == nil || ctx.Err() != nil && (errors.Is(result.err, context.Canceled) || errors.Is(result.err, context.DeadlineExceeded)) {
			continue
		}
		errs = append(errs, fmt.Errorf("%s service: %w", result.name, result.err))
	}
	return errors.Join(errs...)
}
