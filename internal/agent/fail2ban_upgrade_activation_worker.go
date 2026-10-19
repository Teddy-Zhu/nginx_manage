package agent

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"time"
)

// The host Agent continues only an already sent root operation. It cannot
// invent a stop/start authorization or replace a missing original audit.
func (s *Server) startFail2banUpgradeRecovery(ctx context.Context, gate *maintenanceGate) func() {
	if s.Dev || os.Geteuid() != 0 || s.MetricsScope != "host" || s.MaintenanceScope != "host" || (&HostDNS{Scope: "host"}).hostScopeReason() != "" {
		return func() {}
	}
	run, stop := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		lastError := ""
		for {
			err := s.resumeFail2banUpgradeRestore(run, gate)
			if err == nil {
				err = s.resumeFail2banUpgradeQuiesce(run, gate)
			}
			var i *fail2banUpgradeActivationIntent
			var f fail2banUpgradeActivationFacts
			if err == nil {
				i, f, err = pendingFail2banUpgradeActivation(s.DataDir)
			}
			if err == nil && i != nil && (f.Execution || f.Stop != nil || f.Receipt != nil) {
				audit, e := (&Journal{Dir: filepath.Join(s.DataDir, "agent", "operations")}).Get(i.Request.OperationID)
				if e != nil {
					err = e
				} else if pendingFail2banUpgradeActivationRecord(audit, i.record(nil)) {
					leave, ok := gate.enter(true)
					if ok {
						call, cancel := context.WithTimeout(run, 3*time.Minute)
						_, err = ResumeFail2banUpgradeActivation(call, s.DataDir, "host", i.Request.OperationID)
						cancel()
						leave()
					}
				}
			}
			if err != nil && err.Error() != lastError {
				lastError = err.Error()
				slog.Warn("Fail2ban 升级续办未确认", "error", err)
			} else if err == nil {
				lastError = ""
			}
			select {
			case <-run.Done():
				return
			case <-ticker.C:
			}
		}
	}()
	return func() { stop(); <-done }
}

func (s *Server) resumeFail2banUpgradeQuiesce(ctx context.Context, gate *maintenanceGate) error {
	i, f, err := pendingFail2banUpgradeQuiesce(s.DataDir)
	if err != nil || i == nil || !f.Execution && f.Receipt == nil {
		return err
	}
	audit, err := (&Journal{Dir: filepath.Join(s.DataDir, "agent", "operations")}).Get(i.Request.OperationID)
	if err != nil {
		return err
	}
	if !pendingFail2banUpgradeQuiesceRecord(audit, i.record(nil)) {
		return nil
	}
	leave, ok := gate.enter(true)
	if !ok {
		return nil
	}
	defer leave()
	call, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	_, err = ResumeFail2banUpgradeQuiesce(call, s.DataDir, "host", i.Request.OperationID)
	return err
}
