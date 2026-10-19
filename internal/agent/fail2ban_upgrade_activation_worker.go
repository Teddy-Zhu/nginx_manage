package agent

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"time"
)

// The host Agent continues only an already sent root operation. It cannot
// invent a start authorization or replace a missing original audit.
func (s *Server) startFail2banUpgradeActivation(ctx context.Context, gate *maintenanceGate) func() {
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
			i, f, err := pendingFail2banUpgradeActivation(s.DataDir)
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
				slog.Warn("Fail2ban 升级启动续办未确认", "error", err)
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
