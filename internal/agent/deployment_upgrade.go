package agent

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"time"

	"nginxpanel/internal/panelruntime"
	"nginxpanel/internal/panelupdates"
	"nginxpanel/internal/secure"
)

// QueueDeploymentUpgrade uses the installed independent update service. A root
// rescue is a new bounded authorization for the original immutable transaction.
func QueueDeploymentUpgrade(ctx context.Context, data, id, plan, maintenanceID, epoch string, prerelease, allowDowntime, resume bool) (Record, error) {
	var zero Record
	if os.Geteuid() != 0 || !validID(id) {
		return zero, errors.New("协调部署需要本机 root 和原操作 UUID")
	}
	if _, err := panelruntime.Root(data); err != nil {
		return zero, err
	}
	s := &Server{DataDir: data, Journal: &Journal{Dir: filepath.Join(data, "agent", "operations")}, ReleaseTrust: "/etc/nginxpanel/release-trust.json", ComponentScope: "host", MaintenanceScope: "host"}
	in := panelupdates.Input{CoordinateAgent: true, AllowDowntime: allowDowntime, MaintenanceID: maintenanceID, PlanID: plan, Prerelease: prerelease}
	sequence, command := 1, "update"
	if resume {
		r, err := panelUpdateRecord(data, id)
		if err != nil {
			return r, err
		}
		if !r.PanelUpdate.Intent.Input.CoordinateAgent || len(r.PanelUpdate.Authorizations) == 0 {
			return r, errors.New("此操作不是托管协调部署事务")
		}
		if panelUpdateFinalized(r) {
			_, err = s.readPanelUpdate(ctx, id)
			return r, err
		}
		in = panelUpdateAPIInput(r.PanelUpdate.Intent.Input)
		sequence, command = len(r.PanelUpdate.Authorizations)+1, "resume"
		maintenanceID = in.MaintenanceID
	}
	if err := in.Validate(); err != nil {
		return zero, err
	}
	grant, err := s.Journal.Get(maintenanceID)
	if err != nil {
		return zero, err
	}
	if epoch == "" {
		epoch = grant.MaintenanceEpoch
	}
	req := panelupdates.Request{Actor: "local-root", RequestID: secure.ID(), Protocol: Protocol, OperationID: id, Input: in, Sequence: sequence, Command: command, Epoch: epoch, AuthorizationUntil: time.Now().Unix() + 300}
	if _, err = s.queuePanelUpdate(ctx, req, resume); err != nil {
		return zero, err
	}
	return panelUpdateRecord(data, id)
}
