package backup

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	"nginxpanel/internal/agent"
	"nginxpanel/internal/panelrecovery"
)

type RestoreRuntimeReply struct {
	Status agent.DisasterRuntimeStatus `json:"status"`
	Error  string                      `json:"error"`
}

// ApplyRestoration approves one fixed root intent and advances its existing
// Nginx operation. It never opens SQLite or starts the business process.
func ApplyRestoration(ctx context.Context, data, id string, in RestoreInput) (agent.DisasterRuntimeStatus, error) {
	unlock, _, err := lockAdoptionStore(data, false)
	if err != nil {
		return agent.DisasterRuntimeStatus{}, err
	}
	defer unlock()
	if !validID.MatchString(in.PlanID) || !validHash.MatchString(in.PlanSHA256) {
		return agent.DisasterRuntimeStatus{}, errors.New("运行应用须明确指定原计划标识和摘要")
	}
	return advanceRestorationRuntime(ctx, data, id, in, false)
}

func advanceRestorationRuntime(ctx context.Context, data, id string, in RestoreInput, rollback bool) (out agent.DisasterRuntimeStatus, err error) {
	if os.Geteuid() != 0 || !validID.MatchString(id) || !validID.MatchString(in.Epoch) || !validHash.MatchString(in.AdoptionSHA256) {
		return out, errors.New("恢复运行推进需要本机 root、原接入摘要和当前维护 epoch")
	}
	i, err := panelrecovery.ReadDisasterIntent(data, id)
	if err != nil {
		return out, err
	}
	if i.AdoptionSHA256 != in.AdoptionSHA256 || in.PlanID != "" && in.PlanID != i.PlanID || in.PlanSHA256 != "" && in.PlanSHA256 != i.PlanSHA256 {
		return out, errors.New("恢复运行推进指定了不同的原批准")
	}
	out, err = agent.DisasterRuntime(data, id)
	if err != nil {
		return out, err
	}
	if err = agent.AuthorizeDisasterRuntime(ctx, data, id, in.Epoch, rollback); err != nil {
		return out, err
	}
	raw, err := json.Marshal(agent.DisasterRuntimeRequest{Protocol: agent.Protocol, OperationID: id, PlanSHA256: i.PlanSHA256, Epoch: in.Epoch, Rollback: rollback})
	if err != nil {
		return out, err
	}
	var reply RestoreRuntimeReply
	if err = runPreparationHelper(ctx, data, "backup-restore-runtime-data", id, raw, nil, &reply); err != nil {
		return out, err
	}
	if reply.Error != "" {
		return out, errors.New(reply.Error)
	}
	if reply.Status.Restore.OperationID != id || reply.Status.Restore.RequestHash != i.SHA256() || reply.Status.Restore.Kind != "backup.restore" {
		return out, errors.New("恢复运行助手没有返回原恢复记录")
	}
	if reply.Status.Nginx != nil && (reply.Status.Nginx.OperationID != i.PlanID || reply.Status.Nginx.DisasterRestoreID != id || reply.Status.Nginx.RequestHash != i.NginxRequest.SHA256) {
		return out, errors.New("恢复运行助手返回了其他 Nginx 子操作")
	}
	if !rollback {
		if err = panelrecovery.CheckDisasterTarget(ctx, i, true); err != nil {
			return out, err
		}
	}
	return reply.Status, nil
}

// AdvanceRestorationAsPanel only contacts the fixed target socket. The root
// endpoint rechecks durable approval, writer fencing and the current grant.
func AdvanceRestorationAsPanel(ctx context.Context, data, id string, in agent.DisasterRuntimeRequest) RestoreRuntimeReply {
	if os.Geteuid() == 0 || in.OperationID != id || !validID.MatchString(id) || in.Protocol != agent.Protocol {
		return RestoreRuntimeReply{Error: "恢复运行助手身份无效"}
	}
	out, err := agent.NewClient(filepath.Join(data, "run", "agent", "agent.sock")).AdvanceDisasterRuntime(ctx, in)
	reply := RestoreRuntimeReply{Status: out}
	if err != nil {
		reply.Error = previewText(err.Error(), 1024)
	}
	return reply
}
