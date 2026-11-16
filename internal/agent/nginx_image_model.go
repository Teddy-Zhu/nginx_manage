package agent

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"nginxpanel/internal/protocol"
	"os"
	"path/filepath"
	"slices"
	"time"

	"nginxpanel/internal/dockerapi"
	"nginxpanel/internal/imageupdates"
	"nginxpanel/internal/nginxcontainer"
	"nginxpanel/internal/panelruntime"
	"nginxpanel/internal/releases"
	"nginxpanel/internal/secure"
)

const nginxImageKind = "nginx.image"
const nginxImageTemplate = "nginxpanel-nginx-image@.service"
const nginxImageRecordLimit = 256 << 10
const nginxImageIntentLimit = 144 << 10

type NginxImageInput struct {
	Stage         panelruntime.StageInput `json:"stage"`
	Signature     releases.ImageInput     `json:"signature"`
	Image         string                  `json:"image"`
	MaintenanceID string                  `json:"maintenance_id"`
	AllowDowntime bool                    `json:"allow_downtime"`
}
type NginxImageIntent struct {
	Input             NginxImageInput          `json:"input"`
	Epoch             string                   `json:"epoch"`
	Before            nginxcontainer.Binding   `json:"before"`
	Target            nginxcontainer.Binding   `json:"target"`
	Panel             panelruntime.Deployment  `json:"panel"`
	PanelID           string                   `json:"panel_id"`
	ApprovalSHA256    string                   `json:"approval_sha256"`
	Agent             AgentProgram             `json:"agent"`
	AgentProcess      AgentProcess             `json:"agent_process"`
	AgentUnit         string                   `json:"agent_unit"`
	WorkerUnit        string                   `json:"worker_unit"`
	Directory         string                   `json:"directory"`
	PublicationSHA256 string                   `json:"publication_sha256"`
	RevisionID        string                   `json:"revision_id"`
	DeploymentID      string                   `json:"deployment_id"`
	BeforeCompose     []byte                   `json:"before_compose"`
	TargetCompose     []byte                   `json:"target_compose"`
	TargetLabels      map[string]string        `json:"target_labels"`
	Container         nginxcontainer.Container `json:"container"`
	CreatedAt         int64                    `json:"created_at"`
	Deadline          int64                    `json:"deadline"`
}
type NginxImageConfirmation struct {
	ConfirmedAt int64        `json:"confirmed_at"`
	ContainerID string       `json:"container_id"`
	ImageID     string       `json:"image_id"`
	NginxPID    int          `json:"nginx_pid"`
	Agent       AgentProcess `json:"agent"`
	ReadyEpoch  string       `json:"ready_epoch"`
	Runtime     NginxState   `json:"runtime"`
}
type NginxImageOperation struct {
	Authorizations          []ImageAuthorization     `json:"authorizations,omitempty"`
	Intent                  NginxImageIntent         `json:"intent"`
	Rollback                bool                     `json:"rollback"`
	Failure                 string                   `json:"failure"`
	TargetContainerID       string                   `json:"target_container_id"`
	RollbackContainerID     string                   `json:"rollback_container_id"`
	TargetGeneration        *nginxcontainer.Instance `json:"target_generation,omitempty"`
	RollbackGeneration      *nginxcontainer.Instance `json:"rollback_generation,omitempty"`
	ResumedOriginal         *nginxcontainer.Instance `json:"resumed_original,omitempty"`
	CheckCreateSubmitted    bool                     `json:"check_create_submitted"`
	TargetCreateSubmitted   bool                     `json:"target_create_submitted"`
	RollbackCreateSubmitted bool                     `json:"rollback_create_submitted"`
	TargetStartSubmitted    bool                     `json:"target_start_submitted"`
	RollbackStartSubmitted  bool                     `json:"rollback_start_submitted"`
	CheckContainerID        string                   `json:"check_container_id"`
	CheckSubmitted          bool                     `json:"check_submitted"`
	CheckPassed             bool                     `json:"check_passed"`
	CheckExitCode           *int                     `json:"check_exit_code,omitempty"`
	CheckFinishedAt         string                   `json:"check_finished_at"`
	Touched                 bool                     `json:"touched"`
	Confirmation            *NginxImageConfirmation  `json:"confirmation,omitempty"`
}

func nginxImageTerminal(r Record) bool {
	return slices.Contains([]string{"succeeded", "rolled_back", "failed"}, r.State)
}
func nginxImageHash(id string, i NginxImageIntent) string {
	raw, _ := json.Marshal(struct {
		Protocol int
		ID       string
		Intent   NginxImageIntent
	}{protocol.Journal, id, i})
	return secure.Hash(raw)
}
func validNginxImage(r Record) error {
	p := r.NginxImage
	if p == nil || r.Kind != nginxImageKind || !validID(r.OperationID) || !validID(r.MaintenanceEpoch) {
		return errors.New("Nginx 镜像事务身份无效")
	}
	i := p.Intent
	if err := validImageAuthorizations(p.Authorizations, r.OperationID, nginxImageAPIInput(i.Input), i.Epoch, r.MaintenanceEpoch, nginxImageTerminal(r)); err != nil {
		return err
	}
	if raw, err := json.Marshal(i); err != nil || len(raw) > nginxImageIntentLimit {
		return errors.New("Nginx 镜像意图超过保留预算")
	}
	in := i.Input
	if !in.AllowDowntime || !validID(in.MaintenanceID) || in.MaintenanceID == r.OperationID || !validID(i.Epoch) || in.Stage.DataDir != i.Before.DataDir || in.Stage.TrustPath != "/etc/nginxpanel/release-trust.json" || in.Signature.TrustPath != in.Stage.TrustPath || in.Signature.AllowPrerelease != in.Stage.AllowPrerelease || !panelSelectionDigest.MatchString(in.Stage.PlanID) || !panelSelectionDigest.MatchString(in.Signature.ExpectedManifestSHA256) || !nginxcontainer.SameIdentity(i.Before, i.Target) || i.Before.ImageID == i.Target.ImageID || i.Target.Image != in.Image || i.Target.SignedImage.ManifestSHA256 != in.Signature.ExpectedManifestSHA256 || i.Panel.Mode != "native" || i.Panel.DataDir != in.Stage.DataDir || !panelSelectionDigest.MatchString(i.PanelID) || !panelSelectionDigest.MatchString(i.ApprovalSHA256) || !panelSelectionDigest.MatchString(i.PublicationSHA256) || !panelSelectionDigest.MatchString(i.AgentUnit) || !panelSelectionDigest.MatchString(i.WorkerUnit) || r.Deadline != i.Deadline || r.UpdatedAt < i.CreatedAt || i.CreatedAt <= 0 || i.CreatedAt > time.Now().Unix()+300 || i.Deadline != i.CreatedAt+600 || r.RequestHash != nginxImageHash(r.OperationID, i) || len(p.Failure) > 4000 || len(r.Error) > 4000 {
		return errors.New("Nginx 镜像意图或运行来源不一致")
	}
	if i.Directory != "bootstrap" && !validID(i.Directory) || i.RevisionID != "" && !validID(i.RevisionID) || i.DeploymentID != "" && !validID(i.DeploymentID) {
		return errors.New("Nginx 镜像事务缺少固定发布身份")
	}
	if !agentProgramValid(i.Agent) || i.Agent.DataDir != i.Before.DataDir || !agentProcessValid(i.AgentProcess) || i.AgentProcess.State != "running" || i.Container.State != "running" || !panelSelectionDigest.MatchString(i.Container.Instance.ID) || i.Container.Instance.ImageID != i.Before.ImageID || i.Container.Instance.PID <= 1 {
		return errors.New("Nginx 镜像事务缺少原进程代次")
	}
	if started, e := time.Parse(time.RFC3339Nano, i.Container.Instance.StartedAt); e != nil || started.IsZero() || i.Container.Instance.RestartCount < 0 {
		return errors.New("原 Nginx 容器代次缺少固定启动时间")
	}
	if err := dockerapi.ValidateLabels(i.Container.Labels); err != nil {
		return err
	}
	if err := dockerapi.ValidateLabels(i.TargetLabels); err != nil {
		return err
	}
	if len(i.BeforeCompose) == 0 || len(i.TargetCompose) == 0 || len(i.BeforeCompose) > panelruntime.DockerComposeLimit || len(i.TargetCompose) > panelruntime.DockerComposeLimit {
		return errors.New("Nginx Compose 超过意图预算")
	}
	for _, id := range []string{p.TargetContainerID, p.RollbackContainerID, p.CheckContainerID} {
		if id != "" && !panelSelectionDigest.MatchString(id) {
			return errors.New("Nginx 镜像子实例标识无效")
		}
	}
	for _, direction := range []string{"forward", "rollback", "check"} {
		target := i.Target
		if direction == "rollback" {
			target = i.Before
		}
		if err := dockerapi.ValidateLabels((&nginxImageWorker{r: r}).labels(target, direction)); err != nil {
			return err
		}
	}
	if p.CheckExitCode != nil {
		if !p.CheckSubmitted || p.CheckFinishedAt == "" {
			return errors.New("候选校验结果缺少原派发身份")
		}
		if _, err := time.Parse(time.RFC3339Nano, p.CheckFinishedAt); err != nil {
			return errors.New("候选校验结果时间无效")
		}
	}
	if p.CheckPassed && (p.CheckExitCode == nil || *p.CheckExitCode != 0) {
		return errors.New("候选校验通过缺少退出证据")
	}
	if p.CheckContainerID != "" && !p.CheckCreateSubmitted || p.CheckSubmitted && p.CheckContainerID == "" || p.CheckPassed && !p.CheckSubmitted {
		return errors.New("Nginx 候选校验缺少原派发意图")
	}
	if p.TargetContainerID != "" && !p.TargetCreateSubmitted || p.RollbackContainerID != "" && !p.RollbackCreateSubmitted || p.TargetStartSubmitted && p.TargetContainerID == "" || p.RollbackStartSubmitted && p.RollbackContainerID == "" {
		return errors.New("Nginx 容器缺少持久派发意图")
	}
	for _, g := range []struct {
		value     *nginxcontainer.Instance
		id, image string
	}{{p.TargetGeneration, p.TargetContainerID, i.Target.ImageID}, {p.RollbackGeneration, p.RollbackContainerID, i.Before.ImageID}, {p.ResumedOriginal, i.Container.Instance.ID, i.Before.ImageID}} {
		if v := g.value; v != nil {
			started, e := time.Parse(time.RFC3339Nano, v.StartedAt)
			if v.ID != g.id || v.ImageID != g.image || v.RestartCount < 0 || e != nil || started.IsZero() {
				return errors.New("Nginx 镜像进程代次无效")
			}
		}
	}
	if p.ResumedOriginal != nil && (!p.Rollback || p.ResumedOriginal.ID != i.Container.Instance.ID || p.ResumedOriginal.ImageID != i.Before.ImageID || p.ResumedOriginal.RestartCount < 0) {
		return errors.New("Nginx 原容器续办代次无效")
	}
	if !slices.Contains([]string{"running", "compensating", "recovery_required", "succeeded", "rolled_back", "failed"}, r.State) || !slices.Contains([]string{"authorized", "check_creating", "checking", "check_removing", "stopping_agent", "stopping", "removing", "selecting", "creating", "starting", "confirming_nginx", "starting_agent", "confirming_agent", "committed", "rollback_stopping_agent", "rollback_stopping", "rollback_selecting", "rollback_creating", "rollback_starting", "rollback_confirming_nginx", "rollback_starting_agent", "rollback_confirming_agent", "compensated", "rejected"}, r.Stage) {
		return errors.New("Nginx 镜像事务状态或阶段无效")
	}
	if r.State == "succeeded" && (r.Stage != "committed" || p.Rollback || !p.Touched || !p.CheckPassed || p.Failure != "" || r.Error != "") || r.State == "rolled_back" && (r.Stage != "compensated" || !p.Rollback || p.Failure == "") || r.State == "compensating" && !p.Rollback || r.State == "failed" && (r.Stage != "rejected" || p.Touched || p.Failure == "") {
		return errors.New("Nginx 镜像终态缺少原方向证据")
	}
	if c := p.Confirmation; c != nil {
		expected := p.TargetContainerID
		if p.Rollback || r.State == "failed" {
			expected = p.RollbackContainerID
			if c.ContainerID == i.Container.Instance.ID {
				expected = i.Container.Instance.ID
			}
		}
		if expected == "" || c.ContainerID != expected {
			return errors.New("Nginx 联合确认缺少原容器身份")
		}
		target := i.Target
		if p.Rollback || r.State == "failed" {
			target = i.Before
		}
		if c.ConfirmedAt < i.CreatedAt || c.ConfirmedAt > r.UpdatedAt || c.ImageID != target.ImageID || !panelSelectionDigest.MatchString(c.ContainerID) || c.NginxPID <= 1 || !agentProcessValid(c.Agent) || c.Agent.State != "running" || !validID(c.ReadyEpoch) || !c.Runtime.Available || !c.Runtime.Running || !c.Runtime.Integrity || c.Runtime.ExternalChange || c.Runtime.RevisionID != i.RevisionID || c.Runtime.DeploymentID != i.DeploymentID {
			return errors.New("Nginx 镜像确认与原发布不一致")
		}
	} else if nginxImageTerminal(r) {
		return errors.New("Nginx 镜像终态缺少联合确认")
	}
	raw, err := json.Marshal(r)
	if err != nil || len(raw) > nginxImageRecordLimit {
		return errors.New("Nginx 镜像记录超过持久预算")
	}
	return nil
}
func NginxImageStatus(data, id string) (Record, error) {
	var out Record
	if os.Geteuid() != 0 || !validID(id) {
		return out, errors.New("Nginx 镜像状态仅允许宿主机 root 按原 UUID 查询")
	}
	if _, err := panelruntime.Root(data); err != nil {
		return out, err
	}
	raw, err := secure.ReadRootFile(filepath.Join(data, "agent", "operations", id+".json"), nginxImageRecordLimit)
	if err != nil {
		return out, err
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&out) != nil || d.Decode(new(any)) != io.EOF {
		return out, errors.New("Nginx 镜像记录格式无效")
	}
	return out, validNginxImage(out)
}

func nginxImageAPIInput(in NginxImageInput) imageupdates.Input {
	return imageupdates.Input{Component: imageupdates.Nginx, AllowDowntime: in.AllowDowntime, MaintenanceID: in.MaintenanceID, PlanID: in.Stage.PlanID, Prerelease: in.Stage.AllowPrerelease}
}
