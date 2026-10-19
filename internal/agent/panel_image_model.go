package agent

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"time"

	"nginxpanel/internal/imageupdates"
	"nginxpanel/internal/panelready"
	"nginxpanel/internal/panelrecovery"
	"nginxpanel/internal/panelruntime"
	"nginxpanel/internal/releases"
	"nginxpanel/internal/secure"
)

const panelImageKind = "panel.image"
const panelImageRecordLimit = 256 << 10
const panelImageTemplate = "nginxpanel-image@.service"

type PanelImageInput struct {
	Stage         panelruntime.StageInput `json:"stage"`
	Signature     releases.ImageInput     `json:"signature"`
	Image         string                  `json:"image"`
	MaintenanceID string                  `json:"maintenance_id"`
}

type PanelImageIntent struct {
	Input          PanelImageInput              `json:"input"`
	Epoch          string                       `json:"epoch"`
	Before         panelruntime.Deployment      `json:"before"`
	Target         panelruntime.Deployment      `json:"target"`
	PanelID        string                       `json:"panel_id"`
	ApprovalSHA256 string                       `json:"approval_sha256"`
	BeforeCompose  []byte                       `json:"before_compose"`
	TargetCompose  []byte                       `json:"target_compose"`
	TargetLabels   map[string]string            `json:"target_labels"`
	Container      panelruntime.DockerContainer `json:"container"`
	Baseline       PanelReadiness               `json:"baseline"`
	FrontendSHA256 string                       `json:"frontend_sha256"`
	WorkerUnit     string                       `json:"worker_unit"`
	CreatedAt      int64                        `json:"created_at"`
	Deadline       int64                        `json:"deadline"`
}

func panelImageAPIInput(in PanelImageInput) imageupdates.Input {
	return imageupdates.Input{Component: imageupdates.Panel, MaintenanceID: in.MaintenanceID, PlanID: in.Stage.PlanID, Prerelease: in.Stage.AllowPrerelease}
}

type PanelImageOperation struct {
	Authorizations      []ImageAuthorization         `json:"authorizations,omitempty"`
	Intent              PanelImageIntent             `json:"intent"`
	Epoch               string                       `json:"epoch"`
	Rollback            bool                         `json:"rollback"`
	Failure             string                       `json:"failure"`
	TargetContainerID   string                       `json:"target_container_id"`
	RollbackContainerID string                       `json:"rollback_container_id"`
	ResumedOriginal     *panelruntime.DockerInstance `json:"resumed_original,omitempty"`
	Ready               *PanelReadiness              `json:"ready,omitempty"`
	RollbackReady       *PanelReadiness              `json:"rollback_ready,omitempty"`
}

func panelImageHash(id string, i PanelImageIntent) string {
	raw, _ := json.Marshal(struct {
		Protocol int
		ID       string
		Intent   PanelImageIntent
	}{Protocol, id, i})
	return secure.Hash(raw)
}
func panelImageTerminal(r Record) bool { return r.State == "succeeded" || r.State == "rolled_back" }
func validPanelImage(r Record) error {
	p := r.PanelImage
	if p == nil || r.Kind != panelImageKind || !validID(r.OperationID) {
		return errors.New("镜像替换记录身份无效")
	}
	i := p.Intent
	if err := validImageAuthorizations(p.Authorizations, r.OperationID, panelImageAPIInput(i.Input), i.Epoch, p.Epoch, panelImageTerminal(r)); err != nil {
		return err
	}

	raw, err := json.Marshal(i)
	if err != nil || len(raw) > 104<<10 {
		return errors.New("镜像替换意图超过保留预算")
	}
	raw, err = json.Marshal(r)
	if err != nil || len(raw) > panelImageRecordLimit {
		return errors.New("镜像替换记录超过保留预算")
	}
	if _, err := panelruntime.Root(i.Input.Stage.DataDir); err != nil {
		return err
	}
	if !validID(i.Input.MaintenanceID) || !validID(i.Epoch) || !validID(p.Epoch) || !panelSelectionDigest.MatchString(i.Input.Stage.PlanID) || i.Input.Stage.TrustPath != "/etc/nginxpanel/release-trust.json" || i.Input.Signature.TrustPath != i.Input.Stage.TrustPath || i.Input.Signature.AllowPrerelease != i.Input.Stage.AllowPrerelease || i.Input.Signature.ExpectedManifestSHA256 != i.Target.SignedImage.ManifestSHA256 || i.Input.Image != i.Target.Image || i.Before.DataDir != i.Input.Stage.DataDir || !panelruntime.SameDockerApplication(i.Before, i.Target) || i.Before.ImageID == i.Target.ImageID || !panelSelectionDigest.MatchString(i.PanelID) || !panelSelectionDigest.MatchString(i.ApprovalSHA256) || !panelSelectionDigest.MatchString(i.WorkerUnit) || !panelSelectionDigest.MatchString(i.FrontendSHA256) || i.CreatedAt <= 0 || i.CreatedAt > time.Now().Unix()+300 || i.Deadline != i.CreatedAt+600 || len(i.BeforeCompose) == 0 || len(i.TargetCompose) == 0 || len(i.BeforeCompose) > panelruntime.DockerComposeLimit || len(i.TargetCompose) > panelruntime.DockerComposeLimit || r.RequestHash != panelImageHash(r.OperationID, i) || len(p.Failure) > 4000 {
		return errors.New("镜像替换意图或来源绑定无效")
	}
	c, b := i.Container, i.Baseline
	if accepted := p.ResumedOriginal; accepted != nil {
		started, err := time.Parse(time.RFC3339Nano, accepted.StartedAt)
		if !p.Rollback || accepted.ID != c.Instance.ID || accepted.ImageID != i.Before.ImageID || accepted.RestartCount < 0 || err != nil || started.IsZero() {
			return errors.New("显式续办的原容器代次无效")
		}
	}
	if err := panelruntime.ValidateDockerLabels(i.TargetLabels); err != nil {
		return err
	}
	for _, choice := range []struct {
		d         panelruntime.Deployment
		direction string
	}{{i.Target, "forward"}, {i.Before, "rollback"}} {
		if err := panelruntime.ValidateDockerLabels(panelImageLabels(c.Labels, i.TargetLabels, r.OperationID, choice.d, choice.direction)); err != nil {
			return err
		}
	}
	if !panelSelectionDigest.MatchString(c.Instance.ID) || c.Instance.ImageID != i.Before.ImageID || c.Instance.PID <= 1 || c.State != "running" || b.Application.Validate() != nil || b.Application.Mode != "docker" || b.Application.ReleaseID != i.PanelID || b.Application.Maintenance.ID != i.Input.MaintenanceID || b.Application.Maintenance.Epoch != i.Epoch || b.StartID != i.Input.MaintenanceID || !panelSelectionDigest.MatchString(b.StartSHA256) || b.BindingSHA256 != selectionValueHash(i.Before) || b.Process.State != "running" || b.Process.ReleaseID != i.PanelID || !validID(b.Process.BootID) || !validID(b.Process.InstanceID) || b.Process.PID <= 1 || !panelSelectionDigest.MatchString(b.HTTPS.CertificateSHA256) {
		return errors.New("镜像替换原运行证据无效")
	}
	for _, id := range []string{p.TargetContainerID, p.RollbackContainerID} {
		if id != "" && (!panelSelectionDigest.MatchString(id) || id == c.Instance.ID) {
			return errors.New("镜像替换新容器标识无效")
		}
	}
	for n, ready := range []*PanelReadiness{p.Ready, p.RollbackReady} {
		if ready == nil {
			continue
		}
		d := i.Target
		if n == 1 {
			d = i.Before
		}
		if ready.StartID != r.OperationID || ready.StartSHA256 != r.RequestHash || ready.BindingSHA256 != selectionValueHash(d) || ready.CheckedAt < i.CreatedAt || ready.Application.Validate() != nil || ready.Application.ReleaseID != i.PanelID || ready.Application.Maintenance.ID != i.Input.MaintenanceID || ready.Application.Maintenance.Epoch != p.Epoch || ready.HTTPS != b.HTTPS || ready.Application.Configuration != b.Application.Configuration || ready.Application.NodeID != b.Application.NodeID || ready.Application.DatabaseSchema != b.Application.DatabaseSchema || ready.Process.State != "running" || ready.Process.ReleaseID != i.PanelID {
			return errors.New("镜像替换就绪回执无效")
		}
	}
	if r.State == "succeeded" && r.Stage == "committed" && !p.Rollback && p.Ready != nil && p.TargetContainerID != "" && p.Failure == "" && r.Error == "" {
		return nil
	}
	if r.State == "rolled_back" && r.Stage == "compensated" && p.Rollback && p.RollbackReady != nil && p.Failure != "" {
		return nil
	}
	if panelImageTerminal(r) {
		return errors.New("镜像替换终态缺少就绪证据")
	}
	if p.Rollback {
		if !slices.Contains([]string{"compensating", "recovery_required"}, r.State) || !slices.Contains([]string{"rollback_stopping", "rollback_selecting", "rollback_creating", "rollback_starting", "rollback_checking"}, r.Stage) || p.Failure == "" {
			return errors.New("镜像恢复阶段无效")
		}
	} else if r.State != "running" || !slices.Contains([]string{"authorized", "stopping", "removing", "selecting", "creating", "starting", "checking"}, r.Stage) {
		return errors.New("镜像替换阶段无效")
	}
	return nil
}

func PanelImageStatus(data, id string) (Record, error) {
	var r Record
	if os.Geteuid() != 0 || !validID(id) {
		return r, errors.New("镜像替换查询需要 root 和原操作 UUID")
	}
	if _, err := panelruntime.Root(data); err != nil {
		return r, err
	}
	raw, err := secure.ReadRootFile(filepath.Join(data, "agent", "operations", id+".json"), panelImageRecordLimit)
	if err != nil {
		return r, err
	}
	if err = json.Unmarshal(raw, &r); err != nil {
		return r, err
	}
	if err = validPanelImage(r); err != nil {
		return r, err
	}
	if r.OperationID != id || r.PanelImage.Intent.Input.Stage.DataDir != data {
		return Record{}, errors.New("镜像替换记录不属于此节点或原操作")
	}
	return r, nil
}

// A missing optional frontend selection is a distinct, frozen selection.
func panelImageFrontend(data string) (string, error) {
	raw, err := secure.ReadRootFile(filepath.Join(data, "runtime", "frontend.json"), 16<<10)
	if os.IsNotExist(err) {
		return secure.Hash([]byte("no-frontend-selection")), nil
	}
	if err != nil {
		return "", err
	}
	return secure.Hash(raw), nil
}

func panelImageDatabase(s panelready.Status) panelrecovery.Database {
	return panelrecovery.Database{SchemaVersion: s.DatabaseSchema, NodeID: s.NodeID, DesiredRevision: s.Configuration.DesiredRevision, AppliedRevision: s.Configuration.AppliedRevision, HeadVersion: s.Configuration.HeadVersion}
}
