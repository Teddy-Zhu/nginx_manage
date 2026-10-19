package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"time"

	"net/http"
	"nginxpanel/internal/fault"
	"nginxpanel/internal/imageupdates"
	"nginxpanel/internal/nginxcontainer"
	"nginxpanel/internal/panelruntime"
	"nginxpanel/internal/releases"
	"nginxpanel/internal/secure"
	"nginxpanel/internal/storage"
)

type nginxImageWorker struct {
	j *Journal
	r Record
}

func (w *nginxImageWorker) save() error {
	w.r.UpdatedAt = time.Now().Unix()
	if err := validNginxImage(w.r); err != nil {
		return err
	}
	return w.j.Put(w.r)
}
func (w *nginxImageWorker) stage(stage string) error {
	w.r.Stage, w.r.State, w.r.Error = stage, "running", ""
	if w.r.NginxImage.Rollback {
		w.r.State = "compensating"
	}
	return w.save()
}
func nginxImageLocks(ctx context.Context, data string) (*Journal, func(), error) {
	if os.Geteuid() != 0 {
		return nil, nil, errors.New("Nginx 镜像替换需要宿主机 root")
	}
	if _, err := panelruntime.Root(data); err != nil {
		return nil, nil, err
	}
	j := &Journal{Dir: filepath.Join(data, "agent", "operations")}
	unlock, err := j.waitRootLock(ctx, ".nginx-image.lock")
	if err != nil {
		return nil, nil, err
	}
	installer, err := (&Journal{Dir: "/run/nginxpanel-install"}).rootLock("lock")
	if err != nil {
		unlock()
		return nil, nil, err
	}
	return j, func() { installer(); unlock() }, nil
}
func (w *nginxImageWorker) grant(ctx context.Context) error {
	unlock, err := w.j.waitRootLock(ctx, ".maintenance-access.lock")
	if err != nil {
		return err
	}
	defer unlock()
	epoch := w.r.MaintenanceEpoch
	if w.r.NginxImage.Touched {
		epoch = ""
	}
	return installGrantForOperation(w.j, w.r.NginxImage.Intent.Input.MaintenanceID, epoch, true, w.r.OperationID)
}
func (w *nginxImageWorker) nginx(b nginxcontainer.Binding) *Nginx {
	return &Nginx{DataDir: b.DataDir, WorkerUser: "nginxpanel-nginx", Container: &nginxcontainer.Runtime{Binding: b}, Journal: w.j}
}
func (w *nginxImageWorker) publication(n *Nginx) (manifest, error) {
	var zero manifest
	if err := n.setup(); err != nil {
		return zero, err
	}
	dir, m, err := n.active()
	if err != nil {
		return zero, err
	}
	i := w.r.NginxImage.Intent
	if dir != i.Directory || manifestHash(m) != i.PublicationSHA256 || m.RevisionID != i.RevisionID || m.DeploymentID != i.DeploymentID || len(m.Modules) != 0 {
		return zero, errors.New("Nginx 镜像操作期间固定发布或模块来源发生变化")
	}
	return m, nil
}
func (w *nginxImageWorker) guard(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := w.grant(ctx); err != nil {
		return err
	}
	i := w.r.NginxImage.Intent
	hash, _, err := nginxImageHost(ctx, i.Before.DataDir, w.r.OperationID)
	if err != nil {
		return err
	}
	if hash != i.WorkerUnit {
		return errors.New("Nginx 镜像服务偏离原登记")
	}
	agentHash, _, args, err := agentUpgradeUnits(ctx, i.Before.DataDir, w.r.OperationID)
	if err != nil {
		return err
	}
	if agentHash != i.AgentUnit || len(args) < 7 || args[6] != "--nginx-container" {
		return errors.New("Agent 服务偏离固定容器登记")
	}
	if err = checkAgentProgram(i.Agent); err != nil {
		return err
	}
	current, err := panelruntime.Read(i.Before.DataDir)
	if err != nil {
		return err
	}
	if current.Release.ID != i.PanelID || selectionValueHash(current.Deployment) != selectionValueHash(i.Panel) {
		return errors.New("Nginx 镜像操作期间应用选择发生变化")
	}
	frontend, err := panelImageFrontend(i.Before.DataDir)
	if err != nil {
		return err
	}
	if frontend != i.FrontendSHA256 {
		return errors.New("Nginx 镜像操作期间前端选择发生变化")
	}
	raw, err := secure.ReadRootFile(panelruntime.DockerComposePath, panelruntime.DockerComposeLimit)
	if err != nil {
		return err
	}
	info, err := os.Lstat(panelruntime.DockerComposePath)
	if err != nil {
		return err
	}
	if info.Mode().Perm() != 0444 || !bytes.Equal(raw, i.BeforeCompose) && !bytes.Equal(raw, i.TargetCompose) {
		return errors.New("Nginx Compose 偏离原镜像事务")
	}
	b, err := nginxcontainer.Read(i.Before.DataDir)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(b, i.Before) && !reflect.DeepEqual(b, i.Target) {
		return errors.New("Nginx 绑定偏离原镜像事务")
	}
	fenced, err := storage.WriterFenced(i.Before.DataDir)
	if err != nil {
		return err
	}
	if fenced {
		return errors.New("Nginx 镜像切换不能跨越数据恢复隔离")
	}
	if !w.r.NginxImage.Rollback {
		if time.Now().Unix() >= i.Deadline {
			return errors.New("原 Nginx 镜像前进期限已过")
		}
		staged, e := panelruntime.Staged(ctx, i.Input.Stage)
		if e != nil {
			return e
		}
		if staged.Release.AgentProtocol != Protocol || selectionValueHash(staged.Approval) != i.ApprovalSHA256 {
			return errors.New("Nginx 镜像关联的程序批准或 Agent 协议不一致")
		}
		approved, _, e := releases.AdmitImage(i.Input.Signature, "nginx", i.Target.Image, &i.Target.SignedImage)
		if e != nil {
			return e
		}
		if approved != i.Target.SignedImage {
			return errors.New("Nginx 镜像签名批准发生变化")
		}
	}
	_, err = w.publication(w.nginx(b))
	return err
}

// Admission only inspects retained images. Pulling is a separate signed task;
// this durable transaction cannot download or change a source on continuation.
func QueueNginxImage(ctx context.Context, in NginxImageInput, id, epoch string) (Record, error) {
	return queueNginxImage(ctx, in, id, epoch, nil)
}
func queueNginxImage(ctx context.Context, in NginxImageInput, id, epoch string, authorization *imageupdates.Request) (out Record, resultErr error) {
	var zero Record
	if !validID(id) || !validID(epoch) || !validID(in.MaintenanceID) || in.MaintenanceID == id || !in.AllowDowntime || in.Stage.TrustPath != "/etc/nginxpanel/release-trust.json" || in.Signature.TrustPath != in.Stage.TrustPath || in.Signature.AllowPrerelease != in.Stage.AllowPrerelease || !panelSelectionDigest.MatchString(in.Signature.ExpectedManifestSHA256) {
		return zero, errors.New("Nginx 镜像替换须指定固定签名、独立维护身份并允许停机")
	}
	j, unlock, err := nginxImageLocks(ctx, in.Stage.DataDir)
	if err != nil {
		return zero, err
	}
	defer unlock()
	if prior, e := NginxImageStatus(in.Stage.DataDir, id); e == nil {
		if len(prior.NginxImage.Authorizations) != 0 || authorization != nil {
			return zero, errors.New("托管 Nginx 镜像替换须由原 API 授权查询或续办")
		}
		if prior.NginxImage.Intent.Input != in {
			return zero, errors.New("Nginx 镜像标识已用于不同请求")
		}
		return prior, nil
	} else if !os.IsNotExist(e) {
		return zero, e
	}
	publicationAttempted := false
	defer func() {
		if authorization != nil && resultErr != nil && !publicationAttempted {
			resultErr = fault.New(http.StatusConflict, "NGINX_IMAGE_REJECTED", panelRestoreError(resultErr))
		}
	}()
	if authorization != nil {
		if err := validateImageAuthorization(*authorization, id, nginxImageAPIInput(in), epoch, 1); err != nil {
			return zero, err
		}
	}
	access, err := panelUpdateAccess(ctx, j, id, in.MaintenanceID, epoch, false)
	if err != nil {
		return zero, err
	}
	access()
	if _, err = installationExecutable(); err != nil {
		return zero, err
	}
	panel, err := panelruntime.Read(in.Stage.DataDir)
	if err != nil {
		return zero, err
	}
	if panel.Deployment.Mode != "docker" || panel.Release.AgentProtocol != Protocol {
		return zero, errors.New("Nginx 镜像替换要求同协议的容器部署")
	}
	before, err := nginxcontainer.Read(in.Stage.DataDir)
	if err != nil {
		return zero, err
	}
	unit, active, err := nginxImageHost(ctx, in.Stage.DataDir, id)
	if err != nil {
		return zero, err
	}
	if active {
		return zero, errors.New("Nginx 镜像服务实例仍在运行")
	}
	staged, err := panelruntime.Stage(ctx, in.Stage)
	if err != nil {
		return zero, err
	}
	target, err := nginxcontainer.AdmitCandidate(ctx, nginxcontainer.BindInput{DataDir: before.DataDir, Image: in.Image, LauncherBinary: filepath.Join(staged.Directory, "nginxpanel"), UID: before.UID, GID: before.GID, Signature: in.Signature}, before)
	if err != nil {
		return zero, err
	}
	if target.SignedImage.ManifestSHA256 != staged.Approval.ManifestSHA256 || target.BootstrapSHA256 != staged.Release.BinarySHA256 {
		return zero, errors.New("候选 Nginx 镜像与预备程序不属于同一签名发行")
	}
	if err = nginxcontainer.VerifyRetainedImage(ctx, before); err != nil {
		return zero, err
	}
	labels, err := nginxcontainer.ImageLabels(ctx, target)
	if err != nil {
		return zero, err
	}
	agent, err := readAgentProgram()
	if err != nil {
		return zero, err
	}
	agentUnit, _, args, err := agentUpgradeUnits(ctx, before.DataDir, id)
	if err != nil {
		return zero, err
	}
	if len(args) < 7 || args[6] != "--nginx-container" {
		return zero, errors.New("Agent 未登记容器 Nginx")
	}
	process, err := agentUpgradeObserve(ctx, before.DataDir, id, agent)
	if err != nil {
		return zero, err
	}
	if process.State != "running" {
		return zero, errors.New("原 Agent 尚未运行")
	}
	frontend, err := panelImageFrontend(before.DataDir)
	if err != nil {
		return zero, err
	}
	var oldCompose, newCompose bytes.Buffer
	if err = panelruntime.ComposeWithNginx(&oldCompose, panel.Deployment, before); err != nil {
		return zero, err
	}
	if err = panelruntime.ComposeWithNginx(&newCompose, panel.Deployment, target); err != nil {
		return zero, err
	}
	container, err := nginxcontainer.ReadContainer(ctx, before)
	if err != nil {
		return zero, err
	}
	if container.State != "running" {
		return zero, errors.New("原 Nginx 容器尚未运行")
	}
	now := time.Now().Unix()
	i := NginxImageIntent{Input: in, Epoch: epoch, Before: before, Target: target, Panel: panel.Deployment, PanelID: panel.Release.ID, FrontendSHA256: frontend, ApprovalSHA256: selectionValueHash(staged.Approval), Agent: agent, AgentProcess: process, AgentUnit: agentUnit, WorkerUnit: unit, BeforeCompose: oldCompose.Bytes(), TargetCompose: newCompose.Bytes(), TargetLabels: labels, Container: container, CreatedAt: now, Deadline: now + 600}
	w := &nginxImageWorker{j: j, r: Record{OperationID: id, Kind: nginxImageKind, State: "running", Stage: "authorized", MaintenanceEpoch: epoch, CreatedAt: now, UpdatedAt: now, Deadline: i.Deadline, NginxImage: &NginxImageOperation{Intent: i}}}
	n := w.nginx(before)
	if err = n.setup(); err != nil {
		return zero, err
	}
	dir, m, err := n.active()
	if err != nil {
		return zero, err
	}
	if len(m.Modules) != 0 {
		return zero, errors.New("容器 Nginx 仅使用镜像内置模块")
	}
	i.Directory, i.PublicationSHA256, i.RevisionID, i.DeploymentID = dir, manifestHash(m), m.RevisionID, m.DeploymentID
	w.r.NginxImage.Intent = i
	w.r.RequestHash = nginxImageHash(id, i)
	if err = n.observe(ctx, m); err != nil {
		return zero, err
	}
	if err = w.guard(ctx); err != nil {
		return zero, err
	}
	current, err := nginxcontainer.ReadContainer(ctx, before)
	if err != nil {
		return zero, err
	}
	if !reflect.DeepEqual(container, current) {
		return zero, errors.New("镜像授权期间原 Nginx 容器代次变化")
	}
	observed, err := agentUpgradeObserve(ctx, before.DataDir, id, agent)
	if err != nil {
		return zero, err
	}
	if observed != process {
		return zero, errors.New("镜像授权期间原 Agent 代次变化")
	}
	compose, err := secure.ReadRootFile(panelruntime.DockerComposePath, panelruntime.DockerComposeLimit)
	if err != nil {
		return zero, err
	}
	if !bytes.Equal(compose, i.BeforeCompose) {
		return zero, errors.New("Nginx 当前 Compose 与绑定不一致")
	}
	access, err = panelUpdateAccess(ctx, j, id, in.MaintenanceID, epoch, false)
	if err != nil {
		return zero, err
	}
	defer access()
	if raw, marshalErr := json.Marshal(i); marshalErr != nil || len(raw) > nginxImageIntentLimit {
		return zero, errors.New("Nginx 镜像意图未保留足够恢复记录预算")
	}
	if authorization != nil {
		if err = validateImageAuthorization(*authorization, id, nginxImageAPIInput(in), epoch, 1); err != nil {
			return zero, err
		}
		w.r.NginxImage.Authorizations = []ImageAuthorization{{Request: *authorization, AcceptedAt: time.Now().Unix()}}
	}
	publicationAttempted = true
	if err = w.save(); err != nil {
		return w.r, err
	}
	return w.r, dispatchNginxImage(ctx, id)
}

func ResumeNginxImage(ctx context.Context, data, id, epoch string) (Record, error) {
	return resumeNginxImage(ctx, data, id, epoch, nil)
}
func resumeNginxImage(ctx context.Context, data, id, epoch string, authorization *imageupdates.Request) (Record, error) {
	if !validID(epoch) {
		return Record{}, errors.New("Nginx 镜像续办须提供当前维护 epoch")
	}
	j, unlock, err := nginxImageLocks(ctx, data)
	if err != nil {
		return Record{}, err
	}
	defer unlock()
	r, err := NginxImageStatus(data, id)
	if err != nil || nginxImageTerminal(r) {
		return r, err
	}
	if len(r.NginxImage.Authorizations) != 0 && authorization == nil || len(r.NginxImage.Authorizations) == 0 && authorization != nil {
		return r, errors.New("托管 Nginx 镜像替换须使用原 API 授权续办")
	}
	if authorization != nil {
		as := r.NginxImage.Authorizations
		if authorization.Sequence <= len(as) {
			if authorization.Sequence < 1 || as[authorization.Sequence-1].Request != *authorization {
				return r, errors.New("原 Nginx 镜像替换授权不能改变")
			}
			return r, nil
		}
		if err := validateImageAuthorization(*authorization, id, nginxImageAPIInput(r.NginxImage.Intent.Input), epoch, len(as)+1); err != nil {
			return r, err
		}
	}
	hash, active, err := nginxImageHost(ctx, data, id)
	if err != nil {
		return r, err
	}
	if hash != r.NginxImage.Intent.WorkerUnit || active {
		return r, errors.New("Nginx 镜像服务偏离原登记或仍在运行")
	}
	access, err := panelUpdateAccess(ctx, j, id, r.NginxImage.Intent.Input.MaintenanceID, epoch, true)
	if err != nil {
		return r, err
	}
	defer access()
	p := r.NginxImage
	i := p.Intent
	p.Confirmation = nil
	r.MaintenanceEpoch = epoch
	// Only explicit continuation can accept a rebooted original generation. It
	// permanently chooses recovery; the original deadline is never renewed.
	if original, e := nginxcontainer.ReadContainer(ctx, i.Before); e == nil && original.Instance.ID == i.Container.Instance.ID {
		if !reflect.DeepEqual(original.Labels, i.Container.Labels) {
			return r, errors.New("原 Nginx 容器标签在中断期间变化")
		}
		if original.Instance.StartedAt != i.Container.Instance.StartedAt || original.Instance.RestartCount != i.Container.Instance.RestartCount {
			p.ResumedOriginal = &original.Instance
			p.Rollback = true
			p.Failure = "原 Nginx 容器在中断期间重启，显式续办恢复原镜像"
		}
	}
	if p.Rollback {
		r.State, r.Stage = "compensating", "rollback_stopping_agent"
	}
	if authorization != nil {
		if err := validateImageAuthorization(*authorization, id, nginxImageAPIInput(p.Intent.Input), epoch, len(p.Authorizations)+1); err != nil {
			return r, err
		}
		p.Authorizations = append(p.Authorizations, ImageAuthorization{Request: *authorization, AcceptedAt: time.Now().Unix()})
	}
	w := &nginxImageWorker{j: j, r: r}
	if err = w.save(); err != nil {
		return w.r, err
	}
	return w.r, dispatchNginxImage(ctx, id)
}
