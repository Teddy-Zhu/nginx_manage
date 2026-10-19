package agent

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"time"

	"nginxpanel/internal/nginxcontainer"
	"nginxpanel/internal/panelruntime"
	"nginxpanel/internal/releases"
	"nginxpanel/internal/secure"
	"nginxpanel/internal/storage"
)

type panelImageWorker struct {
	j *Journal
	r Record
}

func (w *panelImageWorker) save() error {
	w.r.UpdatedAt = time.Now().Unix()
	if err := validPanelImage(w.r); err != nil {
		return err
	}
	return w.j.Put(w.r)
}
func (w *panelImageWorker) stage(stage string) error {
	w.r.Stage, w.r.State, w.r.Error = stage, "running", ""
	if w.r.PanelImage.Rollback {
		w.r.State = "compensating"
	}
	return w.save()
}
func panelImageLocks(ctx context.Context, data string) (*Journal, func(), error) {
	if os.Geteuid() != 0 {
		return nil, nil, errors.New("镜像替换需要宿主机 root")
	}
	if _, err := panelruntime.Root(data); err != nil {
		return nil, nil, err
	}
	j := &Journal{Dir: filepath.Join(data, "agent", "operations")}
	lock, err := j.waitRootLock(ctx, ".panel-image.lock")
	if err != nil {
		return nil, nil, err
	}
	installer, err := (&Journal{Dir: "/run/nginxpanel-install"}).rootLock("lock")
	if err != nil {
		lock()
		return nil, nil, err
	}
	return j, func() { installer(); lock() }, nil
}
func QueuePanelImage(ctx context.Context, in PanelImageInput, id, epoch string) (Record, error) {
	var zero Record
	if !validID(id) || !validID(in.MaintenanceID) || id == in.MaintenanceID || !validID(epoch) || !panelSelectionDigest.MatchString(in.Signature.ExpectedManifestSHA256) || in.Stage.TrustPath != "/etc/nginxpanel/release-trust.json" || in.Signature.TrustPath != in.Stage.TrustPath || in.Signature.AllowPrerelease != in.Stage.AllowPrerelease {
		return zero, errors.New("镜像替换须使用独立操作 UUID、原维护身份、预期清单散列和固定发布信任")
	}
	j, unlock, err := panelImageLocks(ctx, in.Stage.DataDir)
	if err != nil {
		return zero, err
	}
	defer unlock()
	if prior, err := PanelImageStatus(in.Stage.DataDir, id); err == nil {
		if prior.PanelImage.Intent.Input != in {
			return zero, errors.New("镜像替换标识已用于不同请求")
		}
		return prior, nil
	} else if !os.IsNotExist(err) {
		return zero, err
	}
	access, err := panelUpdateAccess(ctx, j, id, in.MaintenanceID, epoch, false)
	if err != nil {
		return zero, err
	}
	access()
	// Readiness calls back into the Agent. Never keep its maintenance-access
	// lock across that observation; renew the exact lease before publication.
	service, err := j.waitRootLock(ctx, ".panel-service.lock")
	if err != nil {
		return zero, err
	}
	defer service()
	if _, err = installationExecutable(); err != nil {
		return zero, err
	}
	before, err := panelruntime.Read(in.Stage.DataDir)
	if err != nil {
		return zero, err
	}
	if before.Deployment.Mode != "docker" {
		return zero, errors.New("只有容器面板可执行 launcher 镜像替换")
	}
	if before.Release.AgentProtocol != Protocol {
		return zero, errors.New("镜像替换要求当前应用与宿主 Agent 协议一致")
	}
	unit, active, err := panelImageHost(ctx, in.Stage.DataDir, id)
	if err != nil {
		return zero, err
	}
	if active {
		return zero, errors.New("镜像替换服务实例已运行")
	}
	staged, err := panelruntime.Stage(ctx, in.Stage)
	if err != nil {
		return zero, err
	}
	approval, _, err := releases.AdmitImage(in.Signature, "panel-launcher", in.Image, nil)
	if err != nil {
		return zero, err
	}
	if approval.ManifestSHA256 != staged.Approval.ManifestSHA256 || approval.Version != staged.Release.Version || approval.Image.Platform.LauncherSHA256 != staged.Release.BinarySHA256 {
		return zero, errors.New("镜像和预备程序不属于同一签名发行")
	}
	target := before.Deployment
	target.Image, target.ImageID, target.LauncherSHA256, target.SignedImage = in.Image, approval.Image.Platform.ConfigDigest, approval.Image.Platform.LauncherSHA256, approval
	if !panelruntime.SameDockerApplication(before.Deployment, target) || target.ImageID == before.Deployment.ImageID {
		return zero, errors.New("镜像替换不能改变应用绑定或重复选择当前镜像")
	}
	for _, d := range []panelruntime.Deployment{before.Deployment, target} {
		if err = nginxcontainer.InspectPanelImage(ctx, d.Image, d.ImageID, d.LauncherSHA256); err != nil {
			return zero, err
		}
	}
	targetLabels, err := panelruntime.DockerImageLabels(ctx, target)
	if err != nil {
		return zero, err
	}
	var oldCompose, newCompose bytes.Buffer
	if err = panelruntime.ComposeDeployment(&oldCompose, before.Deployment); err != nil {
		return zero, err
	}
	if err = panelruntime.ComposeDeployment(&newCompose, target); err != nil {
		return zero, err
	}
	raw, err := secure.ReadRootFile(panelruntime.DockerComposePath, panelruntime.DockerComposeLimit)
	if err != nil {
		return zero, err
	}
	info, err := os.Lstat(panelruntime.DockerComposePath)
	if err != nil {
		return zero, err
	}
	if info.Mode().Perm() != 0444 {
		return zero, errors.New("已安装 Compose 须保持 root 只读")
	}
	if !bytes.Equal(raw, oldCompose.Bytes()) {
		return zero, errors.New("已安装 Compose 与当前固定绑定不一致")
	}
	frontend, err := panelImageFrontend(in.Stage.DataDir)
	if err != nil {
		return zero, err
	}
	observed, err := observePanelService(ctx, before)
	if err != nil {
		return zero, err
	}
	if observed.State != "running" {
		return zero, errors.New("镜像替换前须确认当前应用正在运行")
	}
	container, err := panelruntime.ReadDockerContainer(ctx, before.Deployment)
	if err != nil {
		return zero, err
	}
	ready, err := panelImageBaseline(ctx, j, before, observed, in.MaintenanceID, epoch)
	if err != nil {
		return zero, err
	}
	after, err := panelruntime.ReadDockerContainer(ctx, before.Deployment)
	if err != nil {
		return zero, err
	}
	if selectionValueHash(after) != selectionValueHash(container) {
		return zero, errors.New("镜像授权期间原容器代次发生变化")
	}
	access, err = panelUpdateAccess(ctx, j, id, in.MaintenanceID, epoch, false)
	if err != nil {
		return zero, err
	}
	defer access()
	current, err := panelruntime.Read(in.Stage.DataDir)
	if err != nil {
		return zero, err
	}
	if selectionValueHash(current) != selectionValueHash(before) {
		return zero, errors.New("镜像授权发布前当前程序或绑定变化")
	}
	selected, err := panelImageFrontend(in.Stage.DataDir)
	if err != nil {
		return zero, err
	}
	if selected != frontend {
		return zero, errors.New("镜像授权发布前前端选择变化")
	}
	compose, err := secure.ReadRootFile(panelruntime.DockerComposePath, panelruntime.DockerComposeLimit)
	if err != nil {
		return zero, err
	}
	if !bytes.Equal(compose, raw) {
		return zero, errors.New("镜像授权发布前 Compose 变化")
	}
	now := time.Now().Unix()
	intent := PanelImageIntent{Input: in, Epoch: epoch, Before: before.Deployment, Target: target, PanelID: before.Release.ID, ApprovalSHA256: selectionValueHash(staged.Approval), BeforeCompose: oldCompose.Bytes(), TargetCompose: newCompose.Bytes(), TargetLabels: targetLabels, Container: container, Baseline: ready, FrontendSHA256: frontend, WorkerUnit: unit, CreatedAt: now, Deadline: now + 600}
	r := Record{OperationID: id, Kind: panelImageKind, State: "running", Stage: "authorized", RequestHash: panelImageHash(id, intent), PanelImage: &PanelImageOperation{Intent: intent, Epoch: epoch}, CreatedAt: now, UpdatedAt: now}
	w := &panelImageWorker{j: j, r: r}
	if err = w.save(); err != nil {
		return zero, err
	}
	_, err = installationSystemctl(ctx, "start", "--no-block", panelImageUnit(id))
	return w.r, err
}

func ResumePanelImage(ctx context.Context, data, id, epoch string) (Record, error) {
	if !validID(epoch) {
		return Record{}, errors.New("续办镜像替换须提供当前维护 epoch")
	}
	j, unlock, err := panelImageLocks(ctx, data)
	if err != nil {
		return Record{}, err
	}
	defer unlock()
	r, err := PanelImageStatus(data, id)
	if err != nil || panelImageTerminal(r) {
		return r, err
	}
	hash, active, err := panelImageHost(ctx, data, id)
	if err != nil {
		return r, err
	}
	if hash != r.PanelImage.Intent.WorkerUnit {
		return r, errors.New("独立镜像服务在授权后发生变化")
	}
	if active {
		return r, errors.New("原镜像替换服务仍在运行")
	}
	access, err := panelUpdateAccess(ctx, j, id, r.PanelImage.Intent.Input.MaintenanceID, epoch, false)
	if err != nil {
		return r, err
	}
	defer access()
	// Epoch renewal never extends the original forward deadline or reverses an
	// already persisted compensation direction. Old readiness is re-observed.
	r.PanelImage.Epoch = epoch
	r.PanelImage.Ready = nil
	r.PanelImage.RollbackReady = nil
	// A host reboot may restart the original, still correctly bound container.
	// Only explicit resume can accept that generation, and only to confirm or
	// restore the original image. It cannot continue the forward replacement.
	i := r.PanelImage.Intent
	if original, inspectErr := panelruntime.ReadDockerContainer(ctx, i.Before); inspectErr == nil && original.Instance.ID == i.Container.Instance.ID {
		if selectionValueHash(original.Labels) != selectionValueHash(i.Container.Labels) {
			return r, errors.New("原面板容器标签在中断期间发生外部变化")
		}
		if original.Instance.StartedAt != i.Container.Instance.StartedAt || original.Instance.RestartCount != i.Container.Instance.RestartCount {
			r.PanelImage.ResumedOriginal = &original.Instance
			if !r.PanelImage.Rollback {
				r.PanelImage.Rollback = true
				r.PanelImage.Failure = "原容器在中断期间重启，显式续办仅恢复并确认原镜像"
			}
			r.State, r.Stage = "compensating", "rollback_stopping"
		}
	}
	w := &panelImageWorker{j: j, r: r}
	if err = w.save(); err != nil {
		return r, err
	}
	_, err = installationSystemctl(ctx, "start", "--no-block", panelImageUnit(id))
	return w.r, err
}

func (w *panelImageWorker) hold() storage.ServiceHold {
	i := w.r.PanelImage.Intent
	return storage.ServiceHold{Schema: 1, OperationID: w.r.OperationID, MaintenanceID: i.Input.MaintenanceID, RequestSHA256: w.r.RequestHash, ReleaseID: i.PanelID, BindingSHA256: selectionValueHash(i.Before)}
}
func (w *panelImageWorker) grant(ctx context.Context, closing bool) error {
	p := w.r.PanelImage
	i := p.Intent
	unlock, err := panelUpdateAccess(ctx, w.j, w.r.OperationID, i.Input.MaintenanceID, p.Epoch, closing)
	if err != nil {
		return err
	}
	defer unlock()
	return nil
}
func (w *panelImageWorker) guard(ctx context.Context, forward bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	p := w.r.PanelImage
	i := p.Intent
	if err := w.grant(ctx, false); err != nil {
		return err
	}
	hash, _, err := panelImageHost(ctx, i.Input.Stage.DataDir, w.r.OperationID)
	if err != nil {
		return err
	}
	if hash != i.WorkerUnit {
		return errors.New("独立镜像服务偏离原授权")
	}
	current, err := panelruntime.Read(i.Input.Stage.DataDir)
	if err != nil {
		return err
	}
	if current.Release.ID != i.PanelID || current.Deployment != i.Before && current.Deployment != i.Target {
		return errors.New("镜像替换期间当前程序或绑定发生外部变化")
	}
	frontend, err := panelImageFrontend(i.Input.Stage.DataDir)
	if err != nil {
		return err
	}
	if frontend != i.FrontendSHA256 {
		return errors.New("镜像替换期间前端选择发生变化")
	}
	raw, err := secure.ReadRootFile(panelruntime.DockerComposePath, panelruntime.DockerComposeLimit)
	if err != nil {
		return err
	}
	info, err := os.Lstat(panelruntime.DockerComposePath)
	if err != nil {
		return err
	}
	if info.Mode().Perm() != 0444 {
		return errors.New("已安装 Compose 权限偏离原部署")
	}
	if !bytes.Equal(raw, i.BeforeCompose) && !bytes.Equal(raw, i.TargetCompose) {
		return errors.New("镜像替换期间 Compose 发生外部变化")
	}
	fenced, err := storage.WriterFenced(i.Input.Stage.DataDir)
	if err != nil {
		return err
	}
	if fenced {
		return errors.New("面板数据仍处于恢复写入隔离")
	}
	if forward {
		if time.Now().Unix() >= i.Deadline {
			return errors.New("原镜像替换前进期限已过")
		}
		staged, err := panelruntime.Staged(ctx, i.Input.Stage)
		if err != nil {
			return err
		}
		if selectionValueHash(staged.Approval) != i.ApprovalSHA256 {
			return errors.New("原镜像关联的程序签名批准已变化")
		}
		approved, _, err := releases.AdmitImage(i.Input.Signature, "panel-launcher", i.Target.Image, &i.Target.SignedImage)
		if err != nil {
			return err
		}
		if approved != i.Target.SignedImage {
			return errors.New("原镜像批准已变化")
		}
	}
	return nil
}
