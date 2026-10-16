package agent

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"nginxpanel/internal/launcher"
	"nginxpanel/internal/panelready"
	"nginxpanel/internal/panelrecovery"
	"nginxpanel/internal/panelruntime"
	"nginxpanel/internal/storage"
)

type PanelReadiness struct {
	StartID        string                  `json:"start_id"`
	StartSHA256    string                  `json:"start_sha256"`
	SnapshotID     string                  `json:"snapshot_id"`
	SnapshotSHA256 string                  `json:"snapshot_sha256"`
	BindingSHA256  string                  `json:"binding_sha256"`
	CheckedAt      int64                   `json:"checked_at"`
	Process        PanelServiceObservation `json:"process"`
	Application    panelready.Status       `json:"application"`
	HTTPS          panelready.HTTPSResult  `json:"https"`
}

func panelReadinessGrant(ctx context.Context, j *Journal, data, id, epoch string, closing bool) error {
	release, err := j.waitRootLock(ctx, ".maintenance-access.lock")
	if err != nil {
		return err
	}
	defer release()
	if err = installGrant(j, id, epoch, closing); err != nil {
		return err
	}
	held, err := storage.ServiceHeld(data)
	if err != nil {
		return err
	}
	if held {
		return errors.New("面板仍处于持久停机状态")
	}
	fenced, err := storage.WriterFenced(data)
	if err != nil {
		return err
	}
	if fenced {
		return errors.New("面板数据恢复尚未完成")
	}
	return nil
}

func panelReadinessParent(ctx context.Context, s panelruntime.Snapshot, expected PanelServiceObservation) (int, error) {
	if s.Deployment.Mode == "native" {
		return 0, nil
	}
	l, peer, err := (launcher.Client{DataDir: s.Deployment.DataDir}).StatusPeer(ctx)
	if err != nil {
		return 0, err
	}
	if l.State != "running" || l.BootID != expected.BootID || l.InstanceID != expected.InstanceID || l.PID != expected.PID || l.ReleaseID != expected.ReleaseID || l.Version != s.Release.Version || peer <= 1 {
		return 0, errors.New("readiness launcher 实例已偏离原启动记录")
	}
	return peer, nil
}

func panelReadinessListener(pid int, address string) error {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	p, err := strconv.Atoi(port)
	if err != nil {
		return err
	}
	owned, err := processSockets(pid)
	if err != nil {
		return err
	}
	sockets, err := networkSockets()
	if err != nil {
		return err
	}
	network := "tcp4"
	if net.ParseIP(host).To4() == nil {
		network = "tcp6"
	}
	for _, socket := range sockets {
		if socket.listener.Network == network && socket.listener.IP == host && socket.listener.Port == p && owned[socket.inode] {
			return nil
		}
	}
	return errors.New("实际管理 HTTPS 监听不属于原面板进程")
}

func panelReadyBaseline(status panelready.Status, s panelruntime.Snapshot, receipt panelrecovery.Receipt, maintenanceID, epoch string) error {
	if err := status.Validate(); err != nil {
		return err
	}
	c, db, m := status.Configuration, receipt.Manifest.Database, status.Maintenance
	if status.DatabaseSchema != s.Release.DatabaseSchema || status.NodeID != db.NodeID || c.DesiredRevision != db.DesiredRevision || c.AppliedRevision != db.AppliedRevision || c.HeadVersion != db.HeadVersion || m.ID != maintenanceID || m.Epoch != epoch {
		return errors.New("就绪数据库或维护身份与原快照、目标程序不一致")
	}
	if c.AppliedRevision != "" && (!c.Available || !c.Integrity || !c.Running || c.ExternalChange || c.RevisionID != c.AppliedRevision) || c.Available && (c.ExternalChange || !c.Integrity) {
		return errors.New("原配置的实际运行修订尚未确认")
	}
	return nil
}

// CheckPanelReadiness is an observation, not an update commit. The parent must
// persist this evidence and decide whether to release or compensate while the
// same maintenance grant is still held; replaying a successful start is not
// evidence that this original process remains alive.
func CheckPanelReadiness(ctx context.Context, data, startID, snapshotID, maintenanceID, epoch string) (PanelReadiness, error) {
	var out PanelReadiness
	if os.Geteuid() != 0 || !validID(startID) || !validID(snapshotID) || !validID(maintenanceID) || !validID(epoch) {
		return out, errors.New("就绪检查需要 root、原启动、快照和维护身份")
	}
	if _, err := panelruntime.Root(data); err != nil {
		return out, err
	}
	ctx, cancel := context.WithTimeout(ctx, 4*time.Minute)
	defer cancel()
	j := &Journal{Dir: filepath.Join(data, "agent", "operations")}
	unlock, err := j.waitRootLock(ctx, ".panel-service.lock")
	if err != nil {
		return out, err
	}
	defer unlock()
	if err = panelReadinessGrant(ctx, j, data, maintenanceID, epoch, true); err != nil {
		return out, err
	}
	started, err := panelServiceRecord(data, startID)
	if err != nil {
		return out, err
	}
	i := started.PanelService.Intent
	if started.State != "succeeded" || i.Input.Action != "start" || i.Input.MaintenanceID != maintenanceID {
		return out, errors.New("就绪检查须关联原维护会话的已完成启动")
	}
	current, err := panelruntime.Read(data)
	if err != nil {
		return out, err
	}
	if current.Release.ID != i.ReleaseID || selectionValueHash(current.Deployment) != i.BindingSHA256 {
		return out, errors.New("当前程序或运行绑定与原启动不一致")
	}
	snapshot, err := panelrecovery.Inspect(ctx, data, snapshotID)
	if err != nil {
		return out, err
	}
	receipt := snapshot.Receipt
	if receipt.Manifest.MaintenanceID != maintenanceID || receipt.Manifest.UID != current.Deployment.UID || receipt.Manifest.GID != current.Deployment.GID || receipt.Manifest.Database.SchemaVersion > current.Release.DatabaseSchema {
		return out, errors.New("就绪快照不属于原维护、运行账户或目标数据库版本")
	}
	if i.Input.SelectionID != "" {
		selected, err := panelSelectionRecord(data, i.Input.SelectionID)
		if err != nil {
			return out, err
		}
		if selected.State != "succeeded" || selected.PanelSelection.TargetID != current.Release.ID || selectionValueHash(selected.PanelSelection.Snapshot) != selectionValueHash(receipt) {
			return out, errors.New("就绪快照不是原版本选择的批准快照")
		}
		approved, err := panelruntime.Staged(ctx, selected.PanelSelection.Stage)
		if err != nil {
			return out, err
		}
		if selectionValueHash(approved.Approval) != selected.PanelSelection.ApprovalSHA256 {
			return out, errors.New("就绪目标的当前签名批准已变化")
		}
	}
	return observePanelReadiness(ctx, j, current, started, receipt, epoch)
}

func observePanelReadiness(ctx context.Context, j *Journal, current panelruntime.Snapshot, started Record, receipt panelrecovery.Receipt, epoch string) (PanelReadiness, error) {
	ctx, cancel := context.WithTimeout(ctx, 4*time.Minute)
	defer cancel()
	var out PanelReadiness
	data := current.Deployment.DataDir
	maintenanceID := started.PanelService.Intent.Input.MaintenanceID
	i := started.PanelService.Intent
	expected := *started.PanelService.After
	var status panelready.Status
	var hostPID, parent int
	// A started process can still be initializing its DB, TLS listener and
	// maintenance coordinator. Retry only unavailable/not-ready observations.
	wait, stop := context.WithTimeout(ctx, 90*time.Second)
	defer stop()
	for {
		if err = panelReadinessGrant(wait, j, data, maintenanceID, epoch, true); err != nil {
			return out, err
		}
		observed, e := observePanelService(wait, current)
		if e != nil {
			return out, e
		}
		if observed != expected {
			return out, errors.New("原启动的面板进程实例已退出或变化")
		}
		parent, err = panelReadinessParent(wait, current, expected)
		if err != nil {
			return out, err
		}
		status, hostPID, err = panelready.Read(wait, current, expected.PID, parent)
		if err == nil {
			break
		}
		if !errors.Is(err, panelready.ErrNotReady) && !errors.Is(err, os.ErrNotExist) && !errors.Is(err, syscall.ECONNREFUSED) && !errors.Is(err, context.DeadlineExceeded) {
			return out, err
		}
		select {
		case <-wait.Done():
			return out, errors.Join(wait.Err(), err)
		case <-time.After(500 * time.Millisecond):
		}
	}
	if err = panelReadyBaseline(status, current, receipt, maintenanceID, epoch); err != nil {
		return out, err
	}
	if err = panelrecovery.CheckMaterial(ctx, receipt); err != nil {
		return out, err
	}
	if err = panelReadinessListener(hostPID, current.Deployment.Listen); err != nil {
		return out, err
	}
	https, err := panelready.CheckHTTPS(ctx, current, status.NodeID)
	if err != nil {
		return out, err
	}
	last, lastPID, err := panelready.Read(ctx, current, expected.PID, parent)
	if err != nil {
		return out, err
	}
	if last != status || lastPID != hostPID {
		return out, errors.New("就绪检查期间应用、配置或进程状态发生变化")
	}
	if err = panelReadinessListener(hostPID, current.Deployment.Listen); err != nil {
		return out, err
	}
	observed, err := observePanelService(ctx, current)
	if err != nil {
		return out, err
	}
	if observed != expected {
		return out, errors.New("就绪检查后原面板进程实例已变化")
	}
	if err = panelrecovery.CheckMaterial(ctx, receipt); err != nil {
		return out, err
	}
	if err = panelReadinessGrant(ctx, j, data, maintenanceID, epoch, false); err != nil {
		return out, err
	}
	return PanelReadiness{StartID: started.OperationID, StartSHA256: started.RequestHash, SnapshotID: receipt.Manifest.OperationID, SnapshotSHA256: selectionValueHash(receipt), BindingSHA256: i.BindingSHA256, CheckedAt: time.Now().Unix(), Process: expected, Application: status, HTTPS: https}, nil
}
