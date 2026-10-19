package agent

import (
	"errors"
	"path/filepath"

	"nginxpanel/internal/nginxmodules"
)

// Preserve the complete artifact and its original audit for later recovery.
// This proves the frozen disk checkpoint, not current Nginx traffic behavior.
type fail2banUpgradeQuiesceNginx struct {
	Directory, RevisionID, ManifestSHA256 string
	Snapshot                              clientDenySnapshot
	Checkpoint                            Record
}

func readFail2banUpgradeQuiesceNginx(data string, p fail2banUpgradePreparation) (*fail2banUpgradeQuiesceNginx, error) {
	if !fail2banJailNeedsNginx(p.Basis.Bundle) {
		return nil, nil
	}
	n := &Nginx{DataDir: data}
	dir, manifest, err := n.activeMetadata()
	if err != nil {
		return nil, err
	}
	if dir != p.Basis.Bundle.NginxDir || manifestHash(manifest) != p.Basis.Bundle.NginxHash {
		return nil, errors.New("升级停止前须保持原活动 Nginx 修订")
	}
	raw, err := nginxmodules.ReadTrusted(n.clientDenyPath(), clientDenyArtifactLimit)
	if err != nil {
		return nil, err
	}
	snapshot, _, err := decodeClientDenySnapshot(raw)
	if err != nil {
		return nil, err
	}
	records, err := (&Journal{Dir: filepath.Join(data, "agent", "operations")}).List()
	if err != nil {
		return nil, err
	}
	checkpoint, err := clientDenyCheckpoint(records)
	if err != nil {
		return nil, err
	}
	if checkpoint == nil {
		return nil, errors.New("升级停止前缺少 Nginx 动作检查点")
	}
	return &fail2banUpgradeQuiesceNginx{Directory: dir, RevisionID: manifest.RevisionID, ManifestSHA256: manifestHash(manifest), Snapshot: snapshot, Checkpoint: *checkpoint}, nil
}

func (i fail2banUpgradeQuiesceIntent) validateNginx(p fail2banUpgradePreparation) error {
	h := i.Nginx
	if !fail2banJailNeedsNginx(p.Basis.Bundle) {
		if h != nil {
			return errors.New("升级停止包含范围外 Nginx 动作材料")
		}
		return nil
	}
	if h == nil || h.Directory != p.Basis.Bundle.NginxDir || h.ManifestSHA256 != p.Basis.Bundle.NginxHash || h.Snapshot.SourceKey != fail2banUpgradeNginxSourceKey(p.Basis.Registry.ID, i.Invocation, i.SocketInode) {
		return errors.New("升级停止缺少原运行代次的 Nginx 拒绝集合")
	}
	checkpoint, err := clientDenyCheckpoint([]Record{h.Checkpoint})
	if err != nil {
		return err
	}
	if checkpoint == nil || checkpoint.BeforeDir != h.Directory || checkpoint.AfterDir != h.Directory || checkpoint.BeforeRevision != h.RevisionID || checkpoint.AfterRevision != h.RevisionID || checkpoint.ClientDeny.ManifestHash != h.ManifestSHA256 {
		return errors.New("升级停止的 Nginx 配置与原检查点不匹配")
	}
	expected := checkpoint.ClientDeny.After
	switch {
	case checkpoint.State == "succeeded" && checkpoint.Stage == "runtime_confirmed" && checkpoint.ObservedRevision == h.RevisionID:
	case checkpoint.State == "failed" && checkpoint.Stage == "rolled_back":
		expected = checkpoint.ClientDeny.Before
	default:
		return errors.New("升级停止的 Nginx 检查点尚未确认成功或完整补偿")
	}
	if !fail2banUpgradeOneOf(expected, h.Snapshot) {
		return errors.New("升级停止的 Nginx 集合与原确认结果不匹配")
	}
	return nil
}
