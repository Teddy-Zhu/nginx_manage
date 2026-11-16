package components

import (
	"context"
	"encoding/json"
	"strings"

	"nginxpanel/internal/fault"
	"nginxpanel/internal/protocol"
	"nginxpanel/internal/releases"
	"nginxpanel/internal/secure"
)

const OfflineChunkBytes = 256 << 10
const OfflineRequestBytes = 3 << 20

type OfflineInput struct {
	Manifest   []byte   `json:"manifest"`
	Signature  []byte   `json:"signature"`
	Assets     []string `json:"assets"`
	Components []string `json:"components"`
	Prerelease bool     `json:"prerelease"`
}

func (in OfflineInput) Validate() error {
	if len(in.Manifest) == 0 || len(in.Manifest) > releases.MaxManifestBytes || len(in.Signature) == 0 || len(in.Signature) > 4096 || len(in.Assets)+len(in.Components) == 0 || len(in.Assets)+len(in.Components) > 2 {
		return fault.Invalid("离线清单、签名或组件选择超出限制")
	}
	// Only reuse selector validation here. The signed manifest supplies the
	// version/channel; Verify separately enforces the real prerelease consent.
	if err := (Input{Action: "check", Assets: in.Assets, Components: in.Components}).Validate(); err != nil {
		return err
	}
	return nil
}

type OfflineRequest struct {
	Protocol int          `json:"protocol"`
	ID       string       `json:"id"`
	Input    OfflineInput `json:"input"`
}

func (r OfflineRequest) Valid() bool {
	return r.Protocol == protocol.Agent && ValidID(r.ID) && r.Input.Validate() == nil
}
func (r OfflineRequest) Hash() string { raw, _ := json.Marshal(r); return secure.Hash(raw) }

type OfflineChunk struct {
	Offset int64  `json:"offset"`
	Data   []byte `json:"data"`
}

func (c OfflineChunk) Validate() error {
	if c.Offset < 0 || c.Offset > releases.MaxArchiveBytes || len(c.Data) == 0 || len(c.Data) > OfflineChunkBytes {
		return fault.Invalid("分块偏移或长度无效")
	}
	return nil
}

type OfflineAsset struct {
	ID       string `json:"id"`
	Archive  string `json:"archive"`
	SHA256   string `json:"sha256"`
	Size     int64  `json:"size"`
	Received int64  `json:"received"`
}
type OfflineUpload struct {
	ID          string         `json:"id"`
	RequestHash string         `json:"request_hash"`
	CreatedAt   int64          `json:"created_at"`
	ExpiresAt   int64          `json:"expires_at"`
	Prerelease  bool           `json:"prerelease"`
	Discarded   bool           `json:"discarded"`
	Complete    bool           `json:"complete"`
	Release     Release        `json:"release"`
	Assets      []OfflineAsset `json:"assets"`
}

func (u OfflineUpload) Valid() bool {
	if !ValidID(u.ID) || !digest(u.RequestHash) || u.CreatedAt <= 0 || u.ExpiresAt <= u.CreatedAt || u.ExpiresAt > u.CreatedAt+86400 || u.ExpiresAt > u.Release.ExpiresAt || !digest(u.Release.PlanID) || !digest(u.Release.ManifestSHA256) || !digest(u.Release.TrustSHA256) || u.Release.Tag != releases.SelectionTag(u.Release.Version, u.Release.Selected) || len(u.Assets) > 2 || len(u.Assets) != len(u.Release.Assets) || len(u.Assets) != 0 && len(u.Assets) != len(u.Release.Selected) {
		return false
	}
	if len(u.Assets) == 0 && (len(u.Release.Images) != 1 || len(u.Release.Selected) != 1 || u.Release.Selected[0] != "image-"+u.Release.Images[0].ID || !u.Release.Images[0].valid(u.Release.Repository)) {
		return false
	}
	seen := map[string]bool{}
	archives := map[string]bool{}
	complete := !u.Discarded
	for _, a := range u.Assets {
		if a.ID == "" || len(a.ID) > 128 || seen[a.ID] || archives[a.Archive] || len(a.Archive) > 180 || strings.ContainsAny(a.Archive, "/\\\x00\r\n") || !strings.HasSuffix(a.Archive, ".tar.gz") || !digest(a.SHA256) || a.Size <= 0 || a.Size > releases.MaxArchiveBytes || a.Received < 0 || a.Received > a.Size {
			return false
		}
		seen[a.ID] = true
		archives[a.Archive] = true
		matched := false
		for _, asset := range u.Release.Assets {
			if asset.ID == a.ID && asset.ArchiveBytes == a.Size {
				matched = true
			}
		}
		if !matched {
			return false
		}
		complete = complete && a.Received == a.Size
	}
	for _, id := range u.Release.Selected {
		if len(u.Assets) == 0 && id == "image-"+u.Release.Images[0].ID {
			continue
		}
		if !seen[id] {
			return false
		}
		delete(seen, id)
	}
	return u.Complete == complete
}

type OfflineHost interface {
	CreateOfflineUpload(context.Context, OfflineRequest) (OfflineUpload, error)
	ListOfflineUploads(context.Context) ([]OfflineUpload, error)
	WriteOfflineChunk(context.Context, string, string, OfflineChunk) (OfflineUpload, error)
	DiscardOfflineUpload(context.Context, string) (OfflineUpload, error)
}
