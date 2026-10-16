package panelrecovery

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"

	"nginxpanel/internal/secure"
)

// CheckMaterial confirms that the fixed secrets still match a maintenance
// snapshot. It never parses SQLite or exposes key/certificate contents.
func CheckMaterial(ctx context.Context, receipt Receipt) error {
	if os.Geteuid() != 0 {
		return errors.New("快照密钥材料核对需要 root")
	}
	m := receipt.Manifest
	if err := receipt.Validate(m.DataDir, m.OperationID); err != nil {
		return err
	}
	return checkMaterialFiles(ctx, m.DataDir, m.UID, m.GID, m.Files)
}

func checkMaterialFiles(ctx context.Context, data string, uid, gid int, files []File) error {
	for i, expected := range files {
		if i == 0 {
			continue
		} // The database is allowed to migrate with the new program.
		f, info, err := openOwned(filepath.Join(data, expected.Name), uid, gid, resources[i].limit)
		if err != nil {
			return err
		}
		h := sha256.New()
		n, err := io.Copy(h, contextReader{ctx, io.LimitReader(f, resources[i].limit+1)})
		unchanged := secure.RootFileUnchanged(f, info)
		closed := f.Close()
		if err != nil || closed != nil {
			return errors.Join(err, closed)
		}
		if !unchanged || n != expected.Size || hex.EncodeToString(h.Sum(nil)) != expected.SHA256 {
			return errors.New("面板密钥或 TLS 材料与原维护快照不一致")
		}
	}
	return nil
}
