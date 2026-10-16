package backup

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"

	"filippo.io/age"
	"golang.org/x/sys/unix"
	"nginxpanel/internal/secure"
)

type boundedWriter struct {
	w      io.Writer
	n, max int64
}

func (w *boundedWriter) Write(p []byte) (int, error) {
	if int64(len(p)) > w.max-w.n {
		return 0, errors.New("加密备份超过容量限制")
	}
	n, err := w.w.Write(p)
	w.n += int64(n)
	return n, err
}
func encodeArchive(ctx context.Context, dir, target string, m Manifest, recipient age.Recipient) (File, error) {
	if err := m.Validate(); err != nil {
		return File{}, err
	}
	f, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return File{}, err
	}
	defer f.Close()
	hash := sha256.New()
	output := &boundedWriter{w: io.MultiWriter(f, hash), max: ArchiveMax}
	cipher, err := age.Encrypt(output, recipient)
	if err != nil {
		return File{}, err
	}
	tw := tar.NewWriter(cipher)
	manifest, err := json.Marshal(m)
	if err != nil {
		return File{}, err
	}
	writeHeader := func(name string, size int64) error {
		return tw.WriteHeader(&tar.Header{Name: name, Size: size, Mode: 0600, Typeflag: tar.TypeReg, Format: tar.FormatUSTAR, ModTime: time.Unix(m.CreatedAt, 0)})
	}
	if err = writeHeader("manifest.json", int64(len(manifest))); err != nil {
		return File{}, err
	}
	if _, err = tw.Write(manifest); err != nil {
		return File{}, err
	}
	for i, r := range resources {
		expected := m.Files[i]
		source, info, e := openPrivate(filepath.Join(dir, r.local), r.limit)
		if e != nil {
			return File{}, e
		}
		if info.Size() != expected.Size {
			source.Close()
			return File{}, errors.New("备份暂存大小已变化")
		}
		if err = writeHeader(r.name, expected.Size); err != nil {
			source.Close()
			return File{}, err
		}
		check := sha256.New()
		n, e := io.Copy(io.MultiWriter(tw, check), contextReader{ctx, io.LimitReader(source, expected.Size+1)})
		unchanged := secure.RootFileUnchanged(source, info)
		source.Close()
		if e != nil {
			return File{}, e
		}
		if n != expected.Size || !unchanged || hex.EncodeToString(check.Sum(nil)) != expected.SHA256 {
			return File{}, errors.New("备份暂存与原清单不一致")
		}
	}
	if err = tw.Close(); err != nil {
		return File{}, err
	}
	if err = cipher.Close(); err != nil {
		return File{}, err
	}
	if err = f.Sync(); err != nil {
		return File{}, err
	}
	if err = f.Close(); err != nil {
		return File{}, err
	}
	if err = syncDir(filepath.Dir(target)); err != nil {
		return File{}, err
	}
	return File{Size: output.n, SHA256: hex.EncodeToString(hash.Sum(nil))}, nil
}
func (m Manifest) Validate() error {
	if (m.Runtime != "native" && m.Runtime != "docker" && m.Runtime != "development") || m.Runtime != "development" && !validHash.MatchString(m.ApplicationReleaseID) || m.Database.HeadVersion < 0 || m.Database.DesiredRevision != "" && !validID.MatchString(m.Database.DesiredRevision) || m.Database.AppliedRevision != "" && !validID.MatchString(m.Database.AppliedRevision) {
		return errors.New("完整备份的运行环境、程序或配置身份无效")
	}
	if m.Schema != Schema || m.Mode != "full" || !validID.MatchString(m.ID) || m.CreatedAt <= 0 || m.ApplicationVersion == "" || len(m.ApplicationVersion) > 128 || len(m.KeyCheck) < 32 || len(m.KeyCheck) > 128 || len(m.Files) != len(resources) || !validID.MatchString(m.Database.NodeID) || m.Database.SchemaVersion < 1 {
		return errors.New("完整备份清单不受支持或身份无效")
	}
	for i, r := range resources {
		f := m.Files[i]
		if f.Name != r.name || f.Size <= 0 || f.Size > r.limit || !validHash.MatchString(f.SHA256) {
			return errors.New("完整备份资源清单无效")
		}
	}
	if m.Files[1].Size != 32 {
		return errors.New("完整备份缺少匹配的业务密钥")
	}
	return nil
}
func decodeStrict(raw []byte, out any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(out); err != nil {
		return err
	}
	if d.Decode(new(any)) != io.EOF {
		return errors.New("备份记录包含额外数据")
	}
	return nil
}
func decryptArchive(ctx context.Context, input io.Reader, dir string, credentials InspectCredentials) (Manifest, error) {
	var m Manifest
	var identity age.Identity
	var err error
	if credentials.Identity != "" && credentials.Passphrase == "" {
		identity, err = age.ParseX25519Identity(credentials.Identity)
	} else if credentials.Identity == "" && passphraseValid(credentials.Passphrase) {
		var scrypt *age.ScryptIdentity
		scrypt, err = age.NewScryptIdentity(credentials.Passphrase)
		if err == nil {
			scrypt.SetMaxWorkFactor(18)
			identity = scrypt
		}
	} else {
		return m, errors.New("须临时提供一个 age 私钥或 16–256 字节口令")
	}
	if err != nil {
		return m, errors.New("恢复解密材料无效")
	}
	reader, err := age.Decrypt(contextReader{ctx, input}, identity)
	if err != nil {
		return m, errors.New("无法解密完整备份")
	}
	plain := io.LimitReader(reader, ArchiveMax+1)
	tr := tar.NewReader(plain)
	h, err := tr.Next()
	if err != nil || h.Name != "manifest.json" || h.Typeflag != tar.TypeReg || h.Linkname != "" || len(h.PAXRecords) != 0 || h.Size < 1 || h.Size > 128<<10 {
		return m, errors.New("完整备份首项必须为受限清单")
	}
	raw, err := io.ReadAll(io.LimitReader(tr, (128<<10)+1))
	if err != nil || int64(len(raw)) != h.Size || decodeStrict(raw, &m) != nil || m.Validate() != nil {
		return m, errors.New("完整备份清单无效")
	}
	for i, r := range resources {
		h, e := tr.Next()
		if e != nil || h.Name != r.name || h.Typeflag != tar.TypeReg || h.Linkname != "" || len(h.PAXRecords) != 0 || h.Size != m.Files[i].Size {
			return m, errors.New("完整备份资源缺失、重复或包含不允许的路径/类型")
		}
		f, e := os.OpenFile(filepath.Join(dir, r.local), os.O_CREATE|os.O_EXCL|os.O_WRONLY|unix.O_NOFOLLOW, 0600)
		if e != nil {
			return m, e
		}
		hash := sha256.New()
		n, e := io.Copy(io.MultiWriter(f, hash), contextReader{ctx, io.LimitReader(tr, r.limit+1)})
		closed := f.Close()
		if e != nil || closed != nil || n != h.Size || hex.EncodeToString(hash.Sum(nil)) != m.Files[i].SHA256 {
			return m, errors.New("完整备份资源的大小或散列不匹配")
		}
	}
	if _, err = tr.Next(); err != io.EOF {
		return m, errors.New("完整备份含有清单外资源")
	}
	// Read beyond the tar terminator to authenticate age's final chunk and reject
	// hidden payloads. No extraction result is usable before this succeeds.
	var extra [1]byte
	n, err := plain.Read(extra[:])
	if n != 0 || err != io.EOF {
		return m, errors.New("备份含有额外数据或加密认证未完成")
	}
	return m, nil
}
