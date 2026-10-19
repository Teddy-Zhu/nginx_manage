package nginxcontainer

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"

	"nginxpanel/internal/nginxruntime"
	"nginxpanel/internal/secure"
)

func (b Binding) Validate() error { return b.validate(b.DataDir) }

// AdmitCandidate authenticates image contents without replacing the existing
// runtime binding or starting an image. Identities and storage stay fixed.
func AdmitCandidate(ctx context.Context, in BindInput, before Binding) (Binding, error) {
	var zero Binding
	if os.Geteuid() != 0 || before.Validate() != nil || in.DataDir != before.DataDir || in.UID != before.UID || in.GID != before.GID || in.Image == before.Image {
		return zero, errors.New("候选镜像必须保留当前 Nginx 数据目录和身份")
	}
	current, err := Read(in.DataDir)
	if err != nil {
		return zero, err
	}
	if !reflect.DeepEqual(current, before) {
		return zero, errors.New("当前 Nginx 绑定已变化")
	}
	launcher, err := filepath.EvalSymlinks(in.LauncherBinary)
	if err != nil {
		return zero, err
	}
	hash, err := secure.HashRootFile(launcher, binaryLimit)
	if err != nil {
		return zero, err
	}
	approval, err := admitSource(in, hash, nil)
	if err != nil {
		return zero, err
	}
	d, err := newDocker()
	if err != nil {
		return zero, err
	}
	defer d.Close()
	image, err := localImage(ctx, d, in.Image, approval.Image.Platform.ConfigDigest)
	if err != nil {
		return zero, err
	}
	if image.ID == before.ImageID {
		return zero, errors.New("候选与原 Nginx 镜像配置摘要相同")
	}
	if err = imageBinary(ctx, d, image.ID, Bootstrap, hash); err != nil {
		return zero, err
	}
	candidate, err := bindingMetadata(ctx, d, in, approval, image, hash)
	if err != nil {
		return zero, err
	}
	current, err = Read(in.DataDir)
	if err != nil {
		return zero, err
	}
	if !reflect.DeepEqual(current, before) {
		return zero, errors.New("镜像准入期间 Nginx 绑定变化")
	}
	return candidate, nil
}

// VerifyRetainedImage compares the frozen local contents with their original
// root approval. Compensation never depends on retaining target source files.
func VerifyRetainedImage(ctx context.Context, b Binding) error {
	if os.Geteuid() != 0 {
		return errors.New("Nginx 镜像核对仅允许宿主机 root")
	}
	if err := b.Validate(); err != nil {
		return err
	}
	d, err := newDocker()
	if err != nil {
		return err
	}
	defer d.Close()
	image, err := localImage(ctx, d, b.Image, b.ImageID)
	if err != nil {
		return err
	}
	if err = imageBinary(ctx, d, image.ID, Bootstrap, b.BootstrapSHA256); err != nil {
		return err
	}
	actual, err := bindingMetadata(ctx, d, BindInput{DataDir: b.DataDir, Image: b.Image, UID: b.UID, GID: b.GID}, b.SignedImage, image, b.BootstrapSHA256)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(actual, b) {
		return errors.New("保留的 Nginx 镜像内容偏离原批准记录")
	}
	return nil
}

func SameIdentity(before, after Binding) bool {
	return before.Validate() == nil && after.Validate() == nil && before.DataDir == after.DataDir && before.UID == after.UID && before.GID == after.GID
}

// SelectBinding accepts only either frozen side of the independent transaction.
// The caller must durably choose its direction before stopping the old runtime.
func SelectBinding(before, after Binding) error {
	if os.Geteuid() != 0 || !SameIdentity(before, after) {
		return errors.New("Nginx 镜像切换不得改变存储和运行身份")
	}
	unlock, err := nginxruntime.LockSelection(before.DataDir)
	if err != nil {
		return err
	}
	defer unlock()
	name, err := Path(before.DataDir)
	if err != nil {
		return err
	}
	f, info, err := secure.OpenRootFile(name, 128<<10)
	if err != nil {
		return err
	}
	defer f.Close()
	current, err := secure.ReadRootFile(name, 128<<10)
	if err != nil {
		return err
	}
	if info.Mode().Perm() != 0444 || !secure.RootFileUnchanged(f, info) {
		return errors.New("Nginx 镜像绑定读取期间变化")
	}
	wanted := canonical(after)
	if bytes.Equal(current, wanted) {
		return syncDir(filepath.Dir(name))
	}
	if !bytes.Equal(current, canonical(before)) {
		return errors.New("Nginx 镜像绑定已偏离原事务")
	}
	tmp, err := os.CreateTemp(filepath.Dir(name), ".image-select-")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()
	if _, err = tmp.Write(wanted); err != nil {
		return err
	}
	if err = tmp.Chmod(0444); err != nil {
		return err
	}
	if err = tmp.Sync(); err != nil {
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	live, err := os.Lstat(name)
	if err != nil {
		return err
	}
	if !os.SameFile(live, info) || !secure.RootFileUnchanged(f, info) {
		return errors.New("Nginx 镜像绑定在切换前变化")
	}
	if err = os.Rename(tmp.Name(), name); err != nil {
		return err
	}
	return syncDir(filepath.Dir(name))
}
