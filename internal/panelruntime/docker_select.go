package panelruntime

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	"nginxpanel/internal/secure"
)

const DockerComposePath = "/etc/nginxpanel/docker/compose.yaml"
const DockerComposeLimit = 32 << 10

// SameDockerApplication allows only the image and its authenticated launcher to
// change. It cannot change identities, storage, listen address or application.
func SameDockerApplication(before, after Deployment) bool {
	if before.Mode != "docker" || after.Mode != "docker" || before.validate(before.DataDir) != nil || after.validate(after.DataDir) != nil {
		return false
	}
	after.Image, after.ImageID, after.LauncherSHA256, after.SignedImage = before.Image, before.ImageID, before.LauncherSHA256, before.SignedImage
	return before == after
}

func replaceDockerFile(name string, before, after []byte, limit int64) error {
	f, info, err := secure.OpenRootFile(name, limit)
	if err != nil {
		return err
	}
	defer f.Close()
	raw, err := secure.ReadRootFile(name, limit)
	if err != nil {
		return err
	}
	if info.Mode().Perm() != 0444 || !secure.RootFileUnchanged(f, info) {
		return errors.New("容器部署文件归属或读取代次变化")
	}
	if bytes.Equal(raw, after) {
		return syncDir(filepath.Dir(name))
	}
	if !bytes.Equal(raw, before) {
		return errors.New("容器部署文件已偏离原事务，禁止覆盖")
	}
	tmp, err := os.CreateTemp(filepath.Dir(name), ".image-select-")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()
	if _, err = tmp.Write(after); err != nil {
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
		return errors.New("容器部署文件在切换前变化")
	}
	if err = os.Rename(tmp.Name(), name); err != nil {
		return err
	}
	return syncDir(filepath.Dir(name))
}

// SelectDockerImage is called only after the independent root transaction has
// persisted its direction and stopped/removed the authenticated old container.
// Each file accepts only its frozen before/after bytes, so a crash between the
// two renames can be resumed in either persisted direction.
func SelectDockerImage(before, after Deployment, beforeCompose, afterCompose []byte) error {
	if os.Geteuid() != 0 || !SameDockerApplication(before, after) || len(beforeCompose) == 0 || len(afterCompose) == 0 || len(beforeCompose) > DockerComposeLimit || len(afterCompose) > DockerComposeLimit {
		return errors.New("镜像切换部署或 Compose 无效")
	}
	root, _ := Root(before.DataDir)
	unlock, err := publicationLock(root)
	if err != nil {
		return err
	}
	defer unlock()
	if err = replaceDockerFile(DockerComposePath, beforeCompose, afterCompose, DockerComposeLimit); err != nil {
		return err
	}
	oldRaw, _ := json.Marshal(before)
	newRaw, _ := json.Marshal(after)
	return replaceDockerFile(filepath.Join(root, "launcher.json"), oldRaw, newRaw, DeploymentLimit)
}
