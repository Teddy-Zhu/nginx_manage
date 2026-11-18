package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"nginxpanel/internal/componentversions"
	"nginxpanel/internal/fault"
	"nginxpanel/internal/nginxcontainer"
	"nginxpanel/internal/panelruntime"
	"nginxpanel/internal/releases"
	"nginxpanel/internal/secure"
	"nginxpanel/internal/software"
	"nginxpanel/internal/storage"
)

func nginxBundle(data string) (string, string, error) {
	raw, err := secure.ReadRootFile("/etc/nginxpanel/install/intent", 4096)
	if err != nil {
		return "", "", err
	}
	intent := string(raw)
	path, hash := "", ""
	for _, line := range strings.Split(intent, "\n") {
		switch key, value, _ := strings.Cut(line, "="); key {
		case "nginx_package":
			path = value
		case "image_manifest_sha256":
			hash = value
		}
	}
	if path == "" {
		return "", "", os.ErrNotExist
	}
	if !strings.HasPrefix(intent, nativeInstallationStamp) || !strings.Contains(intent, "\npanel_mode=native\n") ||
		!strings.Contains(intent, "\ndata="+data+"\n") || !strings.Contains(intent, "\nnginx_image=\n") ||
		!strings.HasPrefix(path, "/opt/nginxpanel/") || filepath.Clean(path) != path || !panelSelectionDigest.MatchString(hash) {
		return "", "", errors.New("配套 Nginx 安装记录无效")
	}
	return path, hash, nil
}

// The Compose file commits a deferred installation. A provisional binding can
// be reused by the next install task after an interrupted first start.
func BundledNginxPending(data string) (bool, error) {
	if _, _, err := nginxBundle(data); err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	_, err := os.Lstat(panelruntime.DockerComposePath)
	if os.IsNotExist(err) {
		return true, nil
	}
	return false, err
}

func (s *Server) installBundledNginx(ctx context.Context, progress software.Progress) (out software.Result, resultErr error) {
	out.AppID = "nginx"
	if s.Dev || s.ComponentScope != "host" || s.MaintenanceScope != "host" || s.CoreReload == nil || s.Nginx != nil {
		return out, fault.Unavailable("当前环境不支持首次安装 Nginx")
	}
	unlock, err := (&Journal{Dir: "/run/nginxpanel-install"}).rootLock("lock")
	if err != nil {
		return out, err
	}
	defer unlock()
	pending, err := BundledNginxPending(s.DataDir)
	if err != nil {
		return out, err
	}
	if !pending {
		return out, fault.Conflict("没有待安装的配套 Nginx")
	}
	if fenced, err := storage.WriterFenced(s.DataDir); err != nil || fenced {
		if err != nil {
			return out, err
		}
		return out, fault.Conflict("数据恢复期间无法安装 Nginx")
	}
	deployment, err := panelruntime.ReadDeployment(s.DataDir)
	if err != nil {
		return out, err
	}
	binding, err := s.bindBundledNginx(ctx, progress)
	if err != nil {
		return out, err
	}
	nginx := &Nginx{DataDir: s.DataDir, WorkerUser: "nginxpanel-nginx", LogOwner: s.NginxLogOwner, Policy: s.Policy,
		Container: &nginxcontainer.Runtime{Binding: binding}, Journal: s.Journal}
	if err := nginx.Open(); err != nil {
		return out, err
	}
	defer nginx.Close()
	progress("正在准备 Nginx 初始配置")
	if err := nginx.Initialize(); err != nil {
		return out, err
	}
	_, revision, err := nginx.active()
	if err != nil {
		return out, err
	}
	if _, err := nginxcontainer.ReadContainer(ctx, binding); err != nil && !os.IsNotExist(err) {
		return out, fmt.Errorf("无法核对现有 Nginx 容器：%w", err)
	}
	var compose bytes.Buffer
	if err := panelruntime.ComposeWithNginx(&compose, deployment, binding); err != nil {
		return out, err
	}
	dir := filepath.Dir(panelruntime.DockerComposePath)
	if err := secure.RootDirectory(dir, 0755); err != nil {
		return out, err
	}
	parent, err := os.Open(dir)
	if err != nil {
		return out, err
	}
	defer parent.Close()
	file, err := os.CreateTemp(dir, ".nginx-install-")
	if err != nil {
		return out, err
	}
	defer os.Remove(file.Name())
	defer file.Close()
	if _, err := file.Write(compose.Bytes()); err != nil {
		return out, err
	}
	if err := file.Chmod(0444); err != nil {
		return out, err
	}
	if err := file.Sync(); err != nil {
		return out, err
	}
	if err := file.Close(); err != nil {
		return out, err
	}
	progress("正在启动 Nginx 容器")
	committed := false
	defer func() {
		if committed || resultErr == nil {
			return
		}
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 75*time.Second)
		defer cancel()
		if err := removeProvisionalNginx(cleanup, binding); err != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("清理未完成的 Nginx 容器失败：%w", err))
		}
	}()
	out.Log, err = software.DockerLocal(ctx, progress, nil, "compose", "--project-directory", dir, "-f", file.Name(), "up", "-d", "--no-recreate", "--pull", "never", "nginx")
	if err != nil {
		return out, err
	}
	progress("正在确认 Nginx 运行状态")
	check, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := nginx.waitObserved(check, revision); err != nil {
		return out, fmt.Errorf("Nginx 启动后未通过运行确认，可查看容器日志后重试：%w", err)
	}
	if err := unix.Renameat2(unix.AT_FDCWD, file.Name(), unix.AT_FDCWD, panelruntime.DockerComposePath, unix.RENAME_NOREPLACE); err != nil {
		return out, err
	}
	if err := parent.Sync(); err != nil {
		if removeErr := os.Remove(panelruntime.DockerComposePath); removeErr != nil {
			committed = true
			return out, errors.Join(err, removeErr)
		}
		return out, err
	}
	committed = true
	out.Message = "Nginx 已安装并启动"
	return out, nil
}

func removeProvisionalNginx(ctx context.Context, binding nginxcontainer.Binding) error {
	container, err := nginxcontainer.ReadContainer(ctx, binding)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	id := container.Instance.ID
	if err := nginxcontainer.ContainerAction(ctx, binding, id, "stop"); err != nil {
		return err
	}
	return nginxcontainer.ContainerAction(ctx, binding, id, "remove")
}

func (s *Server) bindBundledNginx(ctx context.Context, progress software.Progress) (nginxcontainer.Binding, error) {
	var empty nginxcontainer.Binding
	dir, hash, err := nginxBundle(s.DataDir)
	if err != nil {
		return empty, err
	}
	name := filepath.Join(dir, "containers.json")
	raw, err := secure.ReadRootFile(name, 2<<20)
	if err != nil {
		return empty, err
	}
	var pkg releases.ContainerPackage
	if secure.Hash(raw) != hash || json.Unmarshal(raw, &pkg) != nil || !panelSelectionDigest.MatchString(pkg.BinarySHA256) {
		return empty, errors.New("配套 Nginx 镜像清单与安装记录不一致")
	}
	captured := filepath.Join(s.DataDir, "bin", "components", "bundled-nginx.json")
	if previous, err := nginxcontainer.Read(s.DataDir); err == nil {
		if previous.SignedImage.LocalBuild && previous.SignedImage.TrustPath == captured && previous.BootstrapSHA256 == pkg.BinarySHA256 {
			return previous, nil
		}
		return empty, errors.New("已有不同 Nginx 绑定，请检查原安装记录")
	} else if !os.IsNotExist(err) {
		return empty, err
	}
	archive, before, err := secure.OpenRootFile(filepath.Join(dir, "container-images.tar"), 512<<20)
	if err != nil {
		return empty, err
	}
	defer archive.Close()
	progress("正在导入安装包中的 Nginx 镜像")
	if _, err := software.DockerLocal(ctx, progress, archive, "image", "load"); err != nil {
		return empty, err
	}
	if !secure.RootFileUnchanged(archive, before) {
		return empty, errors.New("导入时 Nginx 镜像文件发生变化")
	}
	// Docker's image store can assign a different ID when loading the same
	// archive. The destination image is subsequently verified by Bind.
	tag := "nginxpanel-build-nginx:" + pkg.Architecture + "-" + pkg.BinarySHA256
	image, err := software.DockerLocal(ctx, nil, nil, "image", "inspect", "--format", "{{.Id}}", tag)
	if err != nil {
		return empty, err
	}
	pkg.Images = map[string]string{"nginx": image}
	if err := componentversions.WriteFile(captured, pkg); err != nil {
		return empty, err
	}
	worker, err := user.Lookup("nginxpanel-nginx")
	if err != nil {
		return empty, err
	}
	uid, err := strconv.Atoi(worker.Uid)
	if err != nil {
		return empty, err
	}
	gid, err := strconv.Atoi(worker.Gid)
	if err != nil {
		return empty, err
	}
	return nginxcontainer.Bind(ctx, nginxcontainer.BindInput{DataDir: s.DataDir, Image: image,
		LauncherBinary: filepath.Join(dir, "nginxpanel"), UID: uid, GID: gid,
		Signature: releases.ImageInput{LocalManifestPath: captured}})
}
