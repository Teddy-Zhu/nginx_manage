package nginxcontainer

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/url"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"nginxpanel/internal/dockerapi"
	"nginxpanel/internal/releases"
	"nginxpanel/internal/secure"
)

func localImage(ctx context.Context, d *dockerClient, reference, expected string) (imageInfo, error) {
	var image imageInfo
	if !imageValue.MatchString(reference) || !strings.HasPrefix(expected, "sha256:") || !hashValue.MatchString(strings.TrimPrefix(expected, "sha256:")) {
		return image, errors.New("须指定签名镜像引用和当前架构配置摘要")
	}
	if err := d.JSON(ctx, "GET", "/images/"+url.PathEscape(reference)+"/json", nil, &image); err != nil {
		return image, err
	}
	matched := reference == image.ID
	for _, ref := range image.RepoDigests {
		if repositoryDigest(ref) == repositoryDigest(reference) {
			matched = true
		}
	}
	if !matched || !dockerapi.MatchesImageID(reference, expected, image.ID) || image.Os != "linux" || image.Architecture != runtime.GOARCH || len(image.Config.Volumes) != 0 {
		return image, errors.New("本地镜像引用、平台或内容身份不符合签名批准，或包含额外卷声明")
	}
	return image, nil
}

// imageArchive only creates a stopped metadata container, with no host mounts
// or network. No entry point is executed, including while validating binaries.
func imageArchive(ctx context.Context, d *dockerClient, imageID, path string, maximum int64, consume func(*tar.Reader) error) (runErr error) {
	var created struct {
		ID string `json:"Id"`
	}
	input := map[string]any{"Image": imageID, "Entrypoint": []string{"/nginxpanel-metadata-never-start"}, "Cmd": []string{}, "NetworkDisabled": true,
		"HostConfig": map[string]any{"NetworkMode": "none", "ReadonlyRootfs": true, "CapDrop": []string{"ALL"}, "SecurityOpt": []string{"no-new-privileges:true"}}}
	if err := d.JSON(ctx, "POST", "/containers/create?name=nginxpanel-metadata-"+secure.ID(), input, &created); err != nil {
		return err
	}
	if !hashValue.MatchString(created.ID) {
		return errors.New("Docker 未返回有效元数据容器 ID")
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := d.JSON(cleanup, "DELETE", "/containers/"+created.ID, nil, nil); err != nil {
			runErr = errors.Join(runErr, errors.New("未启动的镜像元数据容器未清理，请本机检查"))
		}
	}()
	resp, err := d.Request(ctx, "GET", "/containers/"+created.ID+"/archive?path="+url.QueryEscape(path), nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	limited := &io.LimitedReader{R: resp.Body, N: maximum + 1}
	if err := consume(tar.NewReader(limited)); err != nil {
		return err
	}
	if limited.N <= 0 {
		return errors.New("镜像归档超过读取预算")
	}
	return nil
}

func imageBinaryHash(ctx context.Context, d *dockerClient, imageID, path string, output io.Writer) (string, error) {
	if path != Bootstrap && path != "/usr/local/bin/nginxpanel-launcher" {
		return "", errors.New("镜像程序不属于固定启动器入口")
	}
	var actual string
	err := imageArchive(ctx, d, imageID, path, binaryLimit+(16<<10), func(t *tar.Reader) error {
		entry, err := t.Next()
		if err != nil {
			return err
		}
		if entry.Name != filepath.Base(path) || entry.Typeflag != tar.TypeReg || entry.Uid != 0 || entry.Gid != 0 || entry.Mode != 0555 || entry.Linkname != "" || entry.Size <= 0 || entry.Size > binaryLimit {
			return errors.New("镜像启动器须为 root 持有的固定只读普通程序")
		}
		h := sha256.New()
		destination := io.Writer(h)
		if output != nil {
			destination = io.MultiWriter(output, h)
		}
		n, err := io.Copy(destination, t)
		if err != nil {
			return err
		}
		if n != entry.Size {
			return errors.New("镜像启动器未完整读取")
		}
		if _, err = t.Next(); err != io.EOF {
			return errors.New("镜像启动器归档包含额外内容或未完整读取")
		}
		actual = hex.EncodeToString(h.Sum(nil))
		return nil
	})
	return actual, err
}

func imageBinary(ctx context.Context, d *dockerClient, imageID, path, expected string) error {
	if !hashValue.MatchString(expected) {
		return errors.New("镜像启动器缺少有效的内容散列")
	}
	actual, err := imageBinaryHash(ctx, d, imageID, path, nil)
	if err != nil {
		return err
	}
	if actual != expected {
		return errors.New("镜像启动器实际内容与批准散列不一致")
	}
	return nil
}

func verifyImageLauncherProtocol(image imageInfo, expected int) error {
	if expected != releases.LauncherVersion || image.Config.Labels["org.nginxpanel.launcher.protocol"] != strconv.Itoa(expected) {
		return errors.New("镜像启动器协议与当前核心不兼容")
	}
	return nil
}

// InspectPanelImage reuses the host-only Docker endpoint and metadata reader;
// the panel container itself is never given Docker access.
func InspectPanelImage(ctx context.Context, reference, configDigest, launcherSHA256 string) (string, error) {
	d, err := newDocker()
	if err != nil {
		return "", err
	}
	defer d.Close()
	image, err := localImage(ctx, d, reference, configDigest)
	if err != nil {
		return "", err
	}
	if err := imageBinary(ctx, d, image.ID, "/usr/local/bin/nginxpanel-launcher", launcherSHA256); err != nil {
		return "", err
	}
	return image.ID, nil
}

// InspectPanelImageBinding also preserves an already frozen daemon identity.
func InspectPanelImageBinding(ctx context.Context, reference, imageID, launcherSHA256 string) error {
	actual, err := InspectPanelImage(ctx, reference, imageID, launcherSHA256)
	if err != nil {
		return err
	}
	if actual != imageID {
		return errors.New("当前镜像内容身份与运行绑定不一致")
	}
	return nil
}
