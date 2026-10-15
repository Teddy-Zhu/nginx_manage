package nginxcontainer

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"golang.org/x/sys/unix"
	"nginxpanel/internal/nginxruntime"
	"nginxpanel/internal/secure"
)

type BindInput struct {
	DataDir, Image, LauncherBinary string
	UID, GID                       int
}
type imageInfo struct {
	ID               string `json:"Id"`
	RepoDigests      []string
	Architecture, Os string
	Config           struct {
		Env     []string
		Volumes map[string]any
	}
}

func Read(data string) (Binding, error) {
	var b Binding
	name, err := Path(data)
	if err != nil {
		return b, err
	}
	raw, err := secure.ReadRootFile(name, 128<<10)
	if err != nil {
		return b, err
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&b) != nil || d.Decode(new(any)) != io.EOF || !bytes.Equal(canonical(b), raw) {
		return b, errors.New("Nginx 容器绑定格式无效")
	}
	if err = b.validate(data); err != nil {
		return b, err
	}
	info, err := os.Lstat(name)
	if err != nil {
		return b, err
	}
	if info.Mode().Perm() != 0444 {
		return b, errors.New("Nginx 容器绑定须为 root 只读文件")
	}
	return b, nil
}
func syncDir(name string) error {
	f, err := os.Open(name)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}
func publicDir(name string) error {
	if err := secure.RootDirectory(name, 0755); err != nil {
		return err
	}
	info, err := os.Lstat(name)
	if err != nil {
		return err
	}
	// Only the installer's public artifact directories use this helper. A
	// restrictive installer umask may leave its newly created directory 0700.
	if info.Mode().Perm() == 0700 {
		return os.Chmod(name, 0755)
	}
	if info.Mode().Perm() != 0755 {
		return errors.New("容器绑定目录权限无效")
	}
	return nil
}
func imageMetadata(ctx context.Context, d *dockerClient, imageID string) (files map[string][]byte, runErr error) {
	var created struct {
		ID string `json:"Id"`
	}
	input := map[string]any{"Image": imageID, "Entrypoint": []string{Binary}, "Cmd": []string{"-V"}, "NetworkDisabled": true, "HostConfig": map[string]any{"NetworkMode": "none", "ReadonlyRootfs": true, "CapDrop": []string{"ALL"}, "SecurityOpt": []string{"no-new-privileges:true"}}}
	if err := d.json(ctx, "POST", "/containers/create?name=nginxpanel-metadata-"+secure.ID(), input, &created); err != nil {
		return nil, err
	}
	if !hashValue.MatchString(created.ID) {
		return nil, errors.New("Docker 未返回有效元数据容器 ID")
	}
	// This temporary container is never started and is removed without force.
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := d.json(cleanup, "DELETE", "/containers/"+created.ID, nil, nil); err != nil {
			runErr = errors.Join(runErr, errors.New("未启动的镜像元数据容器未清理，请本机检查"))
		}
	}()
	resp, err := d.request(ctx, "GET", "/containers/"+created.ID+"/archive?path="+url.QueryEscape("/usr/share/nginxpanel"), nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	files = map[string][]byte{}
	limited := &io.LimitedReader{R: resp.Body, N: 256<<10 + 1}
	t := tar.NewReader(limited)
	for count := 0; ; count++ {
		entry, err := t.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if count > 8 || entry.Size < 0 || entry.Size > 64<<10 {
			return nil, errors.New("镜像元数据超过预算")
		}
		name := strings.TrimPrefix(entry.Name, "nginxpanel/")
		if entry.Typeflag == tar.TypeDir && strings.TrimSuffix(entry.Name, "/") == "nginxpanel" {
			continue
		}
		if entry.Typeflag != tar.TypeReg || entry.Uid != 0 || entry.Mode&0022 != 0 || (name != "capabilities.json" && name != "nginx-build.txt" && name != "nginx.sha256" && name != "launcher.sha256") || files[name] != nil {
			return nil, errors.New("镜像元数据包含非预期文件或链接")
		}
		value, err := io.ReadAll(t)
		if err != nil {
			return nil, err
		}
		files[name] = value
	}
	if limited.N <= 0 || len(files) != 4 {
		return nil, errors.New("镜像缺少完整的预置模块/程序元数据")
	}
	return files, nil
}
func checksum(raw []byte, name string) (string, error) {
	fields := strings.Fields(string(raw))
	if len(fields) != 2 || !hashValue.MatchString(fields[0]) || fields[1] != name {
		return "", errors.New("镜像程序散列清单无效")
	}
	return fields[0], nil
}

// Bind admits an already-local immutable image; it never pulls, builds, starts
// a container or changes an existing Nginx selection.
func Bind(ctx context.Context, in BindInput) (Binding, error) {
	var b Binding
	if os.Geteuid() != 0 {
		return b, errors.New("Nginx 容器登记需要本机 root")
	}
	name, err := Path(in.DataDir)
	if err != nil {
		return b, err
	}
	if !imageValue.MatchString(in.Image) || in.UID <= 0 || in.GID <= 0 {
		return b, errors.New("须明确固定镜像摘要及独立非 root Nginx 身份")
	}
	launcher, err := filepath.EvalSymlinks(in.LauncherBinary)
	if err != nil {
		return b, err
	}
	launcherHash, err := secure.HashRootFile(launcher, binaryLimit)
	if err != nil {
		return b, err
	}
	unlock, err := nginxruntime.LockSelection(in.DataDir)
	if err != nil {
		return b, err
	}
	defer unlock()
	if prior, err := Read(in.DataDir); err == nil {
		if prior.Image != in.Image || prior.UID != in.UID || prior.GID != in.GID || prior.BootstrapSHA256 != launcherHash {
			return b, errors.New("已有不同 Nginx 容器绑定，切换须进入维护流程")
		}
		return prior, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return b, err
	}
	if _, err = os.Lstat(filepath.Join(in.DataDir, "bin", "components", "nginx.json")); err == nil {
		return b, errors.New("已有原生 Nginx 安装登记，不能直接改为容器")
	} else if !errors.Is(err, os.ErrNotExist) {
		return b, err
	}
	d, err := newDocker()
	if err != nil {
		return b, err
	}
	defer d.close()
	var image imageInfo
	if err = d.json(ctx, "GET", "/images/"+url.PathEscape(in.Image)+"/json", nil, &image); err != nil {
		return b, err
	}
	matched := false
	for _, ref := range image.RepoDigests {
		if repositoryDigest(ref) == repositoryDigest(in.Image) {
			matched = true
		}
	}
	if !matched || image.Os != "linux" || image.Architecture != runtime.GOARCH || len(image.Config.Volumes) != 0 || !strings.HasPrefix(image.ID, "sha256:") || !hashValue.MatchString(strings.TrimPrefix(image.ID, "sha256:")) {
		return b, errors.New("本地镜像摘要、平台或卷声明不符合固定运行要求")
	}
	files, err := imageMetadata(ctx, d, image.ID)
	if err != nil {
		return b, err
	}
	var c Capabilities
	decoder := json.NewDecoder(bytes.NewReader(files["capabilities.json"]))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&c) != nil || decoder.Decode(new(any)) != io.EOF {
		return b, errors.New("镜像能力清单格式无效")
	}
	nginxHash, err := checksum(files["nginx.sha256"], Binary)
	if err != nil {
		return b, err
	}
	bootstrapHash, err := checksum(files["launcher.sha256"], Bootstrap)
	if err != nil {
		return b, err
	}
	if bootstrapHash != launcherHash {
		return b, errors.New("Nginx 镜像启动器与本机批准的面板程序不一致")
	}
	b = Binding{Schema: Schema, DataDir: in.DataDir, Image: in.Image, ImageID: image.ID, Architecture: image.Architecture, UID: in.UID, GID: in.GID, BinarySHA256: nginxHash, BootstrapSHA256: bootstrapHash, Build: string(files["nginx-build.txt"]), Capabilities: c, Environment: image.Config.Env, BoundAt: time.Now().Unix()}
	if err = b.validate(in.DataDir); err != nil {
		return b, err
	}
	for _, path := range []string{in.DataDir, filepath.Join(in.DataDir, "bin"), filepath.Dir(name)} {
		if err = publicDir(path); err != nil {
			return b, err
		}
	}
	tmp, err := os.CreateTemp(filepath.Dir(name), ".container-bind-")
	if err != nil {
		return b, err
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()
	if _, err = tmp.Write(canonical(b)); err != nil {
		return b, err
	}
	if err = tmp.Chmod(0444); err != nil {
		return b, err
	}
	if err = tmp.Sync(); err != nil {
		return b, err
	}
	if err = tmp.Close(); err != nil {
		return b, err
	}
	if err = ctx.Err(); err != nil {
		return b, err
	}
	if err = unix.Renameat2(unix.AT_FDCWD, tmp.Name(), unix.AT_FDCWD, name, unix.RENAME_NOREPLACE); err != nil {
		return b, err
	}
	if err = syncDir(filepath.Dir(name)); err != nil {
		return b, err
	}
	return Read(in.DataDir)
}
