package panelruntime

import "errors"

// LauncherRelease resolves only the immutable program named by the root-owned
// image binding. It is independent of the currently selected serve application.
func LauncherRelease(data string) (Snapshot, error) {
	d, err := ReadDeployment(data)
	if err != nil {
		return Snapshot{}, err
	}
	if d.Mode != "docker" {
		return Snapshot{}, errors.New("launcher 程序需要容器面板绑定")
	}
	s, err := ReadVersion(data, d.LauncherRelease)
	if err != nil {
		return s, err
	}
	if s.Deployment != d || s.Release.BinarySHA256 != d.LauncherSHA256 || s.Release.Version != d.SignedImage.Version {
		return s, errors.New("launcher 程序与镜像批准不一致")
	}
	return s, nil
}
