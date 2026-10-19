package panelruntime

import (
	"errors"
	"io"
	"os"
	"text/template"

	"nginxpanel/deploy/docker"
	"nginxpanel/internal/nginxcontainer"
)

func WriteCompose(w io.Writer, data string) error {
	d, err := ReadDeployment(data)
	if err != nil {
		return err
	}
	return ComposeDeployment(w, d)
}

// ComposeDeployment renders an already approved binding without selecting it.
func ComposeDeployment(w io.Writer, d Deployment) error {
	if err := d.validate(d.DataDir); err != nil {
		return err
	}
	if d.Mode != "docker" {
		return errors.New("Compose 仅用于已绑定的容器面板")
	}
	t, err := template.New("panel").Option("missingkey=error").Parse(docker.PanelCompose)
	if err != nil {
		return err
	}
	var nginx *nginxcontainer.Binding
	binding, err := nginxcontainer.Read(d.DataDir)
	if err == nil {
		nginx = &binding
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return composeWithNginx(w, d, nginx, t)
}

// ComposeWithNginx freezes the container definition before selecting a candidate.
func ComposeWithNginx(w io.Writer, d Deployment, b nginxcontainer.Binding) error {
	if d.validate(d.DataDir) != nil || d.Mode != "docker" || b.Validate() != nil || b.DataDir != d.DataDir {
		return errors.New("Nginx 镜像 Compose 部署绑定无效")
	}
	t, err := template.New("panel").Option("missingkey=error").Parse(docker.PanelCompose)
	if err != nil {
		return err
	}
	return composeWithNginx(w, d, &b, t)
}
func composeWithNginx(w io.Writer, d Deployment, nginx *nginxcontainer.Binding, t *template.Template) error {
	return t.Execute(w, struct {
		Deployment
		Nginx *nginxcontainer.Binding
	}{d, nginx})
}
