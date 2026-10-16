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
	if d.Mode != "docker" {
		return errors.New("Compose 仅用于已绑定的容器面板")
	}
	t, err := template.New("panel").Option("missingkey=error").Parse(docker.PanelCompose)
	if err != nil {
		return err
	}
	var nginx *nginxcontainer.Binding
	binding, err := nginxcontainer.Read(data)
	if err == nil {
		nginx = &binding
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return t.Execute(w, struct {
		Deployment
		Nginx *nginxcontainer.Binding
	}{d, nginx})
}
