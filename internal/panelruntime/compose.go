package panelruntime

import (
	"io"
	"text/template"

	"nginxpanel/deploy/docker"
)

func WriteCompose(w io.Writer, data string) error {
	d, err := ReadDeployment(data)
	if err != nil {
		return err
	}
	t, err := template.New("panel").Option("missingkey=error").Parse(docker.PanelCompose)
	if err != nil {
		return err
	}
	return t.Execute(w, d)
}
