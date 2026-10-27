// Package containers provides basic host Docker inspection and lifecycle operations.
package containers

import (
	"nginxpanel/internal/fault"
	"regexp"
)

var containerID = regexp.MustCompile(`^[0-9a-f]{64}$`)

type Control struct {
	ID     string `json:"id"`
	Action string `json:"action"`
}

func ValidID(id string) bool { return containerID.MatchString(id) }
func (c Control) Validate() error {
	if !ValidID(c.ID) || c.Action != "start" && c.Action != "stop" && c.Action != "restart" {
		return fault.Invalid("请选择容器及启动、停止或重启操作")
	}
	return nil
}

type Port struct {
	Address  string `json:"address"`
	Public   int    `json:"public"`
	Private  int    `json:"private"`
	Protocol string `json:"protocol"`
}
type Container struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Image     string `json:"image"`
	State     string `json:"state"`
	Created   int64  `json:"created"`
	Ports     []Port `json:"ports"`
	Project   string `json:"project"`
	Service   string `json:"service"`
	Protected bool   `json:"protected"`
}
type Overview struct {
	Available  bool        `json:"available"`
	Reason     string      `json:"reason"`
	Containers []Container `json:"containers"`
}
type Mount struct {
	Source   string `json:"source"`
	Target   string `json:"target"`
	ReadOnly bool   `json:"read_only"`
}
type Network struct {
	Name    string `json:"name"`
	Address string `json:"address"`
	Gateway string `json:"gateway"`
}
type Detail struct {
	Container
	ImageID       string    `json:"image_id"`
	Started       string    `json:"started"`
	Finished      string    `json:"finished"`
	Restarts      int       `json:"restarts"`
	RestartPolicy string    `json:"restart_policy"`
	Health        string    `json:"health"`
	ExitCode      int       `json:"exit_code"`
	NetworkMode   string    `json:"network_mode"`
	Networks      []Network `json:"networks"`
	Mounts        []Mount   `json:"mounts"`
}
type Logs struct {
	Text      string `json:"text"`
	Truncated bool   `json:"truncated"`
}
