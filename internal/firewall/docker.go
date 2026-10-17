package firewall

// DockerRuntime describes bounded, read-only daemon reports. Equal reports
// before and after collection are not an atomic snapshot or a write grant.
type DockerRuntime struct {
	Available      bool                  `json:"available"`
	EngineHash     string                `json:"engine_hash"`
	Version        string                `json:"version"`
	APIVersion     string                `json:"api_version"`
	SnapshotHash   string                `json:"snapshot_hash"`
	ObservedAt     int64                 `json:"observed_at"`
	Rootless       bool                  `json:"rootless"`
	Swarm          string                `json:"swarm"`
	Networks       int                   `json:"networks"`
	Containers     int                   `json:"containers"`
	PublishedPorts int                   `json:"published_ports"`
	Ports          []DockerPublishedPort `json:"ports"`
	Truncated      bool                  `json:"truncated"`
	Reason         string                `json:"reason"`
}

type DockerPublishedPort struct {
	ContainerID   string   `json:"container_id"`
	Family        string   `json:"family"`
	Protocol      string   `json:"protocol"`
	HostIP        string   `json:"host_ip"`
	HostPort      int      `json:"host_port"`
	ContainerPort int      `json:"container_port"`
	NetworkIDs    []string `json:"network_ids"`
	Path          string   `json:"path"`
	Reason        string   `json:"reason"`
}

type DockerCapability struct {
	Backend   string `json:"backend"`
	Family    string `json:"family"`
	Hook      string `json:"hook"`
	Observed  bool   `json:"observed"`
	Supported bool   `json:"supported"`
	Reason    string `json:"reason"`
}

func EmptyDockerRuntime(reason string) DockerRuntime {
	return DockerRuntime{Ports: []DockerPublishedPort{}, Reason: reason}
}
