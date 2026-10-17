package nginxcontainer

import "nginxpanel/internal/dockerapi"

type dockerClient = dockerapi.Client

func newDocker() (*dockerClient, error) { return dockerapi.New() }
