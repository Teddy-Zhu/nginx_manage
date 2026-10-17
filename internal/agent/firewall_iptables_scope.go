package agent

import (
	"errors"

	"nginxpanel/internal/firewall"
)

// Expectations come only from a validated local intent or confirmed source.
// A family commits both scopes together; independently matching one old and
// one new scope must never be mistaken for an accepted generation.
type iptablesInspectionScope struct {
	Program, Previous                              *firewall.IPTablesRuntimeProgram
	Docker, PreviousDocker                         *dockerIPTablesPolicyRecord
	Transition, AllowMissing, AllowPreviousMissing bool
	RequireDockerHook                              bool
}

type iptablesLibraryDockerScope struct {
	Generation  *firewall.IPTablesGeneration
	RequireHook bool
}

func classifyIPTablesScope(image iptablesImage, scope iptablesInspectionScope) (iptablesImage, string, *iptablesLibraryDockerScope, error) {
	next, previous := iptablesGeneration(scope.Program, image.Family), iptablesGeneration(scope.Previous, image.Family)
	docker, previousDocker := dockerIPTablesGeneration(scope.Docker, image.Family), dockerIPTablesGeneration(scope.PreviousDocker, image.Family)
	if docker == nil && previousDocker == nil {
		foreign, state, err := classifyIPTablesImage(image, next, previous, scope.Transition, scope.AllowMissing, scope.AllowPreviousMissing)
		if err == nil {
			err = proveEmptyDockerNamespace(foreign)
		}
		return foreign, state, nil, err
	}
	result := func(foreign iptablesImage, state string, actual *firewall.IPTablesGeneration) (iptablesImage, string, *iptablesLibraryDockerScope, error) {
		return foreign, state, &iptablesLibraryDockerScope{Generation: actual, RequireHook: scope.RequireDockerHook}, nil
	}
	if !scope.Transition {
		foreign, state, actual, err := classifyIPTablesConfirmedScope(image, next, docker, scope.AllowMissing)
		if err != nil {
			return iptablesImage{}, "", nil, err
		}
		return result(foreign, state, actual)
	}
	if foreign, err := iptablesCombinedForeignImage(image, next, docker); err == nil {
		return result(foreign, "candidate", docker)
	}
	if foreign, err := iptablesCombinedForeignImage(image, previous, previousDocker); err == nil {
		return result(foreign, "previous", previousDocker)
	}
	if scope.AllowPreviousMissing {
		foreign, state, actual, err := classifyIPTablesConfirmedScope(image, previous, previousDocker, true)
		if err == nil {
			if state == "missing" {
				state = "previous_missing"
			} else {
				state = "previous"
			}
			return result(foreign, state, actual)
		}
	}
	return iptablesImage{}, "", nil, errors.New("iptables 的 INPUT/Docker 范围不属于同一原确认或完整候选代际")
}

func classifyIPTablesConfirmedScope(image iptablesImage, host, docker *firewall.IPTablesGeneration, allowMissing bool) (iptablesImage, string, *firewall.IPTablesGeneration, error) {
	foreign, hostState, err := classifyIPTablesImage(image, host, nil, false, allowMissing, false)
	if err != nil {
		return iptablesImage{}, "", nil, err
	}
	if host != nil && hostState == "empty" {
		return iptablesImage{}, "", nil, errors.New("iptables 已确认的 INPUT 代际缺失")
	}
	actual, dockerMissing := docker, false
	stripped, err := dockerIPTablesForeignImage(foreign, docker)
	if err != nil && allowMissing && docker != nil && proveEmptyDockerNamespace(foreign) == nil {
		// A completely absent scope is observable without claiming ownership
		// of partial or changed objects. Reinstallation needs its own intent.
		stripped, actual, dockerMissing, err = foreign, nil, true, nil
	}
	if err != nil {
		return iptablesImage{}, "", nil, err
	}
	state := "empty"
	if host != nil || docker != nil {
		state = "candidate"
	}
	if hostState == "missing" || dockerMissing {
		state = "missing"
	}
	return stripped, state, actual, nil
}
