package nginxconfig

import (
	"regexp"
	"strings"
)

var logResourceID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// Fixed live names cannot collide with the Agent's immutable archive names.
func ManagedLogPath(name string) (kind, resourceID string, ok bool) {
	parts := strings.Split(name, "/")
	if len(parts) == 3 && parts[0] == "logs" && parts[1] == "nginx-global" && (parts[2] == "access.log" || parts[2] == "error.log") {
		return "global", "", true
	}
	if len(parts) != 4 || parts[0] != "logs" || (parts[1] != "nginx" && parts[1] != "stream") || !logResourceID.MatchString(parts[2]) || (parts[3] != "access.log" && parts[3] != "error.log" && (parts[1] != "stream" || parts[3] != "session.log")) {
		return "", "", false
	}
	return parts[1], parts[2], true
}
