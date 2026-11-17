package frpscontainer

import "nginxpanel/internal/frps"

// Configuration is for the privileged component adapter. The token remains in
// the host process and is never included in a version-catalog response.
func Configuration(data string) (frps.Config, bool, error) {
	r, err := read(data)
	return r.Config, r.Installed, err
}
