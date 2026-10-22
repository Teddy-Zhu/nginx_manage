package history

import "encoding/json"

// SnapshotRequest extends forwarding deadlines only for the fixed maintenance
// routes and the bounded snapshot category. The target still validates the full
// request and its permissions before opening any recovery material.
func SnapshotRequest(path string, body []byte) bool {
	switch path {
	case "/history/runtime/preview":
		var in RuntimeFilter
		return json.Unmarshal(body, &in) == nil && in.Kind == "recovery_snapshot"
	case "/history/runtime/execute":
		var in RuntimeExecuteInput
		return json.Unmarshal(body, &in) == nil && in.Filter.Kind == "recovery_snapshot"
	default:
		return false
	}
}
