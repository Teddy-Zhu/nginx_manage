package panelready

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"nginxpanel/internal/panelruntime"
	"nginxpanel/internal/secure"
)

type ReleaseStatus struct {
	Protocol      int    `json:"protocol"`
	PID           int    `json:"pid"`
	Version       string `json:"version"`
	Mode          string `json:"mode"`
	ReleaseID     string `json:"release_id"`
	NodeID        string `json:"node_id"`
	RestoreID     string `json:"restore_id"`
	MaintenanceID string `json:"maintenance_id"`
	ReleasedAt    int64  `json:"released_at"`
}

func (s ReleaseStatus) Validate() error {
	if s.Protocol != Protocol || s.PID <= 1 || s.Version == "" || len(s.Version) > 128 || s.Mode != "native" && s.Mode != "docker" || !digestValue.MatchString(s.ReleaseID) || !idValue.MatchString(s.NodeID) || !idValue.MatchString(s.RestoreID) || !idValue.MatchString(s.MaintenanceID) || s.ReleasedAt <= 0 || s.ReleasedAt > time.Now().Unix()+300 {
		return errors.New("应用维护释放尚未确认")
	}
	return nil
}

// The same authenticated local socket proves both the committed DB release
// and the original process identity. A root release receipt alone is insufficient.
func ReadRelease(ctx context.Context, s panelruntime.Snapshot, pid, parentPID int, restoreID, maintenanceID string) (out ReleaseStatus, err error) {
	if !idValue.MatchString(restoreID) || !idValue.MatchString(maintenanceID) {
		return out, errors.New("维护释放查询身份无效")
	}
	node, _, err := readLocal(ctx, s, pid, parentPID, "/v1/maintenance-release/"+restoreID+"/"+maintenanceID, &out)
	if err != nil {
		return out, err
	}
	if err = out.Validate(); err != nil {
		return out, err
	}
	if out.PID != pid || out.ReleaseID != s.Release.ID || out.Version != s.Release.Version || out.Mode != s.Deployment.Mode || out.NodeID != node || out.RestoreID != restoreID || out.MaintenanceID != maintenanceID {
		return out, errors.New("应用维护释放回执不属于原进程、恢复或维护会话")
	}
	return out, nil
}

func serveRelease(w http.ResponseWriter, r *http.Request, nodeID string, released func(context.Context, string, string) (ReleaseStatus, error)) {
	id := secure.ID()
	out := struct {
		Code      string         `json:"code"`
		Message   string         `json:"message"`
		Data      *ReleaseStatus `json:"data"`
		RequestID string         `json:"request_id"`
		NodeID    string         `json:"node_id"`
	}{Code: "NOT_FOUND", Message: "接口不存在", RequestID: id, NodeID: nodeID}
	code := http.StatusNotFound
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/v1/maintenance-release/"), "/")
	if r.Method == http.MethodGet && r.URL.RawQuery == "" && len(parts) == 2 && idValue.MatchString(parts[0]) && idValue.MatchString(parts[1]) {
		call, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		s, err := released(call, parts[0], parts[1])
		if err == nil {
			err = s.Validate()
		}
		if err == nil {
			out.Code, out.Message, out.Data, code = "OK", "操作成功", &s, http.StatusOK
		} else {
			out.Code, out.Message, code = "NOT_READY", "应用维护释放尚未确认", http.StatusServiceUnavailable
		}
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Request-ID", id)
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(out)
}
