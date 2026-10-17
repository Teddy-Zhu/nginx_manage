package logs

import (
	"encoding/json"
	"fmt"
	"strings"

	"nginxpanel/internal/fault"
)

const EventFormat = "nginxpanel_event"

// Event is deliberately closed: no free-form message, error, configuration,
// request payload, principal name or credentials can enter managed event files.
type Event struct {
	Sequence  int64  `json:"sequence"`
	Time      int64  `json:"time"`
	Category  string `json:"category"`
	Level     string `json:"level"`
	Code      string `json:"code"`
	TaskID    string `json:"task_id"`
	Kind      string `json:"kind"`
	State     string `json:"state"`
	Stage     string `json:"stage"`
	RequestID string `json:"request_id"`
	Count     int64  `json:"count"`
}

func EventToken(value string, limit int) bool {
	return len(value) <= limit && strings.Trim(value, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-/()*:") == ""
}

func EventID(value string) bool {
	if len(value) != 36 {
		return false
	}
	for i, c := range value {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return false
			}
			continue
		}
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func (e Event) Validate() error {
	if e.Sequence < 1 || e.Time < 1 || e.Count < 0 || e.Level != "info" && e.Level != "warn" && e.Level != "error" || !EventToken(e.Code, 96) || e.Code == "" || !EventToken(e.Kind, 192) || !EventToken(e.State, 96) || !EventToken(e.Stage, 96) || e.RequestID != "" && !EventID(e.RequestID) {
		return fault.Invalid("结构化日志事件无效")
	}
	if e.Category != "application" && e.Category != "security" && e.Category != "task" || e.Category == "task" && !EventID(e.TaskID) || e.Category != "task" && e.TaskID != "" {
		return fault.Invalid("结构化日志分类或任务无效")
	}
	switch e.Category {
	case "task":
		if e.Code != "task.created" && e.Code != "task.transition" || e.Count != 0 || e.RequestID != "" {
			return fault.Invalid("任务日志类型无效")
		}
	case "application":
		if e.Code != "application.warn" && e.Code != "application.error" && e.Code != "log.delivery_gap" || e.Code != "log.delivery_gap" && e.Count != 0 || e.Code == "log.delivery_gap" && (e.Count == 0 || e.Kind != "" || e.State != "" || e.Stage != "") {
			return fault.Invalid("应用日志类型无效")
		}
	case "security":
		switch e.Code {
		case "auth.bootstrap", "auth.login", "auth.password", "auth.revoke_sessions", "auth.create_credential", "auth.revoke_credential", "auth.revoke_self":
		default:
			return fault.Invalid("安全日志类型无效")
		}
		if e.Kind != "" || e.Stage != "" || e.State != "succeeded" && e.State != "not_succeeded" || e.Count != 0 {
			return fault.Invalid("安全日志字段无效")
		}
	}
	return nil
}

func parseEvent(line []byte) (Row, bool) {
	var e Event
	if json.Unmarshal(line, &e) != nil || e.Validate() != nil {
		return Row{}, false
	}
	message := strings.TrimSpace(strings.Join([]string{e.Code, e.TaskID, e.Kind, e.State, e.Stage, e.RequestID}, " "))
	if e.Count > 0 {
		message += fmt.Sprintf(" count=%d", e.Count)
	}
	return Row{Time: e.Time, Level: e.Level, Event: e.Code, Message: message}, true
}
