package logs

import (
	"strconv"
	"strings"
	"time"
)

// ExportLine formats a sanitized row as a single human-readable line.
func ExportLine(row Row) string {
	fields := []string{time.Unix(row.Time, 0).UTC().Format(time.RFC3339)}
	if row.Level != "" {
		fields = append(fields, strings.ToUpper(row.Level))
	}
	if row.IP != "" {
		fields = append(fields, row.IP)
	}
	if row.Method != "" {
		fields = append(fields, row.Method, row.Host+row.Path)
	}
	if row.Protocol != "" {
		fields = append(fields, row.Protocol)
	}
	if row.Status != 0 {
		fields = append(fields, strconv.Itoa(row.Status))
	}
	if row.Message != "" {
		fields = append(fields, row.Message)
	}
	for _, value := range []struct{ label, text string }{
		{"duration_s", row.Duration}, {"sent_bytes", row.BytesSent}, {"received_bytes", row.BytesReceived},
		{"upstream", row.Upstream}, {"upstream_status", row.UpstreamStatus}, {"policy", row.PolicyID},
		{"event", row.Event}, {"reason", row.Reason},
	} {
		if value.text != "" {
			fields = append(fields, value.label+"="+value.text)
		}
	}
	return strings.Join(fields, " ") + "\n"
}
