package logs

import (
	"encoding/json"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

var quotedText = regexp.MustCompile(`"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'`)
var queryText = regexp.MustCompile(`\?[^\s,;\]\)]+`)
var credentialsText = regexp.MustCompile(`(?i)(authorization|proxy-authorization|cookie|set-cookie|token|password|secret|api[_-]?key)\s*[:=]\s*[^\r\n]*`)
var userinfoText = regexp.MustCompile(`(https?://)[^/@\s]+@`)
var errorLevel = regexp.MustCompile(`\[(emerg|alert|crit|error|warn|notice|info|debug)\]`)
var commonTime = regexp.MustCompile(`\[([0-9]{2}/[A-Za-z]{3}/[0-9]{4}:[0-9]{2}:[0-9]{2}:[0-9]{2} [+-][0-9]{4})\]`)

func bounded(value string, limit int) string {
	value = strings.Map(func(char rune) rune {
		if unicode.IsControl(char) {
			return ' '
		}
		return char
	}, strings.ToValidUTF8(value, "�"))
	if len(value) <= limit {
		return value
	}
	value = value[:limit]
	for !utf8.ValidString(value) {
		value = value[:len(value)-1]
	}
	return value + "…"
}
func RedactText(value string) string {
	value = quotedText.ReplaceAllString(value, "[已隐藏引述内容]")
	value = queryText.ReplaceAllString(value, "?[已隐藏]")
	value = userinfoText.ReplaceAllString(value, "${1}[已隐藏]@")
	return bounded(credentialsText.ReplaceAllString(value, "${1}=[已隐藏]"), 2048)
}

func Parse(line []byte, format string) (Row, bool) {
	if format != "nginxpanel_http" && format != "nginxpanel_stream" {
		if len(line) < 19 {
			return Row{}, false
		}
		timestamp, err := time.ParseInLocation("2006/01/02 15:04:05", string(line[:19]), time.Local)
		message := string(line[19:])
		if err != nil {
			match := commonTime.FindSubmatch(line)
			if len(match) != 2 {
				return Row{}, false
			}
			timestamp, err = time.Parse("02/Jan/2006:15:04:05 -0700", string(match[1]))
			if err != nil {
				return Row{}, false
			}
			message = string(line)
		}
		row := Row{Time: timestamp.Unix(), Message: RedactText(message)}
		if match := errorLevel.FindSubmatch(line); len(match) > 1 {
			row.Level = string(match[1])
		}
		return row, true
	}
	var fields map[string]string
	if json.Unmarshal(line, &fields) != nil || len(fields) > 32 {
		return Row{}, false
	}
	timestamp, err := time.Parse(time.RFC3339, fields["time_iso8601"])
	if err != nil {
		return Row{}, false
	}
	row := Row{Time: timestamp.Unix(), Duration: bounded(fields["request_time"], 64), BytesSent: bounded(fields["body_bytes_sent"], 32), Upstream: bounded(fields["upstream_addr"], 256), UpstreamStatus: bounded(fields["upstream_status"], 64)}
	if addr, err := netip.ParseAddr(fields["remote_addr"]); err == nil {
		row.IP = addr.Unmap().String()
	}
	row.Status, _ = strconv.Atoi(fields["status"])
	if row.Status < 100 || row.Status > 599 {
		return Row{}, false
	}
	if format == "nginxpanel_stream" {
		row.Protocol = bounded(fields["protocol"], 16)
		row.Duration = bounded(fields["session_time"], 64)
		row.BytesSent = bounded(fields["bytes_sent"], 32)
		row.BytesReceived = bounded(fields["bytes_received"], 32)
		return row, true
	}
	row.Host = bounded(fields["host"], 253)
	row.Method = bounded(fields["request_method"], 32)
	row.Path = bounded(strings.SplitN(fields["uri"], "?", 2)[0], 1024)
	row.PolicyID = bounded(fields["nginxpanel_waf_policy"], 128)
	row.Reason = bounded(fields["nginxpanel_waf_reason"], 256)
	if row.Reason != "" {
		row.Event = "rule_denied"
	}
	switch fields["limit_req_status"] {
	case "REJECTED":
		row.Event = "rate_rejected"
	case "DELAYED":
		row.Event = "rate_delayed"
	case "REJECTED_DRY_RUN", "DELAYED_DRY_RUN":
		row.Event = "rate_observed"
	}
	switch fields["limit_conn_status"] {
	case "REJECTED":
		row.Event = "concurrency_rejected"
	case "REJECTED_DRY_RUN":
		row.Event = "concurrency_observed"
	}
	return row, true
}
