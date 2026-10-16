package logs

// HTTPAuthPresent records presence only, never the Authorization header value.
const HTTPAuthPresent = "nginxpanel_auth_present"

// HTTPFields is the canonical order consumed by fixed Fail2ban filters. Values
// use Nginx escape=json; query strings, headers and request bodies are excluded.
func HTTPFields() []string {
	return []string{"time_iso8601", "remote_addr", "host", "request_method", "uri", "status", "body_bytes_sent", "request_time", "upstream_addr", "upstream_status", "upstream_response_time", HTTPAuthPresent}
}
