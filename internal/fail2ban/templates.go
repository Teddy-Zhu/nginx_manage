package fail2ban

import (
	"encoding/json"
	"sort"
	"strings"

	"nginxpanel/internal/fault"
	"nginxpanel/internal/logs"
	"nginxpanel/internal/secure"
)

const RegexVersion = "1.1.1"
const HTTP401Template = "nginx-http-401"
const Authorization401Template = "nginx-authorization-401"

type FilterSample struct {
	Name       string `json:"name"`
	Line       string `json:"line"`
	ExpectedIP string `json:"expected_ip"`
}
type TemplateCheckInput struct {
	Templates []string `json:"templates"`
}
type TemplateCheck struct {
	Engine        EngineIdentity `json:"engine"`
	Template      string         `json:"template"`
	At            int64          `json:"at"`
	Source        string         `json:"source"`
	Scope         string         `json:"scope"`
	Available     bool           `json:"available"`
	Passed        bool           `json:"passed"`
	FilterSHA256  string         `json:"filter_sha256"`
	SamplesSHA256 string         `json:"samples_sha256"`
	ToolPath      string         `json:"tool_path"`
	ToolSHA256    string         `json:"tool_sha256"`
	ToolVersion   string         `json:"tool_version"`
	ExpectedIPs   []string       `json:"expected_ips"`
	MatchedIPs    []string       `json:"matched_ips"`
	Reason        string         `json:"reason"`
}

func (in TemplateCheckInput) Normalize() (TemplateCheckInput, error) {
	out := TemplateCheckInput{Templates: append([]string{}, in.Templates...)}
	if len(out.Templates) < 1 || len(out.Templates) > 2 {
		return out, fault.Invalid("请选择 1–2 个内置模板")
	}
	sort.Strings(out.Templates)
	for i, id := range out.Templates {
		if !KnownTemplate(id) || i > 0 && id == out.Templates[i-1] {
			return out, fault.Invalid("内置模板无效或重复")
		}
	}
	return out, nil
}
func KnownTemplate(id string) bool { return id == HTTP401Template || id == Authorization401Template }

// Use the numeric ip4/ip6 captures understood by the official filter engine.
// Enumerating compressed IPv6 group counts keeps matching bounded and excludes
// malformed addresses before they can become failure IDs.
func numericAddressPattern() string {
	octet := `(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])`
	v4 := octet + strings.Repeat(`\.`+octet, 3)
	hextet := `[0-9a-fA-F]{1,4}`
	groups := func(count int) string {
		if count == 0 {
			return ""
		}
		return hextet + strings.Repeat(":"+hextet, count-1)
	}
	parts := []string{groups(8), groups(6) + ":" + v4}
	for left := 0; left < 8; left++ {
		for right := 0; right < 8-left; right++ {
			parts = append(parts, groups(left)+"::"+groups(right))
		}
	}
	for left := 0; left < 6; left++ {
		for right := 0; right < 6-left; right++ {
			suffix := groups(right)
			if right > 0 {
				suffix += ":"
			}
			parts = append(parts, groups(left)+"::"+suffix+v4)
		}
	}
	return `(?:(?:::[fF]{4}:)?(?P<ip4>` + v4 + `)|(?P<ip6>(?:` + strings.Join(parts, "|") + `)))`
}

// FilterConfig is authored here rather than accepting user regular expressions
// or importing distribution filter includes. Date extraction leaves an empty
// time value. Structural JSON matching prevents request text forging an address
// or status field; fixed numeric captures and usedns=no exclude DNS names.
func FilterConfig(id string) (string, error) {
	if !KnownTemplate(id) {
		return "", fault.Invalid("未知内置模板")
	}
	text := `(?:[^"\\\x00-\x1f]|\\(?:["\\/bfnrt]|u[0-9a-fA-F]{4}))*`
	fields := []string{}
	for _, field := range logs.HTTPFields() {
		value := text
		switch field {
		case "time_iso8601":
			value = ""
		case "remote_addr":
			value = numericAddressPattern()
		case "status":
			value = "401"
		case logs.HTTPAuthPresent:
			value = "[01]"
			if id == Authorization401Template {
				value = "1"
			}
		}
		fields = append(fields, `"`+field+`":"`+value+`"`)
	}
	regex := `^\{` + strings.Join(fields, ",") + `(?:,"(?:nginxpanel_waf_policy|nginxpanel_waf_reason|limit_req_status|limit_conn_status)":"` + text + `"){0,4}\}$`
	return "[Definition]\nfailregex = " + regex + "\nignoreregex =\ndatepattern = %%Y-%%m-%%dT%%H:%%M:%%S%%z\nmaxlines = 1\n", nil
}
func FilterSamples(id string) []FilterSample {
	if !KnownTemplate(id) {
		return []FilterSample{}
	}
	line := func(ip, status, auth, uri string) string {
		fields := map[string]string{"time_iso8601": "2026-01-02T03:04:05+00:00", "remote_addr": ip, "host": "example.invalid", "request_method": "GET", "uri": uri, "status": status, "body_bytes_sent": "0", "request_time": "0.001", "upstream_addr": "-", "upstream_status": "-", "upstream_response_time": "-", logs.HTTPAuthPresent: auth}
		parts := []string{}
		for _, key := range logs.HTTPFields() {
			raw, _ := json.Marshal(fields[key])
			parts = append(parts, `"`+key+`":`+string(raw))
		}
		return "{" + strings.Join(parts, ",") + "}"
	}
	challenge := ""
	if id == HTTP401Template {
		challenge = "192.0.2.12"
	}
	return []FilterSample{
		{Name: "IPv4 认证响应", Line: line("192.0.2.10", "401", "1", "/private"), ExpectedIP: "192.0.2.10"},
		{Name: "IPv6 认证响应", Line: line("2001:db8::11", "401", "1", "/private"), ExpectedIP: "2001:db8::11"},
		{Name: "首次认证挑战", Line: line("192.0.2.12", "401", "0", "/private"), ExpectedIP: challenge},
		{Name: "认证成功", Line: line("192.0.2.13", "200", "1", "/private")},
		{Name: "URI 伪造 JSON 字段", Line: line("192.0.2.14", "200", "1", `/x","remote_addr":"198.51.100.99","status":"401","nginxpanel_auth_present":"1`)},
		{Name: "URI 转义字符", Line: line("192.0.2.15", "401", "1", "/x\"\\\n"), ExpectedIP: "192.0.2.15"},
		{Name: "主机名来源拒绝", Line: line("invalid.example", "401", "1", "/private")},
		{Name: "非法数值地址拒绝", Line: line("999.999.999.999", "401", "1", "/private")},
		{Name: "非法 IPv6 拒绝", Line: line("2001:db8::1::2", "401", "1", "/private")},
		{Name: "IPv4 映射地址", Line: line("::ffff:192.0.2.21", "401", "1", "/private"), ExpectedIP: "192.0.2.21"},
		{Name: "IPv6 兼容地址", Line: line("::192.0.2.22", "401", "1", "/private"), ExpectedIP: "::c000:216"},
		{Name: "IPv6 混合地址", Line: line("2001:db8::192.0.2.23", "401", "1", "/private"), ExpectedIP: "2001:db8::c000:217"},
		{Name: "未知认证标记拒绝", Line: line("192.0.2.18", "401", "yes", "/private")},
		{Name: "不完整 JSON 拒绝", Line: strings.TrimSuffix(line("192.0.2.19", "401", "1", "/private"), "}")},
		{Name: "WAF 附加字段", Line: strings.TrimSuffix(line("192.0.2.20", "401", "1", "/private"), "}") + `,"nginxpanel_waf_policy":"policy","nginxpanel_waf_reason":"reason","limit_conn_status":"PASSED","limit_req_status":"PASSED"}`, ExpectedIP: "192.0.2.20"},
	}
}
func FilterIdentity(id string) (string, string) {
	filter, err := FilterConfig(id)
	if err != nil {
		return "", ""
	}
	raw, _ := json.Marshal(FilterSamples(id))
	return secure.Hash([]byte(filter)), secure.Hash(raw)
}
func ExpectedSampleIPs(id string) []string {
	out := []string{}
	for _, sample := range FilterSamples(id) {
		if sample.ExpectedIP != "" {
			out = append(out, sample.ExpectedIP)
		}
	}
	return out
}
