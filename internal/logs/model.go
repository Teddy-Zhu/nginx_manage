package logs

import (
	"encoding/json"
	"net/netip"
	"strings"
	"time"
	"unicode/utf8"

	"nginxpanel/internal/fault"
	"nginxpanel/internal/limits"
)

type Policy struct {
	SizeMiB       int64 `json:"size_mib"`
	IntervalHours int64 `json:"interval_hours"`
	AccessDays    int64 `json:"access_days"`
	ErrorDays     int64 `json:"error_days"`
	ResourceMiB   int64 `json:"resource_mib"`
	TotalMiB      int64 `json:"total_mib"`
	Compress      bool  `json:"compress"`
}

func DefaultPolicy() Policy {
	return Policy{SizeMiB: 100, IntervalHours: 24, AccessDays: 14, ErrorDays: 30, ResourceMiB: 512, TotalMiB: 2048, Compress: true}
}
func (p Policy) Validate() error {
	if p.SizeMiB < 1 || p.SizeMiB > 1024 || p.IntervalHours < 1 || p.IntervalHours > 168 || p.AccessDays < 1 || p.AccessDays > 90 || p.ErrorDays < 1 || p.ErrorDays > 90 || p.ResourceMiB < p.SizeMiB || p.ResourceMiB > 16384 || p.TotalMiB < p.ResourceMiB || p.TotalMiB > 65536 {
		return fault.Invalid("日志策略超出范围：轮转 1–1024 MiB、1–168 小时，保留 1–90 天，单资源最多 16 GiB、总计最多 64 GiB；配额不得小于轮转阈值")
	}
	return nil
}

type PolicyView struct {
	Version     int64  `json:"version"`
	Policy      Policy `json:"policy"`
	Owner       string `json:"owner"`
	Editable    bool   `json:"editable"`
	LastSweepAt int64  `json:"last_sweep_at"`
	Bytes       int64  `json:"bytes"`
	Warning     string `json:"warning"`
}
type PolicyInput struct {
	BaseVersion int64  `json:"base_version"`
	Policy      Policy `json:"policy"`
}
type Source struct {
	AuthPresence bool   `json:"auth_presence"`
	ID           string `json:"id"`
	ResourceID   string `json:"resource_id"`
	Category     string `json:"category"`
	Label        string `json:"label"`
	Format       string `json:"format"`
	Sensitive    bool   `json:"sensitive"`
	Active       bool   `json:"active"`
	Bytes        int64  `json:"bytes"`
	Archives     int    `json:"archives"`
	Reason       string `json:"reason"`
}
type Query struct {
	SourceID   string `json:"source_id"`
	Mode       string `json:"mode"`
	From       int64  `json:"from"`
	Until      int64  `json:"until"`
	Status     int    `json:"status"`
	IP         string `json:"ip"`
	Path       string `json:"path"`
	Keyword    string `json:"keyword"`
	PolicyID   string `json:"policy_id"`
	Reason     string `json:"reason"`
	EventsOnly bool   `json:"events_only"`
	Limit      int    `json:"limit"`
	Cursor     string `json:"cursor"`
}

func (q Query) Validate() error {
	if len(q.SourceID) != 64 || strings.Trim(q.SourceID, "0123456789abcdef") != "" || (q.Mode != "recent" && q.Mode != "history") || q.Limit < 1 || q.Limit > limits.PageSize || len(q.Cursor) > 128 {
		return fault.Invalid("日志来源、模式、页大小或游标无效")
	}
	if q.From <= 0 || q.From > time.Now().Add(time.Minute).Unix() || q.Until < 0 || q.Until != 0 && (q.Until < q.From || q.Until-q.From > 7*24*3600) || q.Cursor == "" && q.From < time.Now().Add(-7*24*time.Hour).Unix() && q.Until == 0 {
		return fault.Invalid("日志查询时间范围最多七天，实时查询须从最近七天内开始")
	}
	if q.Status != 0 && (q.Status < 100 || q.Status > 599) {
		return fault.Invalid("状态码须为 100–599")
	}
	if q.IP != "" {
		if _, err := netip.ParseAddr(q.IP); err != nil {
			return fault.Invalid("来源 IP 无效")
		}
	}
	for _, value := range []string{q.Path, q.Keyword, q.PolicyID, q.Reason} {
		if !utf8.ValidString(value) || len(value) > 256 || strings.ContainsAny(value, "\x00\r\n") {
			return fault.Invalid("日志筛选条件须为最多 256 字节的单行 UTF-8 文本")
		}
	}
	if q.Path != "" && !strings.HasPrefix(q.Path, "/") {
		return fault.Invalid("路径筛选须以 / 开始")
	}
	return nil
}
func (q Query) fingerprint() string { q.Cursor = ""; raw, _ := json.Marshal(q); return string(raw) }

type Row struct {
	Time           int64  `json:"time"`
	Level          string `json:"level"`
	IP             string `json:"ip"`
	Host           string `json:"host"`
	Method         string `json:"method"`
	Path           string `json:"path"`
	Status         int    `json:"status"`
	Protocol       string `json:"protocol"`
	Duration       string `json:"duration"`
	BytesSent      string `json:"bytes_sent"`
	BytesReceived  string `json:"bytes_received"`
	Upstream       string `json:"upstream"`
	UpstreamStatus string `json:"upstream_status"`
	PolicyID       string `json:"policy_id"`
	Reason         string `json:"reason"`
	Event          string `json:"event"`
	Message        string `json:"message"`
}
type Page struct {
	Rows         []Row  `json:"rows"`
	Cursor       string `json:"cursor"`
	More         bool   `json:"more"`
	ScannedBytes int64  `json:"scanned_bytes"`
	Skipped      int    `json:"skipped"`
	Gap          bool   `json:"gap"`
	Notice       string `json:"notice"`
}

// File names and identities are supplied by the root-owned source catalog,
// never by an HTTP request. Compressed readers retain their bounded streaming
// position in the cursor session; paging does not repeatedly decompress prefixes.
type File struct {
	Name          string
	Identity      string
	Compressed    bool
	Current       bool
	Writing       bool
	Format        string
	Size          int64
	CreatedAt     int64
	Device, Inode uint64
}
type Snapshot struct {
	Source Source
	Files  []File
	Gap    bool
}

func Matches(q Query, row Row) bool {
	if row.Time < q.From || q.Until > 0 && row.Time > q.Until || q.Status != 0 && row.Status != q.Status || q.IP != "" && row.IP != q.IP || q.Path != "" && !strings.HasPrefix(row.Path, q.Path) || q.PolicyID != "" && row.PolicyID != q.PolicyID || q.Reason != "" && !strings.Contains(row.Reason+" "+row.Event, q.Reason) || q.EventsOnly && row.Event == "" {
		return false
	}
	return q.Keyword == "" || strings.Contains(row.Message+" "+row.Path+" "+row.Host+" "+row.Upstream+" "+row.Reason+" "+row.Event, q.Keyword)
}
