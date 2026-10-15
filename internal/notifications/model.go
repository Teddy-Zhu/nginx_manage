package notifications

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"

	"nginxpanel/internal/fault"
)

const MaxChannels = 16

type Kind struct {
	ID    string `json:"id"`
	Label string `json:"label"`
}

var Kinds = []Kind{{"certificate.failure", "证书申请或续期失败"}, {"certificate.expiring", "证书临近过期"}, {"certificate.expired", "证书已过期"}, {"configuration.failure", "配置校验、应用或恢复失败"}, {"recovery.required", "任务需要恢复"}, {"backup.failure", "备份或迁移失败"}, {"update.failure", "更新失败"}, {"task.failure", "其他任务失败"}, {"resource.alert", "资源持续超限"}, {"resource.recovered", "资源使用恢复"}, {"disk.low", "数据目录空间不足"}, {"disk.recovered", "数据目录空间恢复"}}

func validKind(value string) bool {
	for _, kind := range Kinds {
		if kind.ID == value {
			return true
		}
	}
	return false
}

type Policy struct {
	ExpiryDays  int64   `json:"expiry_days"`
	TTLHours    int64   `json:"ttl_hours"`
	MaxAttempts int     `json:"max_attempts"`
	DiskMiB     int64   `json:"disk_mib"`
	DiskPercent float64 `json:"disk_percent"`
}

func DefaultPolicy() Policy {
	return Policy{ExpiryDays: 14, TTLHours: 24, MaxAttempts: 6, DiskMiB: 256, DiskPercent: 5}
}
func (p Policy) Validate() error {
	if p.ExpiryDays < 1 || p.ExpiryDays > 60 || p.TTLHours < 1 || p.TTLHours > 24 || p.MaxAttempts < 1 || p.MaxAttempts > 8 || p.DiskMiB < 64 || p.DiskMiB > 10240 || !(p.DiskPercent >= 1 && p.DiskPercent <= 20) {
		return fault.Invalid("到期阈值须为 1–60 天，有效期 1–24 小时，尝试 1–8 次，剩余容量 64–10240 MiB/1–20%")
	}
	return nil
}

type PolicyView struct {
	Version int64  `json:"version"`
	Policy  Policy `json:"policy"`
}
type PolicyInput struct {
	BaseVersion int64  `json:"base_version"`
	Policy      Policy `json:"policy"`
}
type Config struct {
	URL           string `json:"url"`
	ChatID        string `json:"chat_id"`
	ThreadID      int64  `json:"thread_id"`
	BotToken      string `json:"bot_token"`
	BearerToken   string `json:"bearer_token"`
	SigningSecret string `json:"signing_secret"`
}
type ChannelInput struct {
	BaseVersion   int64    `json:"base_version"`
	Name          string   `json:"name"`
	Kind          string   `json:"kind"`
	Enabled       bool     `json:"enabled"`
	Subscriptions []string `json:"subscriptions"`
	URL           *string  `json:"url"`
	ChatID        *string  `json:"chat_id"`
	ThreadID      *int64   `json:"thread_id"`
	BotToken      *string  `json:"bot_token"`
	BearerToken   *string  `json:"bearer_token"`
	SigningSecret *string  `json:"signing_secret"`
}
type Channel struct {
	ID               string   `json:"id"`
	Version          int64    `json:"version"`
	Name             string   `json:"name"`
	Kind             string   `json:"kind"`
	Enabled          bool     `json:"enabled"`
	Subscriptions    []string `json:"subscriptions"`
	Target           string   `json:"target"`
	Configured       bool     `json:"configured"`
	HasBotToken      bool     `json:"has_bot_token"`
	HasBearerToken   bool     `json:"has_bearer_token"`
	HasSigningSecret bool     `json:"has_signing_secret"`
	Reason           string   `json:"reason"`
	CreatedAt        int64    `json:"created_at"`
	UpdatedAt        int64    `json:"updated_at"`
}
type storedChannel struct {
	Channel
	Config     Config
	NextSendAt int64
}

func text(value string, max int) bool {
	if !utf8.ValidString(value) || len(value) > max {
		return false
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}
func (c Config) validate(kind string, required bool) error {
	for _, value := range []string{c.URL, c.ChatID, c.BotToken, c.BearerToken, c.SigningSecret} {
		if !text(value, 2048) {
			return fault.Invalid("渠道字段超限或包含无效字符")
		}
	}
	if kind == "telegram" {
		if c.URL != "" || c.BearerToken != "" || c.SigningSecret != "" || c.ThreadID < 0 {
			return fault.Invalid("Telegram 渠道字段无效")
		}
		if c.BotToken != "" {
			id, secret, ok := strings.Cut(c.BotToken, ":")
			if !ok || len(id) > 32 || len(secret) < 20 || len(secret) > 128 || strings.Trim(id, "0123456789") != "" || id == "" || strings.Trim(secret, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-") != "" {
				return fault.Invalid("Bot Token 格式无效")
			}
		}
		if c.ChatID != "" {
			if strings.HasPrefix(c.ChatID, "@") {
				name := strings.TrimPrefix(c.ChatID, "@")
				if len(name) < 5 || len(name) > 32 || strings.Trim(name, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_") != "" {
					return fault.Invalid("Telegram chat ID 无效")
				}
			} else {
				n, err := strconv.ParseInt(c.ChatID, 10, 64)
				if err != nil || n == 0 {
					return fault.Invalid("Telegram chat ID 无效")
				}
			}
		}
		if required && (c.BotToken == "" || c.ChatID == "") {
			return fault.Invalid("需填写 Bot Token 和目标 chat ID")
		}
	} else if kind == "webhook" {
		if c.BotToken != "" || c.ChatID != "" || c.ThreadID != 0 {
			return fault.Invalid("Webhook 渠道字段无效")
		}
		if c.URL != "" {
			parsed, err := url.Parse(c.URL)
			if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil || parsed.Fragment != "" || parsed.Opaque != "" || strings.ContainsAny(c.URL, " \\\t") {
				return fault.Invalid("Webhook 需为不含用户信息及片段的 HTTPS 地址")
			}
		}
		if c.URL != "" {
			parsed, _ := url.Parse(c.URL)
			if port := parsed.Port(); port != "" {
				value, err := strconv.ParseUint(port, 10, 16)
				if err != nil || value == 0 {
					return fault.Invalid("Webhook 端口无效")
				}
			}
		}
		if c.SigningSecret != "" && len(c.SigningSecret) < 16 {
			return fault.Invalid("HMAC 共享密钥至少 16 字节")
		}
		if required && c.URL == "" {
			return fault.Invalid("需填写 Webhook HTTPS 地址")
		}
	} else {
		return fault.Invalid("未知通知渠道类型")
	}
	return nil
}
func (c *storedChannel) view() Channel {
	out := c.Channel
	out.HasBotToken = c.Config.BotToken != ""
	out.HasBearerToken = c.Config.BearerToken != ""
	out.HasSigningSecret = c.Config.SigningSecret != ""
	out.Configured = c.Config.validate(c.Kind, true) == nil
	if !out.Configured {
		out.Reason = "目标或凭据尚未配置完整"
	}
	if c.Kind == "webhook" {
		if parsed, err := url.Parse(c.Config.URL); err == nil && parsed.Host != "" {
			out.Target = "https://" + parsed.Host
		}
	} else if c.Config.ChatID != "" {
		target := c.Config.ChatID
		if len(target) > 4 {
			target = "…" + target[len(target)-4:]
		}
		out.Target = "chat " + target
		if c.Config.ThreadID > 0 {
			out.Target += fmt.Sprintf(" / topic %d", c.Config.ThreadID)
		}
	}
	return out
}

type Event struct {
	ID           string `json:"id"`
	Kind         string `json:"kind"`
	ResourceKind string `json:"resource_kind"`
	ResourceID   string `json:"resource_id"`
	Severity     string `json:"severity"`
	State        string `json:"state"`
	Summary      string `json:"summary"`
	Occurrences  int64  `json:"occurrences"`
	CreatedAt    int64  `json:"created_at"`
	LastSeenAt   int64  `json:"last_seen_at"`
	ExpiresAt    int64  `json:"expires_at"`
}
type Payload struct {
	Version int    `json:"version"`
	NodeID  string `json:"node_id"`
	Event   Event  `json:"event"`
}
type Delivery struct {
	ID            string `json:"id"`
	EventID       string `json:"event_id"`
	ChannelID     string `json:"channel_id"`
	ChannelName   string `json:"channel_name"`
	State         string `json:"state"`
	Attempts      int    `json:"attempts"`
	MaxAttempts   int    `json:"max_attempts"`
	NextAttemptAt int64  `json:"next_attempt_at"`
	LastError     string `json:"last_error"`
	HTTPStatus    int    `json:"http_status"`
	CreatedAt     int64  `json:"created_at"`
	LastAttemptAt int64  `json:"last_attempt_at"`
	CompletedAt   int64  `json:"completed_at"`
	ExpiresAt     int64  `json:"expires_at"`
}
type Change struct {
	ID         string `json:"id"`
	Version    int64  `json:"version"`
	DeliveryID string `json:"delivery_id"`
}
type Health struct {
	EvictedEvents     int64  `json:"evicted_events"`
	DroppedDeliveries int64  `json:"dropped_deliveries"`
	Pending           int    `json:"pending"`
	Failed            int    `json:"failed"`
	Reason            string `json:"reason"`
}
type Overview struct {
	Enabled  bool       `json:"enabled"`
	Policy   PolicyView `json:"policy"`
	Channels []Channel  `json:"channels"`
	Kinds    []Kind     `json:"kinds"`
	Health   Health     `json:"health"`
}
