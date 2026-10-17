// Package auditlog reads bounded audit metadata without changing source records.
package auditlog

import (
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"nginxpanel/internal/fault"
)

type Filter struct {
	From       int64  `json:"from"`
	Until      int64  `json:"until"`
	Principal  string `json:"principal"`
	Action     string `json:"action"`
	ResourceID string `json:"resource_id"`
	Outcome    string `json:"outcome"`
	RequestID  string `json:"request_id"`
}

func (f Filter) Validate() error {
	if f.From <= 0 || f.Until < f.From || f.Until-f.From > 90*24*3600 || f.Until > time.Now().Unix()+60 {
		return fault.Invalid("审计查询须明确起止时间，单次范围最多九十天")
	}
	for _, value := range []string{f.Principal, f.Action, f.ResourceID, f.Outcome, f.RequestID} {
		if !utf8.ValidString(value) || len(value) > 128 || strings.IndexFunc(value, unicode.IsControl) >= 0 {
			return fault.Invalid("审计筛选条件须为最多 128 字节的单行文本")
		}
	}
	return nil
}

type Query struct {
	Filter
	Limit  int    `json:"limit"`
	Cursor string `json:"cursor"`
}

type Row struct {
	ID         string `json:"id"`
	RequestID  string `json:"request_id"`
	Principal  string `json:"principal"`
	Action     string `json:"action"`
	ResourceID string `json:"resource_id"`
	Outcome    string `json:"outcome"`
	CreatedAt  int64  `json:"created_at"`
}

func (f Filter) matches(r Row) bool {
	return (f.Principal == "" || f.Principal == r.Principal) &&
		(f.Action == "" || f.Action == r.Action) &&
		(f.ResourceID == "" || f.ResourceID == r.ResourceID) &&
		(f.Outcome == "" || f.Outcome == r.Outcome) &&
		(f.RequestID == "" || f.RequestID == r.RequestID)
}

type Page struct {
	Rows        []Row  `json:"rows"`
	Cursor      string `json:"cursor"`
	StartCursor string `json:"start_cursor"`
	More        bool   `json:"more"`
	Scanned     int    `json:"scanned"`
	Notice      string `json:"notice"`
}

type Manifest struct {
	Type       string `json:"type"`
	Schema     int    `json:"schema"`
	ID         string `json:"id"`
	NodeID     string `json:"node_id"`
	CreatedAt  int64  `json:"created_at"`
	Filter     Filter `json:"filter"`
	Count      int    `json:"count"`
	RowsSHA256 string `json:"rows_sha256"`
}

type Archive struct {
	Manifest Manifest
	Bytes    []byte
}
