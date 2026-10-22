package auditlog

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"nginxpanel/internal/fault"
	"nginxpanel/internal/secure"
)

const pageScanLimit = 5000
const exportScanLimit = 10000
const archiveByteLimit = 8 << 20

// Recovery events retain a phase-qualified ID derived from their operation.
var auditID = regexp.MustCompile(`^(restore\.(reconcile|activate):)?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

type Service struct {
	db       *sql.DB
	nodeID   string
	key      []byte
	readers  chan struct{}
	exporter chan struct{}
}

func New(db *sql.DB, nodeID string) *Service {
	// Cursors expire after ten minutes and on process restart or database restore.
	return &Service{db: db, nodeID: nodeID, key: []byte(secure.Token()), readers: make(chan struct{}, 4), exporter: make(chan struct{}, 1)}
}

type position struct {
	MaxRowID int64  `json:"max_row_id"`
	Time     int64  `json:"time"`
	ID       string `json:"id"`
	Expires  int64  `json:"expires"`
	Query    string `json:"query"`
}

func fingerprint(q Query) string {
	q.Cursor = ""
	raw, _ := json.Marshal(q)
	return secure.Hash(raw)
}

func (s *Service) encode(p position) string {
	raw, _ := json.Marshal(p)
	mac := hmac.New(sha256.New, s.key)
	mac.Write(raw)
	return base64.RawURLEncoding.EncodeToString(raw) + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func (s *Service) decode(q Query) (position, error) {
	var p position
	payload, signature, ok := strings.Cut(q.Cursor, ".")
	raw, err := base64.RawURLEncoding.DecodeString(payload)
	sig, sigErr := base64.RawURLEncoding.DecodeString(signature)
	mac := hmac.New(sha256.New, s.key)
	mac.Write(raw)
	if !ok || err != nil || sigErr != nil || !hmac.Equal(sig, mac.Sum(nil)) || json.Unmarshal(raw, &p) != nil || p.Query != fingerprint(q) || p.MaxRowID < 0 || p.Expires <= time.Now().Unix() || p.ID == "" && p.Time != 0 || p.ID != "" && (p.Time < q.From || p.Time > q.Until) {
		return p, fault.New(409, "AUDIT_CURSOR_INVALID", "审计游标已失效或查询条件已变化，请重新查询")
	}
	return p, nil
}

func acquire(ch chan struct{}) (func(), error) {
	select {
	case ch <- struct{}{}:
		return func() { <-ch }, nil
	default:
		return nil, fault.New(429, "AUDIT_READ_LIMIT", "审计读取已达并发上限，请稍后重试")
	}
}

func (s *Service) start(ctx context.Context, tx *sql.Tx, q Query) (position, error) {
	if q.Cursor != "" {
		return s.decode(q)
	}
	p := position{Expires: time.Now().Unix() + 600, Query: fingerprint(q)}
	err := tx.QueryRowContext(ctx, "SELECT COALESCE(MAX(rowid),0) FROM audit_logs").Scan(&p.MaxRowID)
	return p, err
}

func entry(r Row) ([]byte, error) {
	return json.Marshal(struct {
		Type string `json:"type"`
		Row  Row    `json:"row"`
	}{"entry", r})
}

func scan(ctx context.Context, tx *sql.Tx, f Filter, p position, budget, limit int) (Page, position, error) {
	out := Page{Rows: []Row{}}
	query := `SELECT id,request_id,principal,action,resource_id,outcome,created_at FROM audit_logs WHERE rowid<=? AND created_at>=? AND created_at<=?`
	args := []any{p.MaxRowID, f.From, f.Until}
	if p.ID != "" {
		query += " AND (created_at,id)<(?,?)"
		args = append(args, p.Time, p.ID)
	}
	query += " ORDER BY created_at DESC,id DESC LIMIT ?"
	args = append(args, budget+1)
	rows, err := tx.QueryContext(ctx, query, args...)
	if err != nil {
		return out, p, err
	}
	defer rows.Close()
	encodedBytes := 0
	for rows.Next() {
		if out.Scanned == budget || len(out.Rows) == limit {
			out.More = true
			break
		}
		var r Row
		if err = rows.Scan(&r.ID, &r.RequestID, &r.Principal, &r.Action, &r.ResourceID, &r.Outcome, &r.CreatedAt); err != nil {
			return out, p, err
		}
		if len(r.ID)+len(r.RequestID)+len(r.Principal)+len(r.Action)+len(r.ResourceID)+len(r.Outcome) > 8192 {
			return out, p, errors.New("审计元数据超出单条读取预算")
		}
		if !auditID.MatchString(r.ID) {
			return out, p, errors.New("审计记录缺少有效标识")
		}
		for _, value := range []string{r.ID, r.RequestID, r.Principal, r.Action, r.ResourceID, r.Outcome} {
			if !utf8.ValidString(value) {
				return out, p, errors.New("审计元数据包含无效 UTF-8，不能完整归档")
			}
		}
		out.Scanned++
		p.Time, p.ID = r.CreatedAt, r.ID
		if f.matches(r) {
			raw, e := entry(r)
			if e != nil {
				return out, p, e
			}
			encodedBytes += len(raw) + 1
			if encodedBytes > archiveByteLimit {
				return out, p, fault.New(409, "AUDIT_EXPORT_TOO_LARGE", "审计结果超出 8 MiB，请缩小时间范围")
			}
			out.Rows = append(out.Rows, r)
		}
	}
	return out, p, rows.Err()
}

func (s *Service) Query(ctx context.Context, q Query) (Page, error) {
	var empty Page
	if err := q.Filter.Validate(); err != nil {
		return empty, err
	}
	if q.Limit < 1 || q.Limit > 100 || len(q.Cursor) > 1024 {
		return empty, fault.Invalid("审计页大小须为 1–100，游标最多 1024 字节")
	}
	done, err := acquire(s.readers)
	if err != nil {
		return empty, err
	}
	defer done()
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return empty, err
	}
	defer tx.Rollback()
	p, err := s.start(ctx, tx, q)
	if err != nil {
		return empty, err
	}
	start := p
	out, p, err := scan(ctx, tx, q.Filter, p, pageScanLimit, q.Limit)
	if err != nil {
		return empty, err
	}
	out.StartCursor = s.encode(start)
	if out.More {
		out.Cursor = s.encode(p)
	}
	if out.More && out.Scanned == pageScanLimit {
		out.Notice = "本页已扫描 5000 条记录，可继续翻页或缩小时间范围"
	}
	return out, nil
}

func (s *Service) Export(ctx context.Context, f Filter) (Archive, error) {
	var out Archive
	if err := f.Validate(); err != nil {
		return out, err
	}
	done, err := acquire(s.exporter)
	if err != nil {
		return out, err
	}
	defer done()
	readDone, err := acquire(s.readers)
	if err != nil {
		return out, err
	}
	defer readDone()
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return out, err
	}
	defer tx.Rollback()
	p, err := s.start(ctx, tx, Query{Filter: f})
	if err != nil {
		return out, err
	}
	page, _, err := scan(ctx, tx, f, p, exportScanLimit, exportScanLimit)
	if err != nil {
		return out, err
	}
	tooLarge := func() error {
		return fault.New(409, "AUDIT_EXPORT_TOO_LARGE", "审计归档最多扫描 10000 条、输出 8 MiB，请缩小时间范围")
	}
	if page.More {
		return out, tooLarge()
	}
	var entries bytes.Buffer
	for _, r := range page.Rows {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		raw, err := entry(r)
		if err != nil {
			return out, err
		}
		if entries.Len()+len(raw)+1 > archiveByteLimit {
			return out, tooLarge()
		}
		entries.Write(raw)
		entries.WriteByte('\n')
	}
	out.Manifest = Manifest{Type: "nginxpanel_audit_archive", Schema: 1, ID: secure.ID(), NodeID: s.nodeID, CreatedAt: time.Now().Unix(), Filter: f, Count: len(page.Rows), RowsSHA256: secure.Hash(entries.Bytes())}
	header, err := json.Marshal(out.Manifest)
	if err != nil {
		return out, err
	}
	if len(header)+1+entries.Len() > archiveByteLimit {
		return Archive{}, tooLarge()
	}
	out.Bytes = make([]byte, 0, len(header)+1+entries.Len())
	out.Bytes = append(out.Bytes, header...)
	out.Bytes = append(out.Bytes, '\n')
	out.Bytes = append(out.Bytes, entries.Bytes()...)
	return out, ctx.Err()
}
