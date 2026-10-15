package logs

import (
	"bufio"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"nginxpanel/internal/fault"
	"nginxpanel/internal/limits"
	"nginxpanel/internal/secure"
)

var ErrCursor = fault.New(409, "LOG_CURSOR_EXPIRED", "日志游标已失效或不再保留该页，请重新查询")

type Reader struct {
	Snapshot func(string) (Snapshot, error)
	Open     func(File) (*os.File, error)
	mu       sync.Mutex
	sessions map[string]*scanSession
	slots    chan struct{}
}
type scanSession struct {
	mu                       sync.Mutex
	id, subject, fingerprint string
	query                    Query
	expires                  time.Time
	files                    []File
	seen                     map[string]bool
	index                    int
	file                     *os.File
	reader                   *bufio.Reader
	gzip                     *gzip.Reader
	partial                  []byte
	oversized                bool
	step, lastStep           uint64
	last                     Page
	initial                  bool
	gap                      bool
	broken                   bool
	sensitive                bool
}

func NewReader(snapshot func(string) (Snapshot, error), open func(File) (*os.File, error)) *Reader {
	return &Reader{Snapshot: snapshot, Open: open, sessions: map[string]*scanSession{}, slots: make(chan struct{}, limits.LogQueryConcurrency)}
}
func (s *scanSession) closeFile() {
	if s.gzip != nil {
		s.gzip.Close()
		s.gzip = nil
	}
	if s.file != nil {
		s.file.Close()
		s.file = nil
	}
	s.reader = nil
	s.partial = nil
	s.oversized = false
}
func (r *Reader) Close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for id, s := range r.sessions {
		s.mu.Lock()
		s.closeFile()
		s.mu.Unlock()
		delete(r.sessions, id)
	}
}
func (r *Reader) discardExpiredLocked() {
	for id, s := range r.sessions {
		if !s.mu.TryLock() {
			continue
		}
		if time.Now().After(s.expires) {
			s.closeFile()
			delete(r.sessions, id)
		}
		s.mu.Unlock()
	}
}
func (r *Reader) Expire() { r.mu.Lock(); defer r.mu.Unlock(); r.discardExpiredLocked() }
func splitCursor(cursor string) (string, uint64, bool) {
	id, position, found := strings.Cut(cursor, ":")
	step, err := strconv.ParseUint(position, 10, 64)
	return id, step, found && err == nil && len(id) == 36 && step > 0
}
func (r *Reader) Release(subject, cursor string) {
	id, _, ok := splitCursor(cursor)
	if !ok {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if s := r.sessions[id]; s != nil && s.subject == subject && s.mu.TryLock() {
		s.closeFile()
		delete(r.sessions, id)
		s.mu.Unlock()
	}
}

func (r *Reader) Read(ctx context.Context, subject string, q Query, allowSensitive bool, budgets ...int64) (Page, error) {
	if err := q.Validate(); err != nil {
		return Page{}, err
	}
	if q.IP != "" {
		addr, _ := netip.ParseAddr(q.IP)
		q.IP = addr.Unmap().String()
	}
	budget := int64(limits.LogScanBytes)
	if len(budgets) > 0 && budgets[0] > 0 {
		budget = min(budget, budgets[0])
	}
	if subject == "" || len(subject) > 256 {
		return Page{}, fault.Invalid("日志读取身份无效")
	}
	select {
	case r.slots <- struct{}{}:
		defer func() { <-r.slots }()
	default:
		return Page{}, fault.New(429, "LOG_QUERY_LIMIT", "日志查询并发已达上限")
	}
	snapshot, err := r.Snapshot(q.SourceID)
	if err != nil {
		return Page{}, err
	}
	if snapshot.Source.Sensitive && !allowSensitive {
		return Page{}, fault.New(403, "FORBIDDEN", "原生日志可能包含敏感数据，须具备敏感配置读取权限并重新认证")
	}
	if strings.HasPrefix(snapshot.Source.Category, "stream") && (q.Path != "" || q.PolicyID != "" || q.Reason != "" || q.EventsOnly) {
		return Page{}, fault.Invalid("Stream 日志不支持 HTTP 路径或 WAF 条件")
	}
	if snapshot.Source.Format != "nginxpanel_http" && (q.PolicyID != "" || q.Reason != "" || q.EventsOnly || q.Path != "") {
		return Page{}, fault.Invalid("当前日志格式不支持 HTTP 路径和 WAF 字段筛选")
	}
	if snapshot.Source.Format == "text" && (q.Status != 0 || q.IP != "") {
		return Page{}, fault.Invalid("原生日志仅支持时间与脱敏消息关键字筛选")
	}
	var s *scanSession
	var step uint64
	r.mu.Lock()
	r.discardExpiredLocked()
	if q.Cursor != "" {
		id, want, ok := splitCursor(q.Cursor)
		step = want
		if ok {
			s = r.sessions[id]
		}
		if s == nil || s.subject != subject || s.fingerprint != q.fingerprint() {
			r.mu.Unlock()
			return Page{}, ErrCursor
		}
	} else {
		if len(r.sessions) >= limits.LogCursorSessions {
			r.mu.Unlock()
			return Page{}, fault.New(429, "LOG_CURSOR_LIMIT", "日志游标数量已达上限，请关闭旧查询或稍后重试")
		}
		s = &scanSession{id: secure.ID(), subject: subject, fingerprint: q.fingerprint(), query: q, expires: time.Now().Add(5 * time.Minute), initial: true, lastStep: ^uint64(0), seen: map[string]bool{}, gap: snapshot.Gap, sensitive: snapshot.Source.Sensitive}
		for _, file := range snapshot.Files {
			s.seen[file.Identity] = true
		}
		if q.Mode == "recent" {
			for _, file := range snapshot.Files {
				if file.Current || file.Writing {
					s.files = append(s.files, file)
				}
			}
		} else {
			s.files = append(s.files, snapshot.Files...)
		}
		r.sessions[s.id] = s
	}
	if !s.mu.TryLock() {
		r.mu.Unlock()
		return Page{}, fault.New(409, "LOG_CURSOR_BUSY", "该日志游标正在读取，请稍后重试")
	}
	r.mu.Unlock()
	defer s.mu.Unlock()
	s.expires = time.Now().Add(5 * time.Minute)
	s.sensitive = s.sensitive || snapshot.Source.Sensitive
	if s.sensitive && !allowSensitive {
		return Page{}, fault.New(403, "FORBIDDEN", "该日志游标包含原生日志，须重新认证并具备敏感配置读取权限")
	}
	if s.broken {
		return Page{}, ErrCursor
	}
	if q.Cursor != "" && step == s.lastStep {
		return s.last, nil
	}
	if step != s.step {
		return Page{}, ErrCursor
	}
	s.gap = s.gap || snapshot.Gap
	if !s.initial {
		if !s.refresh(snapshot.Files, q.Mode == "recent") {
			s.broken = true
			s.closeFile()
			return Page{}, ErrCursor
		}
	}
	page, err := r.readPage(ctx, s, budget)
	if err != nil {
		s.broken = true
		s.closeFile()
		s.expires = time.Now()
		return Page{}, err
	}
	s.lastStep = step
	s.step++
	page.Cursor = fmt.Sprintf("%s:%d", s.id, s.step)
	s.last = page
	s.initial = false
	return page, nil
}

func (s *scanSession) refresh(files []File, appendNew bool) bool {
	for i, old := range s.files {
		s.files[i].Current = false
		s.files[i].Writing = false
		found := false
		for _, current := range files {
			if current.Identity == old.Identity {
				found = true
				s.files[i].Current = current.Current
				s.files[i].Writing = current.Writing
				if s.file == nil || i != s.index {
					s.files[i] = current
				}
				break
			}
		}
		if !found && old.Current {
			s.gap = true
		}
	}
	for _, file := range files {
		if appendNew && !s.seen[file.Identity] {
			if len(s.seen) >= 2*limits.LogSourceArchives+2 {
				return false
			}
			s.files = append(s.files, file)
			s.seen[file.Identity] = true
		}
	}
	return len(s.files) <= limits.LogSourceArchives+1
}

func (r *Reader) openCurrent(s *scanSession) error {
	file := s.files[s.index]
	f, err := r.Open(file)
	if err != nil {
		// Compression can publish between the catalog snapshot and opening a
		// later file. Resolve the same generation once before declaring a gap.
		if latest, snapshotErr := r.Snapshot(s.query.SourceID); snapshotErr == nil {
			for _, candidate := range latest.Files {
				if candidate.Identity == file.Identity && candidate.Format == file.Format {
					file = candidate
					s.files[s.index] = candidate
					f, err = r.Open(candidate)
					break
				}
			}
		}
		if err != nil {
			return err
		}
	}
	s.file = f
	var reader io.Reader = f
	if file.Compressed {
		s.gzip, err = gzip.NewReader(f)
		if err != nil {
			s.closeFile()
			return err
		}
		reader = s.gzip
	} else if s.initial && s.query.Mode == "recent" && (file.Current || file.Writing) {
		info, err := f.Stat()
		if err != nil {
			s.closeFile()
			return err
		}
		start := max(info.Size()-limits.LogScanBytes, 0)
		if _, err := f.Seek(start, io.SeekStart); err != nil {
			s.closeFile()
			return err
		}
		if start > 0 {
			s.oversized = true
			s.gap = true
		}
	}
	s.reader = bufio.NewReaderSize(reader, limits.LogLineBytes)
	return nil
}

// A partial active line stays in the cursor until its newline arrives. Long
// attacker-controlled lines are drained with a fixed buffer and counted once.
func (s *scanSession) line() ([]byte, int, error) {
	chunk, err := s.reader.ReadSlice('\n')
	consumed := len(chunk)
	if len(s.partial)+len(chunk) > limits.LogLineBytes {
		s.partial = nil
		s.oversized = true
	}
	if !s.oversized {
		s.partial = append(s.partial, chunk...)
	}
	if err == bufio.ErrBufferFull {
		return nil, consumed, nil
	}
	if err == io.EOF && (s.files[s.index].Current || s.files[s.index].Writing) {
		return nil, consumed, io.EOF
	}
	if err != nil && err != io.EOF {
		return nil, consumed, err
	}
	if s.oversized {
		s.oversized = false
		s.partial = nil
		return nil, consumed, errOversized
	}
	line := s.partial
	s.partial = nil
	return line, consumed, err
}

var errOversized = errors.New("log line exceeds bounded reader limit")

func (r *Reader) readPage(ctx context.Context, s *scanSession, budget int64) (Page, error) {
	out := Page{Rows: []Row{}, Gap: s.gap}
	s.gap = false
	recentInitial := s.initial && s.query.Mode == "recent"
	for out.ScannedBytes < budget && s.index < len(s.files) {
		if err := ctx.Err(); err != nil {
			return Page{}, err
		}
		if s.reader == nil {
			if err := r.openCurrent(s); err != nil {
				out.Gap = true
				out.Notice = "部分日志文件已移除、身份变化或无法读取；该范围存在缺口"
				s.index++
				continue
			}
			out.Gap = out.Gap || s.gap
			s.gap = false
		}
		line, used, err := s.line()
		out.ScannedBytes += int64(used)
		if errors.Is(err, errOversized) {
			out.Skipped++
			continue
		}
		if err != nil && err != io.EOF {
			return Page{}, fault.New(503, "LOG_READ_FAILED", "日志文件读取失败，请重新查询")
		}
		if len(line) > 0 {
			row, ok := Parse(line, s.files[s.index].Format)
			if !ok {
				out.Skipped++
			} else if Matches(s.query, row) {
				out.Rows = append(out.Rows, row)
				if recentInitial && len(out.Rows) > s.query.Limit {
					copy(out.Rows, out.Rows[1:])
					out.Rows = out.Rows[:s.query.Limit]
				}
			}
		}
		if err == io.EOF {
			if s.files[s.index].Writing || s.files[s.index].Current && s.index == len(s.files)-1 {
				info, statErr := s.file.Stat()
				position, seekErr := s.file.Seek(0, io.SeekCurrent)
				if statErr == nil && seekErr == nil && info.Size() < position {
					s.closeFile()
					s.initial = false
					out.Gap = true
					out.Notice = "日志文件被截短，后续从当前文件开头继续"
				}
				if s.index < len(s.files)-1 {
					out.More = true
					out.Notice = "日志轮转仍在等待旧文件关闭，可稍后继续读取"
				}
				break
			}
			s.closeFile()
			s.index++
		}
		if !recentInitial && len(out.Rows) >= s.query.Limit {
			out.More = true
			break
		}
	}
	if out.ScannedBytes >= budget {
		out.More = true
		out.Notice = "已达到单次扫描字节预算，可继续读取下一页"
	}
	if out.Skipped > 0 && out.Notice == "" {
		out.Notice = "存在超长或无法解析的日志行，已计入跳过数量"
	}
	if recentInitial && out.Gap && out.Notice == "" {
		out.Notice = "最近视图仅扫描当前文件末尾；更早记录请使用历史查询"
	}
	if s.index > 0 {
		s.files = append([]File(nil), s.files[s.index:]...)
		s.index = 0
	}
	return out, nil
}
