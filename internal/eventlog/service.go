// Package eventlog delivers a bounded metadata outbox to the privileged log
// writer. Web cannot open the managed files, and never retries with new IDs.
package eventlog

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log/slog"
	"runtime"
	"strings"
	"sync/atomic"
	"time"

	"nginxpanel/internal/agent"
	"nginxpanel/internal/logs"
)

type Service struct {
	OnDelivered func()
	DB          *sql.DB
	Agent       *agent.Client
	input       chan logs.Event
	dropped     atomic.Int64
	held        []logs.Event
}

func New(db *sql.DB, client *agent.Client) *Service {
	return &Service{DB: db, Agent: client, input: make(chan logs.Event, 256)}
}

// Mirror preserves stderr diagnostics, while the persistent file receives only
// metadata. Raw messages and arbitrary attributes are never copied; only a
// validated request UUID can accompany the fixed level and caller metadata.
func (s *Service) Mirror(next slog.Handler) slog.Handler { return &handler{service: s, next: next} }

type handler struct {
	service *Service
	next    slog.Handler
}

func (h *handler) Enabled(ctx context.Context, l slog.Level) bool {
	return l >= slog.LevelWarn || h.next.Enabled(ctx, l)
}
func (h *handler) WithAttrs(a []slog.Attr) slog.Handler {
	return &handler{service: h.service, next: h.next.WithAttrs(a)}
}
func (h *handler) WithGroup(name string) slog.Handler {
	return &handler{service: h.service, next: h.next.WithGroup(name)}
}
func (h *handler) Handle(ctx context.Context, r slog.Record) error {
	if r.Level >= slog.LevelWarn {
		level := "warn"
		if r.Level >= slog.LevelError {
			level = "error"
		}
		caller := "unknown"
		if f := runtime.FuncForPC(r.PC); f != nil {
			name := f.Name()
			if strings.HasPrefix(name, "nginxpanel/") && logs.EventToken(name, 192) {
				caller = name
			}
		}
		event := logs.Event{Time: max(r.Time.Unix(), 1), Category: "application", Level: level, Code: "application." + level, Kind: caller}
		r.Attrs(func(a slog.Attr) bool {
			if a.Key == "request_id" && a.Value.Kind() == slog.KindString && logs.EventID(a.Value.String()) {
				event.RequestID = a.Value.String()
			}
			return true
		})
		select {
		case h.service.input <- event:
		default:
			h.service.dropped.Add(1)
		}
	}
	if h.next.Enabled(ctx, r.Level) {
		return h.next.Handle(ctx, r)
	}
	return nil
}

func (s *Service) Run(ctx context.Context) error {
	defer func() {
		final, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		// Persist queued metadata after the other application workers have stopped.
		for i := 0; i < 4; i++ {
			if err := s.flush(final); err != nil {
				return
			}
			if len(s.input) == 0 {
				return
			}
		}
	}()
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	warned := false
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
		work, cancel := context.WithTimeout(ctx, 4*time.Second)
		err := s.cycle(work)
		cancel()
		if ctx.Err() != nil {
			return nil
		}
		if err != nil && !warned {
			slog.Warn("Managed event log delivery pending; metadata remains bounded in the outbox")
			warned = true
		}
		if err == nil {
			warned = false
		}
	}
}

func (s *Service) cycle(ctx context.Context) error {
	hasLocalEvents := len(s.input) != 0 || len(s.held) != 0 || s.dropped.Load() != 0
	if !hasLocalEvents {
		var queued, dropped bool
		err := s.DB.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM event_log_queue), dropped>0 FROM event_log_status WHERE id=1").Scan(&queued, &dropped)
		if err != nil {
			return err
		}
		if !dropped {
			if !queued {
				return nil
			}
			return s.deliver(ctx)
		}
	}
	if err := s.flush(ctx); err != nil {
		return err
	}
	return s.deliver(ctx)
}

func (s *Service) flush(ctx context.Context) error {
	if len(s.held) == 0 {
		for len(s.held) < 64 {
			select {
			case event := <-s.input:
				s.held = append(s.held, event)
			default:
				goto drained
			}
		}
	}
drained:
	originalLost := s.dropped.Swap(0)
	lost := originalLost
	committed := false
	defer func() {
		if !committed {
			s.dropped.Add(originalLost)
		}
	}()
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, event := range s.held {
		raw, err := json.Marshal(event)
		if err != nil {
			return err
		}
		result, err := tx.ExecContext(ctx, "INSERT INTO event_log_queue(payload) SELECT ? WHERE (SELECT COUNT(*) FROM event_log_queue)<8192", string(raw))
		if err != nil {
			return err
		}
		n, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if n == 0 {
			lost++
		}
	}
	if lost > 0 {
		if _, err = tx.ExecContext(ctx, "UPDATE event_log_status SET dropped=min(dropped+?,9223372036854775807) WHERE id=1", lost); err != nil {
			return err
		}
	}
	var dropped int64
	if err = tx.QueryRowContext(ctx, "SELECT dropped FROM event_log_status WHERE id=1").Scan(&dropped); err != nil {
		return err
	}
	if dropped > 0 {
		raw, _ := json.Marshal(logs.Event{Time: time.Now().Unix(), Category: "application", Level: "warn", Code: "log.delivery_gap", Count: dropped})
		result, err := tx.ExecContext(ctx, "INSERT INTO event_log_queue(payload) SELECT ? WHERE (SELECT COUNT(*) FROM event_log_queue)<8192", string(raw))
		if err != nil {
			return err
		}
		n, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if n == 1 {
			if _, err = tx.ExecContext(ctx, "UPDATE event_log_status SET dropped=0 WHERE id=1"); err != nil {
				return err
			}
		}
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	committed = true
	s.held = nil
	return nil
}

func (s *Service) deliver(ctx context.Context) error {
	var batch agent.EventLogRequest
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = tx.QueryRowContext(ctx, "SELECT (SELECT value FROM settings WHERE key='event_log_epoch'),(SELECT value FROM settings WHERE key='node_id')").Scan(&batch.Epoch, &batch.NodeID); err != nil {
		return err
	}
	rows, err := tx.QueryContext(ctx, "SELECT sequence,payload FROM event_log_queue ORDER BY sequence LIMIT 64")
	if err != nil {
		return err
	}
	for rows.Next() {
		var seq int64
		var raw string
		var event logs.Event
		if err = rows.Scan(&seq, &raw); err != nil {
			break
		}
		if err = json.Unmarshal([]byte(raw), &event); err != nil {
			break
		}
		event.Sequence = seq
		if err = event.Validate(); err != nil {
			break
		}
		batch.Events = append(batch.Events, event)
	}
	err = errors.Join(err, rows.Err(), rows.Close())
	if err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	if len(batch.Events) == 0 {
		return nil
	}
	if err = s.Agent.AppendEvents(ctx, batch); err != nil {
		return err
	}
	// Acknowledgement authorizes deletion of only the original epoch's prefix.
	_, err = s.DB.ExecContext(ctx, "DELETE FROM event_log_queue WHERE sequence<=? AND EXISTS(SELECT 1 FROM settings WHERE key='event_log_epoch' AND value=?)", batch.Events[len(batch.Events)-1].Sequence, batch.Epoch)
	if s.OnDelivered != nil {
		for _, event := range batch.Events {
			if event.Category == "task" {
				s.OnDelivered()
				break
			}
		}
	}
	return err
}
