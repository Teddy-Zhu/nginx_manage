package notifications

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
	"nginxpanel/internal/certificates"
	"nginxpanel/internal/limits"
	"nginxpanel/internal/secure"
)

func (s *Service) collectSignals(ctx context.Context, policy Policy) error {
	now := time.Now().Unix()
	rows, err := s.DB.QueryContext(ctx, `SELECT v.id,v.certificate_id,v.summary,COALESCE(r.renew_at,0)
FROM certificate_versions v JOIN certificates c ON c.id=v.certificate_id LEFT JOIN acme_renewals r ON r.version_id=v.id
WHERE v.id=c.latest_version_id OR v.id IN (SELECT version_id FROM nginx_certificate_references WHERE revision_id=(SELECT applied_revision FROM config_head WHERE id=1))
ORDER BY v.id LIMIT ?`, limits.Certificates+limits.CertificateReferences+1)
	if err != nil {
		return err
	}
	type certificateSignal struct {
		event     Event
		versionID string
	}
	items := []certificateSignal{}
	scanned := 0
	for rows.Next() {
		scanned++
		if scanned > limits.Certificates+limits.CertificateReferences {
			rows.Close()
			return errors.New("certificate signal budget exceeded")
		}
		var versionID, certificateID, raw string
		var renewAt int64
		if err := rows.Scan(&versionID, &certificateID, &raw, &renewAt); err != nil {
			rows.Close()
			return err
		}
		if len(raw) > 16<<10 {
			rows.Close()
			return errors.New("certificate summary exceeds notification budget")
		}
		var summary certificates.Summary
		if err := json.Unmarshal([]byte(raw), &summary); err != nil {
			rows.Close()
			return err
		}
		if summary.NotAfter <= summary.NotBefore {
			rows.Close()
			return errors.New("invalid certificate lifetime")
		}
		end := summary.NotAfter
		if summary.ChainNotAfter > 0 {
			end = min(end, summary.ChainNotAfter)
		}
		lifetime := max(int64(1), end-summary.NotBefore)
		lead := min(policy.ExpiryDays*86400, lifetime/3)
		warnAt := end - lead
		if renewAt > warnAt && renewAt < end {
			warnAt = renewAt
		}
		kind, severity, state := "certificate.expiring", "warning", "firing"
		if now >= end {
			kind = "certificate.expired"
			severity = "critical"
		} else if now < warnAt {
			continue
		}
		summaryText := fmt.Sprintf("证书版本 %s 将于 %s 到期", versionID, time.Unix(end, 0).UTC().Format(time.RFC3339))
		if now >= end {
			summaryText = fmt.Sprintf("证书版本 %s 已过期", versionID)
		}
		items = append(items, certificateSignal{versionID: versionID, event: Event{ID: "certificate." + secure.Hash([]byte(kind+":"+versionID)), Kind: kind, ResourceKind: "certificate", ResourceID: certificateID, Severity: severity, State: state, Summary: summaryText, Occurrences: 1, CreatedAt: now, LastSeenAt: now, ExpiresAt: now + 86400}})
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	if len(items) > limits.Certificates+limits.CertificateReferences {
		return errors.New("certificate signal budget exceeded")
	}
	stat, diskErr := s.readDisk(ctx)
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, item := range items {
		event := item.event // The stable version key records an episode once, not every polling cycle.
		var exists bool
		if err = tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM notification_signals WHERE id=?)", event.ID).Scan(&exists); err != nil {
			return err
		}
		if exists {
			continue
		}
		if err = insertEvent(ctx, tx, event, event.ID); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, "INSERT INTO notification_signals(id,active,episode,version_id) VALUES(?,1,?,?)", event.ID, now, item.versionID); err != nil {
			return err
		}
	}
	if diskErr == nil {
		diskErr = s.diskSignal(ctx, tx, policy, now, stat)
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	return diskErr
}

type diskProbe struct {
	done chan struct{}
	stat unix.Statfs_t
	err  error
}

func (s *Service) readDisk(ctx context.Context) (unix.Statfs_t, error) {
	s.mu.Lock()
	probe := s.disk
	if probe != nil {
		select {
		case <-probe.done:
			probe = nil
		default:
		}
	}
	if probe == nil {
		probe = &diskProbe{done: make(chan struct{})}
		s.disk = probe
		go func() { probe.err = unix.Statfs(filepath.Join(s.DataDir, "app"), &probe.stat); close(probe.done) }()
	}
	s.mu.Unlock()
	read, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	select {
	case <-read.Done():
		return unix.Statfs_t{}, errors.New("panel data filesystem statistics timed out")
	case <-probe.done:
		return probe.stat, probe.err
	}
}
func (s *Service) diskSignal(ctx context.Context, tx *sql.Tx, policy Policy, now int64, stat unix.Statfs_t) error {
	if stat.Bsize <= 0 || stat.Bavail > stat.Bfree || stat.Bfree > stat.Blocks || stat.Blocks > math.MaxUint64/uint64(stat.Bsize) {
		return errors.New("panel data filesystem statistics unavailable")
	}
	available := float64(stat.Bavail) * float64(stat.Bsize)
	capacity := float64(stat.Blocks-stat.Bfree+stat.Bavail) * float64(stat.Bsize)
	if capacity <= 0 {
		return errors.New("panel data filesystem capacity unavailable")
	}
	percent := available / capacity * 100
	var active bool
	var episode int64
	err := tx.QueryRowContext(ctx, "SELECT active,episode FROM notification_signals WHERE id='panel-data'").Scan(&active, &episode)
	if !errors.Is(err, sql.ErrNoRows) && err != nil {
		return err
	}
	low := available < float64(policy.DiskMiB)*float64(1<<20) || percent < policy.DiskPercent
	recovered := available >= float64(policy.DiskMiB)*float64(1<<20)*1.2 && percent >= policy.DiskPercent+2
	if !active && !low || active && !recovered {
		return nil
	}
	kind, severity, state := "disk.low", "warning", "firing"
	summary := fmt.Sprintf("面板数据目录剩余空间 %.0f MiB（%.1f%%）", available/float64(1<<20), percent)
	if active {
		kind = "disk.recovered"
		severity = "info"
		state = "resolved"
	} else {
		episode++
	}
	eventID := "disk." + secure.Hash([]byte(fmt.Sprintf("%s:%d", kind, episode)))
	event := Event{ID: eventID, Kind: kind, ResourceKind: "panel_data", ResourceID: "data", Severity: severity, State: state, Summary: summary, Occurrences: 1, CreatedAt: now, LastSeenAt: now, ExpiresAt: now + 86400}
	if err = insertEvent(ctx, tx, event, event.ID); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, "INSERT INTO notification_signals(id,active,episode) VALUES('panel-data',?,?) ON CONFLICT(id) DO UPDATE SET active=excluded.active,episode=excluded.episode", !active, episode)
	return err
}
