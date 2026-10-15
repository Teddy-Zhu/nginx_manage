package acme

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/go-acme/lego/v5/challenge/dns01"
	"nginxpanel/internal/limits"
	"nginxpanel/internal/secure"
)

type dnsIntent struct {
	Zone          string   `json:"zone"`
	ZoneID        string   `json:"zone_id"`
	Value         string   `json:"value"`
	Baseline      []string `json:"baseline"`
	Created       []string `json:"created"`
	CreatePending bool     `json:"create_pending"`
}
type journalDNS struct {
	service *Service
	orderID string
	api     *dnsAPI
}

var challengeFQDN = regexp.MustCompile(`^[a-z0-9_.-]{1,253}\.$`)
var errDNSChanged = errors.New("challenge DNS record changed externally")
var errDNSCreateUnconfirmed = errors.New("challenge DNS create result remains uncertain")

func (j *journalDNS) Timeout() (time.Duration, time.Duration) {
	return 3 * time.Minute, 3 * time.Second
}
func (j *journalDNS) save(ctx context.Context, id, state string, payload dnsIntent) error {
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	_, err = j.service.DB.ExecContext(ctx, "UPDATE acme_dns_records SET payload=?,state=?,last_error='' WHERE id=? AND order_id=?", j.service.Vault.Seal(raw, "acme:dns-record:"+id), state, id, j.orderID)
	return err
}
func (j *journalDNS) decode(id string, sealed []byte) (dnsIntent, error) {
	raw, err := j.service.Vault.Open(sealed, "acme:dns-record:"+id)
	var p dnsIntent
	if err == nil {
		err = json.Unmarshal(raw, &p)
	}
	if err == nil && (p.Zone == "" || p.ZoneID == "" || len(p.Value) != 43 || len(p.Baseline) > 16 || len(p.Created) > 16) {
		err = errors.New("invalid DNS intent")
	}
	return p, err
}
func (j *journalDNS) Present(ctx context.Context, domain, token, keyAuth string) error {
	info := dns01.GetChallengeInfo(ctx, domain, keyAuth)
	fqdn := strings.ToLower(info.EffectiveFQDN)
	if !challengeFQDN.MatchString(fqdn) {
		return errors.New("invalid effective challenge DNS name")
	}
	hash := secure.Hash([]byte(info.Value))
	var id, state string
	var sealed []byte
	err := j.service.DB.QueryRowContext(ctx, "SELECT id,state,payload FROM acme_dns_records WHERE order_id=? AND fqdn=? AND value_hash=?", j.orderID, fqdn, hash).Scan(&id, &state, &sealed)
	var intent dnsIntent
	if err == nil {
		intent, err = j.decode(id, sealed)
		if err != nil {
			return err
		}
	}
	if err == nil && intent.Value != info.Value {
		return errors.New("DNS intent differs from authorization")
	}
	if errors.Is(err, sql.ErrNoRows) || state == "cleaned" {
		zone, zoneID, err := j.api.zone(ctx, fqdn)
		if err != nil {
			return err
		}
		records, err := j.api.list(ctx, fqdn, zone, zoneID)
		if err != nil {
			return err
		}
		intent = dnsIntent{Zone: zone, ZoneID: zoneID, Value: info.Value, Baseline: []string{}, Created: []string{}}
		for _, record := range records {
			if record.Value == info.Value {
				intent.Baseline = append(intent.Baseline, record.ID)
			}
		}
		if len(intent.Baseline) > 16 {
			return errors.New("too many identical challenge values")
		}
		tx, err := j.service.DB.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		defer tx.Rollback()
		var count int
		if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM acme_dns_records").Scan(&count); err != nil {
			return err
		}
		if id == "" && count >= limits.ACMEDNSRecords {
			return errors.New("DNS intent history capacity reached")
		}
		if _, err := tx.ExecContext(ctx, "INSERT INTO acme_dns_locks(fqdn,order_id) VALUES(?,?) ON CONFLICT(fqdn) DO NOTHING", fqdn, j.orderID); err != nil {
			return err
		}
		var owner string
		if err := tx.QueryRowContext(ctx, "SELECT order_id FROM acme_dns_locks WHERE fqdn=?", fqdn).Scan(&owner); err != nil {
			return err
		}
		if owner != j.orderID {
			return errors.New("challenge DNS name has an unresolved owner")
		}
		if id == "" {
			id = secure.ID()
		}
		raw, _ := json.Marshal(intent)
		if _, err := tx.ExecContext(ctx, "INSERT INTO acme_dns_records(id,order_id,fqdn,value_hash,payload,state) VALUES(?,?,?,?,?,'preparing') ON CONFLICT(id) DO UPDATE SET payload=excluded.payload,state='preparing',last_error=''", id, j.orderID, fqdn, hash, j.service.Vault.Seal(raw, "acme:dns-record:"+id)); err != nil {
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	records, err := j.api.list(ctx, fqdn, intent.Zone, intent.ZoneID)
	if err != nil {
		return err
	}
	found, owned := false, false
	for _, record := range records {
		if slices.Contains(intent.Created, record.ID) && record.Value != intent.Value {
			return errDNSChanged
		}
		if record.Value == intent.Value {
			found = true
			if !slices.Contains(intent.Baseline, record.ID) {
				owned = true
				if !slices.Contains(intent.Created, record.ID) {
					intent.Created = append(intent.Created, record.ID)
				}
			}
		}
	}
	if intent.CreatePending && !owned {
		return errDNSCreateUnconfirmed
	}
	if owned {
		intent.CreatePending = false
	}
	if len(intent.Created) > 16 {
		return errors.New("too many created challenge records")
	}
	if !found {
		if len(intent.Created) >= 16 {
			return errors.New("challenge record retry budget reached")
		}
		// The encrypted intent and baseline are durable before the remote write.
		// A lost create response is reconciled by the unique challenge value.
		intent.CreatePending = true
		if err := j.save(ctx, id, "preparing", intent); err != nil {
			return err
		}
		recordID, err := j.api.create(ctx, fqdn, intent.Zone, intent.ZoneID, intent.Value)
		if err != nil {
			if dnsRejected(err) {
				intent.CreatePending = false
				if saveErr := j.save(ctx, id, "preparing", intent); saveErr != nil {
					return saveErr
				}
			}
			return err
		}
		intent.CreatePending = false
		intent.Created = append(intent.Created, recordID)
	}
	return j.save(ctx, id, "present", intent)
}

// Cleanup is driven explicitly by the order worker. It is never delegated to
// provider cleanup routines that can delete another TXT value at the same name.
func (j *journalDNS) CleanUp(context.Context, string, string, string) error {
	return errors.New("use durable order cleanup")
}
func (j *journalDNS) cleanup(ctx context.Context) error {
	rows, err := j.service.DB.QueryContext(ctx, "SELECT id,fqdn,payload FROM acme_dns_records WHERE order_id=? AND state!='cleaned' ORDER BY fqdn,id", j.orderID)
	if err != nil {
		return err
	}
	type item struct {
		id, fqdn string
		sealed   []byte
	}
	items := []item{}
	for rows.Next() {
		var it item
		if err := rows.Scan(&it.id, &it.fqdn, &it.sealed); err != nil {
			rows.Close()
			return err
		}
		items = append(items, it)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	var failures error
	for _, it := range items {
		intent, err := j.decode(it.id, it.sealed)
		if err == nil {
			err = j.cleanupRecord(ctx, it.id, it.fqdn, intent)
		}
		if err != nil {
			failures = errors.Join(failures, err)
			if _, saveErr := j.service.DB.ExecContext(ctx, "UPDATE acme_dns_records SET state='blocked',last_error='验证记录清理未确认，请恢复原任务或核对本机记录' WHERE id=?", it.id); saveErr != nil {
				return saveErr
			}
		}
	}
	if failures != nil {
		return failures
	}
	_, err = j.service.DB.ExecContext(ctx, "DELETE FROM acme_dns_locks WHERE order_id=?", j.orderID)
	return err
}
func (j *journalDNS) cleanupRecord(ctx context.Context, id, fqdn string, intent dnsIntent) error {
	records, err := j.api.list(ctx, fqdn, intent.Zone, intent.ZoneID)
	if err != nil {
		return err
	}
	owned := false
	for _, record := range records {
		if slices.Contains(intent.Created, record.ID) && record.Value != intent.Value {
			return errDNSChanged
		}
		if record.Value == intent.Value && !slices.Contains(intent.Baseline, record.ID) {
			owned = true
			if !slices.Contains(intent.Created, record.ID) {
				intent.Created = append(intent.Created, record.ID)
			}
		}
	}
	// Absence cannot prove a timed-out create was rejected. Retain the intent
	// and lock for reconciliation instead of allowing an untracked late record.
	if intent.CreatePending && !owned {
		return errDNSCreateUnconfirmed
	}
	intent.CreatePending = false
	if len(intent.Created) > 16 {
		return errors.New("too many challenge records to clean")
	}
	if err := j.save(ctx, id, "present", intent); err != nil {
		return err
	}
	for _, record := range records {
		if slices.Contains(intent.Created, record.ID) && record.Value == intent.Value {
			if err := j.api.delete(ctx, intent.Zone, intent.ZoneID, record.ID); err != nil {
				return err
			}
		}
	}
	return j.save(ctx, id, "cleaned", intent)
}
