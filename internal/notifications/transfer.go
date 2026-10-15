package notifications

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"nginxpanel/internal/fault"
	"nginxpanel/internal/secure"
)

type TransferChannel struct {
	Name          string   `json:"name"`
	Kind          string   `json:"kind"`
	Subscriptions []string `json:"subscriptions"`
	Config        Config   `json:"config"`
}

func (s *Service) ExportChannels(ctx context.Context, tx *sql.Tx) ([]TransferChannel, error) {
	rows, err := tx.QueryContext(ctx, "SELECT "+channelColumns+" FROM notification_channels ORDER BY id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []TransferChannel{}
	for rows.Next() {
		c, err := s.scanChannel(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, TransferChannel{c.Name, c.Kind, c.Subscriptions, c.Config})
	}
	return out, rows.Err()
}
func ValidateTransferChannels(items []TransferChannel) error {
	if len(items) > MaxChannels {
		return fault.Invalid("迁移通知渠道超过限制")
	}
	for _, c := range items {
		if !text(c.Name, 128) || c.Name == "" || len(c.Subscriptions) > len(Kinds) {
			return fault.Invalid("迁移通知渠道无效")
		}
		seen := map[string]bool{}
		for _, kind := range c.Subscriptions {
			if !validKind(kind) || seen[kind] {
				return fault.Invalid("迁移通知订阅无效")
			}
			seen[kind] = true
		}
		if err := c.Config.validate(c.Kind, false); err != nil {
			return err
		}
	}
	return nil
}
func (s *Service) ImportChannels(ctx context.Context, tx *sql.Tx, items []TransferChannel) error {
	if err := ValidateTransferChannels(items); err != nil {
		return err
	}
	var count int
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM notification_channels").Scan(&count); err != nil {
		return err
	}
	if count+len(items) > MaxChannels {
		return fault.Conflict("目标通知渠道容量不足")
	}
	for _, c := range items {
		id := secure.ID()
		raw, err := json.Marshal(c.Config)
		if err != nil {
			return err
		}
		subs, err := json.Marshal(c.Subscriptions)
		if err != nil {
			return err
		}
		now := time.Now().Unix()
		if _, err := tx.ExecContext(ctx, "INSERT INTO notification_channels(id,version,name,kind,enabled,subscriptions,config,created_at,updated_at) VALUES(?,1,?,?,0,?,?,?,?)", id, c.Name, c.Kind, string(subs), s.Vault.Seal(raw, channelAAD(id, 1)), now, now); err != nil {
			return err
		}
	}
	return nil
}
