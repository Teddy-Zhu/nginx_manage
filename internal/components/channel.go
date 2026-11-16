package components

import (
	"context"
	"database/sql"
	"errors"

	"nginxpanel/internal/auth"
	"nginxpanel/internal/fault"
)

type UpdateChannel struct {
	Channel string `json:"channel"`
}

func (s *Service) GetUpdateChannel(ctx context.Context) (UpdateChannel, error) {
	var out UpdateChannel
	err := s.DB.QueryRowContext(ctx, "SELECT value FROM settings WHERE key='update_channel'").Scan(&out.Channel)
	if errors.Is(err, sql.ErrNoRows) {
		return UpdateChannel{Channel: "stable"}, nil
	}
	if err != nil {
		return out, err
	}
	if out.Channel != "stable" && out.Channel != "beta" {
		return out, fault.Unavailable("更新通道设置无效")
	}
	return out, nil
}

func (s *Service) SetUpdateChannel(ctx context.Context, p auth.Principal, in UpdateChannel) (UpdateChannel, error) {
	if err := p.Require("components.manage", "system.write"); err != nil {
		return UpdateChannel{}, err
	}
	if in.Channel != "stable" && in.Channel != "beta" {
		return UpdateChannel{}, fault.Invalid("请选择稳定版或 Beta 更新通道")
	}
	_, err := s.DB.ExecContext(ctx, "INSERT INTO settings(key,value) VALUES('update_channel',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", in.Channel)
	return in, err
}
