package hostdns

import (
	"context"
	"database/sql"
	"encoding/json"

	"nginxpanel/internal/fault"
)

const MaxTransferTargets = 64

// Transfer contains confirmed desired settings, never observed DHCP state,
// connection secrets, host files, source hashes or recovery authorizations.
type Transfer struct {
	Entries []TransferEntry `json:"entries"`
}
type TransferEntry struct {
	Target string `json:"target"`
	Config Config `json:"config"`
}

func ValidateTransfer(value *Transfer) error {
	if value == nil {
		return nil
	}
	if value.Entries == nil || len(value.Entries) > MaxTransferTargets {
		return fault.Invalid("主机 DNS 迁移最多包含 64 个已保存目标")
	}
	seen := map[string]bool{}
	for _, entry := range value.Entries {
		if seen[entry.Target] {
			return fault.Invalid("主机 DNS 迁移目标重复")
		}
		if entry.Config.Servers == nil || entry.Config.Search == nil {
			return fault.Invalid("主机 DNS 迁移配置的地址和搜索域须为数组")
		}
		for _, family := range []*Family{entry.Config.IPv4, entry.Config.IPv6} {
			if family != nil && (family.Servers == nil || family.Search == nil) {
				return fault.Invalid("主机 DNS 地址族的地址和搜索域须为数组")
			}
		}
		if err := entry.Config.Validate(entry.Target); err != nil {
			return err
		}
		seen[entry.Target] = true
	}
	return nil
}

func (s *Service) Export(ctx context.Context, tx *sql.Tx) (*Transfer, error) {
	rows, err := tx.QueryContext(ctx, "SELECT target,payload FROM host_dns_desired ORDER BY target LIMIT 65")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := &Transfer{Entries: []TransferEntry{}}
	for rows.Next() {
		var entry TransferEntry
		var raw []byte
		if err = rows.Scan(&entry.Target, &raw); err != nil {
			return nil, err
		}
		plain, err := s.Vault.Open(raw, "host-dns:desired:"+entry.Target)
		if err != nil {
			return nil, err
		}
		if err = json.Unmarshal(plain, &entry.Config); err != nil {
			return nil, err
		}
		out.Entries = append(out.Entries, entry)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	return out, ValidateTransfer(out)
}
