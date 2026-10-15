package migrations

import (
	"errors"
	"strconv"
	"strings"
)

// LatestVersion derives the binary's target schema from its embedded SQL files.
func LatestVersion() (int64, error) {
	entries, err := FS.ReadDir(".")
	if err != nil {
		return 0, err
	}
	var latest int64
	seen := map[int64]bool{}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}
		prefix, _, found := strings.Cut(entry.Name(), "_")
		version, err := strconv.ParseInt(prefix, 10, 64)
		if !found || err != nil || version < 1 || seen[version] {
			return 0, errors.New("内嵌数据库迁移版本无效或重复")
		}
		seen[version] = true
		latest = max(latest, version)
	}
	if latest == 0 {
		return 0, errors.New("内嵌数据库迁移为空")
	}
	return latest, nil
}
