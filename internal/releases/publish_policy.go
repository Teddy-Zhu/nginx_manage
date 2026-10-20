package releases

import (
	"encoding/json"
	"errors"
	"path/filepath"
)

// ReadPublicationPolicy reads the release author's version-specific decision.
// Signing reads this separately from the build artifact's publication spec.
func ReadPublicationPolicy(name, version string) (bool, error) {
	if name == "" || !validVersion(version) {
		return false, errors.New("须提供明确版本及独立批准的发布策略文件")
	}
	abs, err := filepath.Abs(name)
	if err != nil {
		return false, err
	}
	raw, err := readPublicationFile(abs, 4<<10)
	if err != nil {
		return false, err
	}
	var policy map[string]json.RawMessage
	if err := strictJSON(raw, &policy); err != nil {
		return false, err
	}
	if len(policy) != 2 || policy["version"] == nil || policy["automatic_rollback"] == nil {
		return false, errors.New("发布策略仅允许 version 和 automatic_rollback 字段")
	}
	var declaredVersion string
	var automaticRollback *bool
	if err := json.Unmarshal(policy["version"], &declaredVersion); err != nil {
		return false, err
	}
	if err := json.Unmarshal(policy["automatic_rollback"], &automaticRollback); err != nil {
		return false, err
	}
	if declaredVersion != version || automaticRollback == nil {
		return false, errors.New("发布策略须匹配确切版本并显式声明 automatic_rollback")
	}
	return *automaticRollback, nil
}
