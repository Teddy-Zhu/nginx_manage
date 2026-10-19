package dockerapi

import (
	"errors"
	"strings"
)

// ValidateLabels bounds metadata frozen by independent container transactions.
func ValidateLabels(labels map[string]string) error {
	if len(labels) > 64 {
		return errors.New("容器标签超过预算")
	}
	total := 0
	for k, v := range labels {
		total += len(k) + len(v)
		if k == "" || len(k) > 256 || len(v) > 2048 || strings.ContainsAny(k+v, "\x00\r\n") {
			return errors.New("容器标签无效")
		}
	}
	if total > 8192 {
		return errors.New("容器标签超过预算")
	}
	return nil
}
