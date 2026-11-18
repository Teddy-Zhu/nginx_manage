package software

import (
	"context"
	"fmt"
	"regexp"

	"nginxpanel/internal/componentversions"
)

var pulledDigest = regexp.MustCompile(`(?m)^Digest: (sha256:[0-9a-f]{64})\r?$`)

// PullBuiltinTag resolves a mutable tag before changing the running service or
// writing configuration. The installed component and its rollback use digests.
func PullBuiltinTag(ctx context.Context, app, tag string, progress Progress) (string, error) {
	repository := componentversions.BuiltinImageRepository(app)
	if repository == "" || !componentversions.ValidImageTag(tag) {
		return "", fmt.Errorf("无效的组件镜像标签")
	}
	reference := repository + ":" + tag
	if progress != nil {
		progress("正在下载镜像 " + reference)
	}
	log, err := Docker(ctx, progress, "pull", reference)
	if err != nil {
		return "", fmt.Errorf("无法拉取 %s，请核对镜像标签或选择其他版本：%w", reference, err)
	}
	if match := pulledDigest.FindStringSubmatch(log); match != nil {
		return repository + "@" + match[1], nil
	}
	return "", fmt.Errorf("Docker 未提供 %s 对应的镜像摘要", reference)
}
