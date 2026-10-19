package dockerapi

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"regexp"
	"strings"
	"time"
)

var pullReference = regexp.MustCompile(`^ghcr\.io/[a-z0-9][a-z0-9._-]*/[a-z0-9][a-z0-9._-]*/(panel|nginx)@sha256:[0-9a-f]{64}$`)

// Pull only downloads an immutable signed catalog choice. It never imports a
// caller URL, authenticates a registry, reads CLI credentials or starts images.
// Callers still have to verify local image contents after a complete stream.
func Pull(ctx context.Context, reference, architecture string) error {
	if !pullReference.MatchString(reference) || architecture != "amd64" && architecture != "arm64" {
		return errors.New("镜像拉取须使用固定 GHCR 仓库摘要和受支持架构")
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	d, err := newClient(10 * time.Minute)
	if err != nil {
		return err
	}
	defer d.Close()
	parts := strings.SplitN(reference, "@", 2)
	q := url.Values{"fromImage": {parts[0]}, "tag": {parts[1]}, "platform": {"linux/" + architecture}}
	resp, err := d.Request(ctx, "POST", "/images/create?"+q.Encode(), nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	limited := &io.LimitedReader{R: resp.Body, N: (8 << 20) + 1}
	scanner := bufio.NewScanner(limited)
	scanner.Buffer(make([]byte, 4096), 64<<10)
	count := 0
	for scanner.Scan() {
		count++
		if count > 65536 || limited.N <= 0 {
			return errors.New("Docker 镜像下载进度超过读取预算")
		}
		var event struct {
			Error       string `json:"error"`
			ErrorDetail *struct {
				Message string `json:"message"`
			} `json:"errorDetail"`
		}
		if json.Unmarshal(scanner.Bytes(), &event) != nil {
			return errors.New("Docker 镜像下载进度无效")
		}
		if event.Error != "" || event.ErrorDetail != nil {
			message := event.Error
			if event.ErrorDetail != nil && event.ErrorDetail.Message != "" {
				message = event.ErrorDetail.Message
			}
			message = strings.Map(func(r rune) rune {
				if r < 32 || r == 127 {
					return ' '
				}
				return r
			}, message)
			chars := []rune(strings.TrimSpace(message))
			if len(chars) > 400 {
				chars = chars[:400]
			}
			if len(chars) == 0 {
				return errors.New("Docker 返回镜像拉取错误")
			}
			return errors.New("Docker 镜像拉取失败：" + string(chars))
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	if limited.N <= 0 || count == 0 {
		return errors.New("Docker 镜像下载回执缺失或超过读取预算")
	}
	return ctx.Err()
}
