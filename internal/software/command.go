package software

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"time"
)

type limitedLog struct {
	bytes.Buffer
	progress Progress
	last     time.Time
}

func (b *limitedLog) Write(p []byte) (int, error) {
	n := len(p)
	_, _ = b.Buffer.Write(p)
	if b.progress != nil && time.Since(b.last) >= time.Second {
		b.last = time.Now()
		lines := strings.FieldsFunc(strings.ToValidUTF8(string(p), ""), func(r rune) bool { return r == '\n' || r == '\r' })
		if len(lines) > 0 {
			last := lines[len(lines)-1]
			if len(last) > 500 {
				last = last[:500]
			}
			b.progress(last)
		}
	}
	if b.Len() > 16000 {
		tail := append([]byte(nil), b.Bytes()[b.Len()-16000:]...)
		b.Reset()
		_, _ = b.Buffer.Write(tail)
	}
	return n, nil
}
func Docker(ctx context.Context, progress Progress, args ...string) (string, error) {
	return runDocker(ctx, progress, nil, args...)
}

func DockerLocal(ctx context.Context, progress Progress, input io.Reader, args ...string) (string, error) {
	return runDocker(ctx, progress, input, append([]string{"--host", "unix:///run/docker.sock"}, args...)...)
}

func runDocker(ctx context.Context, progress Progress, input io.Reader, args ...string) (string, error) {
	command := exec.CommandContext(ctx, "/usr/bin/docker", args...)
	command.Stdin = input
	log := limitedLog{progress: progress}
	command.Stdout = &log
	command.Stderr = &log
	err := command.Run()
	text := strings.TrimSpace(log.String())
	if err != nil {
		if text == "" {
			return text, fmt.Errorf("无法执行 Docker 操作：%w", err)
		}
		return text, fmt.Errorf("Docker 操作失败：%s", text)
	}
	return text, nil
}
