package software

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
	"sync"
	"time"
)

type runtimeObservation struct {
	State           string `json:"state"`
	Message         string `json:"message,omitempty"`
	Entry           string `json:"entry,omitempty"`
	Version         string `json:"version,omitempty"`
	SoftwareVersion string `json:"software_version,omitempty"`
}

func decodeObservation(raw string) (runtimeObservation, error) {
	var state runtimeObservation
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	err := decoder.Decode(&state)
	if err == nil && decoder.Decode(new(any)) != io.EOF {
		err = errors.New("状态检查返回了多余内容")
	}
	if err == nil {
		switch state.State {
		case "running", "starting", "stopped", "unhealthy", "missing", "unknown":
		default:
			err = errors.New("状态检查返回了不支持的状态")
		}
	}
	if err == nil && (len(state.Message) > 1024 || len(state.Version) > 128 || len(state.SoftwareVersion) > 128 || !validEntry(state.Entry)) {
		err = errors.New("状态检查返回的信息或访问入口无效")
	}
	return state, err
}
func observeApplication(ctx context.Context, data string, installed *Installation) {
	installed.State, installed.Error, installed.Entry = "unknown", "", ""
	call, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	raw, err := operationCommand(call, data, installed.SourceID, installed.Application, "status", nil)
	var state runtimeObservation
	if err == nil {
		state, err = decodeObservation(raw)
	}
	if err != nil {
		installed.Error = "无法读取软件状态：" + err.Error()
		return
	}
	installed.State, installed.Error, installed.Entry = state.State, state.Message, state.Entry
	if installed.Version != nil && state.Version != installed.Version.Version {
		installed.State, installed.Error = "unknown", "实际运行版本与安装记录不一致，请查看操作日志"
	}
}
func validEntry(raw string) bool {
	if raw == "" {
		return true
	}
	if len(raw) > 2048 {
		return false
	}
	value := strings.ReplaceAll(raw, "{host}", "localhost")
	if strings.ContainsAny(value, "{}\\") {
		return false
	}
	u, err := url.Parse(value)
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Hostname() != "" && u.User == nil
}

// Software owns its runtime. The panel only invokes the registered read-only
// status operation and consumes its documented response, without inspecting Docker.
func Observe(ctx context.Context, data string, catalog *Catalog) {
	var workers sync.WaitGroup
	jobs := make(chan int)
	for i := 0; i < min(4, len(catalog.Installed)); i++ {
		workers.Go(func() {
			for index := range jobs {
				observeApplication(ctx, data, &catalog.Installed[index])
			}
		})
	}
	for i := range catalog.Installed {
		select {
		case jobs <- i:
		case <-ctx.Done():
			catalog.Installed[i].State = "unknown"
			catalog.Installed[i].Error = fmt.Sprintf("状态检查未完成：%v", ctx.Err())
			catalog.Installed[i].Entry = ""
		}
	}
	close(jobs)
	workers.Wait()
}
