package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os/exec"
	"strings"
	"sync"
	"time"

	"nginxpanel/internal/fault"
	"nginxpanel/internal/limits"
	"nginxpanel/internal/monitoring"
	"nginxpanel/internal/platform"
)

type metricSampler struct {
	mu         sync.Mutex
	collector  platform.MetricsCollector
	capability monitoring.Capability
	ctx        context.Context
	done       chan struct{}
	last       time.Time
	sample     *monitoring.Sample
	err        error
}
type metricRequest struct {
	Protocol int   `json:"protocol"`
	Interval int64 `json:"interval_seconds"`
}
type metricResult struct {
	Protocol int                `json:"protocol"`
	Code     string             `json:"code"`
	Message  string             `json:"message"`
	Data     *monitoring.Sample `json:"data"`
}

func metricReply(w http.ResponseWriter, sample *monitoring.Sample, err error) {
	status, code, message := 200, "OK", "成功"
	if err != nil {
		status, code, message = 503, "METRICS_UNAVAILABLE", "宿主机采样暂不可用"
		var known *fault.Error
		if errors.As(err, &known) {
			status, code, message = known.Status, known.Code, known.Message
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	writeJSON(w, metricResult{Protocol, code, message, sample})
}
func (m *metricSampler) read(ctx context.Context, interval int64) (*monitoring.Sample, error) {
	if !m.capability.Available {
		return nil, fault.Unavailable(m.capability.Reason)
	}
	m.mu.Lock()
	if m.done == nil && time.Since(m.last) >= time.Duration(limits.MetricIntervalSeconds)*time.Second {
		m.last = time.Now()
		m.done = make(chan struct{})
		done := m.done
		// One job can remain blocked in a kernel filesystem operation. Further
		// requests wait on this job instead of accumulating root goroutines.
		go func() {
			sample := m.collector.Collect(interval)
			serviceCtx, cancel := context.WithTimeout(m.ctx, 3*time.Second)
			sample.Services = readMetricServices(serviceCtx)
			cancel()
			encoded, err := json.Marshal(sample)
			if err == nil && len(encoded) > limits.MetricSampleBytes {
				err = fault.Unavailable("采样超过响应容量上限")
			}
			m.mu.Lock()
			if err == nil {
				m.sample = &sample
			}
			m.err = err
			m.done = nil
			close(done)
			m.mu.Unlock()
		}()
	}
	done := m.done
	if done == nil {
		sample, err := m.sample, m.err
		m.mu.Unlock()
		return sample, err
	}
	m.mu.Unlock()
	select {
	case <-ctx.Done():
		return nil, fault.Unavailable("宿主机采样超时，已有采样尚未完成")
	case <-done:
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.sample, m.err
}
func (s *Server) monitoringHandlers(mux *http.ServeMux, sampler *metricSampler) {
	mux.HandleFunc("POST /v1/monitoring/sample", func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 1024)
		defer r.Body.Close()
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		var in metricRequest
		if decoder.Decode(&in) != nil || decoder.Decode(new(any)) != io.EOF || in.Protocol != Protocol || in.Interval < 15 || in.Interval > 300 {
			metricReply(w, nil, fault.Invalid("宿主机采样请求无效"))
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		sample, err := sampler.read(ctx, in.Interval)
		metricReply(w, sample, err)
	})
}
func (c *Client) ReadHostMetrics(ctx context.Context, interval int64) (monitoring.Sample, error) {
	var result metricResult
	if err := c.request(ctx, "POST", "/v1/monitoring/sample", metricRequest{Protocol, interval}, &result); err != nil {
		return monitoring.Sample{}, err
	}
	if result.Protocol != Protocol || result.Code != "OK" || result.Data == nil {
		return monitoring.Sample{}, fault.Unavailable("宿主机采样协议无效")
	}
	return *result.Data, nil
}

type serviceOutput struct{ buffer bytes.Buffer }

func (w *serviceOutput) String() string { return w.buffer.String() }

func (w *serviceOutput) Write(p []byte) (int, error) {
	if w.buffer.Len()+len(p) > 16<<10 {
		return 0, errors.New("service output exceeds budget")
	}
	return w.buffer.Write(p)
}
func readMetricServices(ctx context.Context) []monitoring.ServiceState {
	units := []string{"nginxpanel.service", "nginxpanel-agent.service", "nginxpanel-nginx.service", "nginxpanel-fail2ban.service"}
	states := make([]monitoring.ServiceState, 0, len(units))
	for _, id := range units {
		states = append(states, monitoring.ServiceState{ID: id, Reason: "systemd 状态不可用"})
	}
	binary, err := trustedFile("/usr/bin/systemctl", true)
	if err != nil {
		return states
	}
	args := append([]string{"show", "--no-pager", "--property=Id,LoadState,ActiveState,SubState"}, units...)
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Env = []string{"PATH=/usr/bin:/usr/sbin", "LC_ALL=C", "SYSTEMD_PAGER=cat"}
	cmd.WaitDelay = time.Second
	var output serviceOutput
	cmd.Stdout = &output
	cmd.Stderr = io.Discard
	if err := cmd.Run(); err != nil {
		var exit *exec.ExitError
		if !errors.As(err, &exit) || ctx.Err() != nil {
			return states
		}
	}
	for _, block := range strings.Split(strings.TrimSpace(output.String()), "\n\n") {
		fields := map[string]string{}
		for _, line := range strings.Split(block, "\n") {
			key, value, ok := strings.Cut(line, "=")
			if ok && len(value) <= 128 {
				fields[key] = value
			}
		}
		for i := range states {
			if states[i].ID == fields["Id"] && fields["LoadState"] != "" && fields["ActiveState"] != "" {
				states[i].Load = fields["LoadState"]
				states[i].Active = fields["ActiveState"]
				states[i].Sub = fields["SubState"]
				states[i].Reason = ""
			}
		}
	}
	return states
}
