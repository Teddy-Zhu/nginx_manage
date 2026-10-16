package migration

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"nginxpanel/internal/firewall"
	"strconv"
	"strings"
	"time"
)

type pushPeerError struct {
	Status   int
	Code     string
	Identity bool
	Wait     int64
	Plan     *Plan
}

func (e *pushPeerError) Error() string { return "target migration request failed" }

// Only the fixed migration receiver, plan and execute paths are constructed by
// the worker. Redirects, destination resolution and TLS share the pull policy.
func pushRPC(ctx context.Context, remote Remote, node, method, path, key string, in, out any) error {
	client, base, err := remoteClient(remote)
	if err != nil {
		return &pushPeerError{Identity: true}
	}
	defer client.CloseIdleConnections()
	var body io.Reader
	if in != nil {
		raw, e := json.Marshal(in)
		if e != nil {
			return e
		}
		if len(raw) > MaxRequestBytes {
			return &pushPeerError{Identity: true}
		}
		body = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, base+path, body)
	if err != nil {
		return &pushPeerError{Identity: true}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+remote.APIKey)
	if key != "" {
		req.Header.Set("Idempotency-Key", key)
	}
	response, err := client.Do(req)
	if err != nil {
		return &pushPeerError{}
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, 262145))
	if err != nil || len(raw) > 262144 {
		return &pushPeerError{Identity: true}
	}
	var envelope struct {
		Code, Message string
		Data          json.RawMessage
		RequestID     string `json:"request_id"`
		NodeID        string `json:"node_id"`
	}
	if decodeStrict(raw, &envelope) != nil || envelope.Code == "" || envelope.RequestID == "" || (response.StatusCode == http.StatusOK) != (envelope.Code == "OK") || !validTransferID(envelope.NodeID) || node != "" && envelope.NodeID != node {
		return &pushPeerError{Identity: true}
	}
	if response.StatusCode != http.StatusOK || envelope.Code != "OK" {
		e := &pushPeerError{Status: response.StatusCode, Code: envelope.Code}
		if response.StatusCode == http.StatusTooManyRequests || response.StatusCode == http.StatusServiceUnavailable {
			e.Wait = 60
			if value := response.Header.Get("Retry-After"); value != "" {
				if n, err := strconv.ParseInt(value, 10, 64); err == nil && n > 0 {
					e.Wait = min(n, 86400)
				} else if at, err := http.ParseTime(value); err == nil && at.After(time.Now()) {
					e.Wait = min(int64(time.Until(at).Seconds())+1, 86400)
				}
			}
		}
		if envelope.Code == "MIGRATION_BLOCKED" {
			var plan Plan
			if decodeStrict(envelope.Data, &plan) == nil {
				e.Plan = &plan
			}
		}
		return e
	}
	if out == nil {
		return nil
	}
	if err = decodeStrict(envelope.Data, out); err != nil {
		return &pushPeerError{Identity: true}
	}
	var receiver *Receiver
	if value, ok := out.(*Receiver); ok {
		receiver = value
	}
	if receiver != nil && receiver.NodeID != envelope.NodeID {
		return &pushPeerError{Identity: true}
	}
	return nil
}
func sanitizePushPlan(plan Plan, remote Remote, passphrase string) (Plan, error) {
	if !validTransferID(plan.ID) || !validTransferID(plan.SourceNode) || plan.BaseVersion < 0 || len(plan.Steps) > 129 || len(plan.Omissions) > 64 || len(plan.SourceVersion) > 128 || len(plan.LastError) > 4096 {
		return Plan{}, errors.New("invalid migration plan")
	}
	if d := plan.Dependencies; d != nil {
		if !validTransferID(d.TaskID) || d.CheckTaskID != "" && !validTransferID(d.CheckTaskID) || d.PrepareTaskID != "" && !validTransferID(d.PrepareTaskID) || d.MaintenanceTaskID != "" && !validTransferID(d.MaintenanceTaskID) || d.InstallTaskID != "" && !validTransferID(d.InstallTaskID) || len(d.Error) > 1024 || len(d.State) > 32 || len(d.Stage) > 64 || d.Deadline <= 0 {
			return Plan{}, errors.New("invalid dependency result")
		}
	}
	redact := func(text string) string {
		for _, secret := range []string{remote.APIKey, passphrase} {
			if secret != "" {
				text = strings.ReplaceAll(text, secret, "[已隐藏]")
			}
		}
		return text
	}
	if f := plan.Firewall; f != nil {
		if err := validateFirewallPreview(f); err != nil {
			return Plan{}, err
		}
		copy := *f
		copy.Entries = append([]firewall.Rule{}, f.Entries...)
		copy.Interfaces = append([]FirewallInterface{}, f.Interfaces...)
		copy.Warnings = append([]string{}, f.Warnings...)
		for i := range copy.Entries {
			copy.Entries[i].Name = redact(copy.Entries[i].Name)
			copy.Entries[i].Comment = redact(copy.Entries[i].Comment)
			copy.Entries[i].Interface = redact(copy.Entries[i].Interface)
		}
		for i := range copy.Interfaces {
			copy.Interfaces[i].Source = redact(copy.Interfaces[i].Source)
			copy.Interfaces[i].Target = redact(copy.Interfaces[i].Target)
		}
		for i := range copy.Warnings {
			copy.Warnings[i] = redact(copy.Warnings[i])
		}
		plan.Firewall = &copy
	}
	if d := plan.Dependencies; d != nil {
		copy := *d
		copy.Error, copy.Stage, copy.State = redact(d.Error), redact(d.Stage), redact(d.State)
		plan.Dependencies = &copy
	}
	for i := range plan.Steps {
		step := &plan.Steps[i]
		if len(step.Kind) > 64 || len(step.Resource) > 4096 || len(step.State) > 64 || len(step.Message) > 4096 {
			return Plan{}, errors.New("invalid migration step")
		}
		step.Kind, step.Resource, step.State, step.Message = redact(step.Kind), redact(step.Resource), redact(step.State), redact(step.Message)
	}
	for i := range plan.Omissions {
		if len(plan.Omissions[i]) > 4096 {
			return Plan{}, errors.New("invalid migration omission")
		}
		plan.Omissions[i] = redact(plan.Omissions[i])
	}
	plan.SourceVersion, plan.LastError = redact(plan.SourceVersion), redact(plan.LastError)
	raw, err := json.Marshal(plan)
	if err != nil || len(raw) > 262144 {
		return Plan{}, errors.New("migration plan exceeds canonical budget")
	}
	return plan, nil
}
