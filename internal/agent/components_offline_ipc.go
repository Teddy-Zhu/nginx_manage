package agent

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"

	"nginxpanel/internal/components"
	"nginxpanel/internal/fault"
)

func decodeComponentOffline(w http.ResponseWriter, r *http.Request, out any, limit int64) bool {
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	defer r.Body.Close()
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if d.Decode(out) != nil || d.Decode(new(any)) != io.EOF {
		componentReply(w, nil, fault.Invalid("离线组件请求格式或长度无效"))
		return false
	}
	return true
}
func (s *Server) componentOfflineHandlers(mux *http.ServeMux, m *components.Manager) {
	mux.HandleFunc("GET /v1/components/offline", func(w http.ResponseWriter, r *http.Request) { out, err := m.ListOffline(); componentReply(w, out, err) })
	mux.HandleFunc("POST /v1/components/offline", func(w http.ResponseWriter, r *http.Request) {
		var in components.OfflineRequest
		if !decodeComponentOffline(w, r, &in, components.OfflineRequestBytes) {
			return
		}
		out, err := m.CreateOffline(r.Context(), in)
		componentReply(w, out, err)
	})
	mux.HandleFunc("PUT /v1/components/offline/{id}/assets/{asset}", func(w http.ResponseWriter, r *http.Request) {
		var in components.OfflineChunk
		if !decodeComponentOffline(w, r, &in, 512<<10) {
			return
		}
		out, err := m.UploadChunk(r.Context(), r.PathValue("id"), r.PathValue("asset"), in)
		componentReply(w, out, err)
	})
	mux.HandleFunc("DELETE /v1/components/offline/{id}", func(w http.ResponseWriter, r *http.Request) {
		out, err := m.DiscardOffline(r.Context(), r.PathValue("id"))
		componentReply(w, out, err)
	})
}
func (c *Client) CreateOfflineUpload(ctx context.Context, in components.OfflineRequest) (components.OfflineUpload, error) {
	var out components.OfflineUpload
	if !in.Valid() {
		return out, fault.Invalid("离线上传请求无效")
	}
	err := c.envelopeRequest(ctx, http.MethodPost, "/v1/components/offline", in, &out)
	if err == nil && (!out.Valid() || out.ID != in.ID || out.RequestHash != in.Hash()) {
		err = errors.New("离线上传回执与请求不一致")
	}
	return out, err
}
func (c *Client) ListOfflineUploads(ctx context.Context) ([]components.OfflineUpload, error) {
	var out []components.OfflineUpload
	err := c.envelopeRequest(ctx, http.MethodGet, "/v1/components/offline", nil, &out)
	if err == nil {
		if out == nil || len(out) > 32 {
			return nil, errors.New("离线上传列表不完整或超限")
		}
		seen := map[string]bool{}
		for _, u := range out {
			if !u.Valid() || seen[u.ID] {
				return nil, errors.New("离线上传列表材料无效")
			}
			seen[u.ID] = true
		}
	}
	return out, err
}
func (c *Client) WriteOfflineChunk(ctx context.Context, id, asset string, in components.OfflineChunk) (components.OfflineUpload, error) {
	var out components.OfflineUpload
	if !components.ValidID(id) || in.Validate() != nil {
		return out, fault.Invalid("离线上传分块无效")
	}
	err := c.envelopeRequest(ctx, http.MethodPut, "/v1/components/offline/"+id+"/assets/"+url.PathEscape(asset), in, &out)
	if err == nil && (!out.Valid() || out.ID != id) {
		err = errors.New("离线上传分块回执不一致")
	}
	return out, err
}
func (c *Client) DiscardOfflineUpload(ctx context.Context, id string) (components.OfflineUpload, error) {
	var out components.OfflineUpload
	if !components.ValidID(id) {
		return out, fault.Invalid("离线上传 UUID 无效")
	}
	err := c.envelopeRequest(ctx, http.MethodDelete, "/v1/components/offline/"+id, nil, &out)
	if err == nil && (!out.Valid() || out.ID != id || !out.Discarded) {
		err = errors.New("离线上传清除回执不一致")
	}
	return out, err
}
