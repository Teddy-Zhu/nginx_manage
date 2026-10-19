package transport

import (
	"net/http"
	"nginxpanel/internal/components"
	"nginxpanel/internal/transport/apigen"
)

func (s *Server) ListComponentOfflineUploads(w http.ResponseWriter, r *http.Request) {
	p, ok := s.authorize(w, r, false, "read", "components.manage")
	if !ok || !s.componentsReady(w, r) {
		return
	}
	out, err := s.Components.OfflineUploads(r.Context(), p)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, out)
}
func (s *Server) CreateComponentOfflineUpload(w http.ResponseWriter, r *http.Request, params apigen.CreateComponentOfflineUploadParams) {
	p, ok := s.authorize(w, r, true, "components.manage")
	if !ok || !s.componentsReady(w, r) {
		return
	}
	var in components.OfflineInput
	if err := decodeLimit(w, r, &in, components.OfflineRequestBytes); err != nil {
		s.fail(w, r, err)
		return
	}
	out, err := s.Components.StartOffline(r.Context(), p, r.Context().Value(requestIDKey).(string), params.IdempotencyKey, in)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, out)
}
func (s *Server) WriteComponentOfflineChunk(w http.ResponseWriter, r *http.Request, id, asset string, params apigen.WriteComponentOfflineChunkParams) {
	p, ok := s.authorize(w, r, true, "components.manage")
	if !ok || !s.componentsReady(w, r) {
		return
	}
	var in components.OfflineChunk
	if err := decodeLimit(w, r, &in, 512<<10); err != nil {
		s.fail(w, r, err)
		return
	}
	out, err := s.Components.UploadOfflineChunk(r.Context(), p, id, asset, in)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, out)
}
func (s *Server) DiscardComponentOfflineUpload(w http.ResponseWriter, r *http.Request, id string, params apigen.DiscardComponentOfflineUploadParams) {
	p, ok := s.authorize(w, r, true, "components.manage")
	if !ok || !s.componentsReady(w, r) {
		return
	}
	out, err := s.Components.ClearOffline(r.Context(), p, r.Context().Value(requestIDKey).(string), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, out)
}
