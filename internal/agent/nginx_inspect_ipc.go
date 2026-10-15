package agent

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"nginxpanel/internal/limits"
)

func (s *Server) inspect(w http.ResponseWriter, r *http.Request) {
	if s.Nginx == nil {
		http.Error(w, "Nginx execution unavailable", 503)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, limits.RequestBytes)
	defer r.Body.Close()
	var in InspectRequest
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if d.Decode(&in) != nil || d.Decode(new(any)) != io.EOF {
		http.Error(w, "invalid inspection request", 400)
		return
	}
	out, err := s.Nginx.Inspect(in)
	if err != nil {
		status := 409
		if errors.Is(err, ErrRuntimeUnavailable) {
			status = 503
		}
		http.Error(w, "unable to inspect the recorded publication", status)
		return
	}
	writeJSON(w, out)
}
func (c *Client) Inspect(ctx context.Context, in InspectRequest) (ExternalSnapshot, error) {
	var out ExternalSnapshot
	err := c.request(ctx, "POST", "/v1/nginx/inspect", in, &out)
	return out, err
}
