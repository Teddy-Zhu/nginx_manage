package agent

import (
	"context"
	"net/http"
	"net/url"
	"strconv"

	"nginxpanel/internal/components"
	"nginxpanel/internal/componentversions"
	"nginxpanel/internal/fault"
)

func (s *Server) componentVersionHandlers(mux *http.ServeMux, manager *components.Manager) {
	mux.HandleFunc("GET /v1/components/versions", func(w http.ResponseWriter, r *http.Request) {
		if s.Dev || s.ComponentScope != "host" {
			componentReply(w, nil, fault.Unavailable("组件版本服务不可用"))
			return
		}
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		q := componentversions.Query{SourceID: r.URL.Query().Get("source_id"), AppID: r.URL.Query().Get("app_id"), Channel: r.URL.Query().Get("channel"), Page: page, Refresh: r.URL.Query().Get("refresh") == "true"}
		out, err := manager.Versions(r.Context(), q)
		componentReply(w, out, err)
	})
}

func (c *Client) ComponentVersions(ctx context.Context, q componentversions.Query) (componentversions.Catalog, error) {
	var out componentversions.Catalog
	if err := q.Validate(); err != nil {
		return out, fault.Invalid(err.Error())
	}
	values := url.Values{"source_id": {q.SourceID}, "app_id": {q.AppID}, "channel": {q.Channel}, "page": {strconv.Itoa(q.Page)}, "refresh": {strconv.FormatBool(q.Refresh)}}
	err := c.envelopeRequest(ctx, http.MethodGet, "/v1/components/versions?"+values.Encode(), nil, &out)
	return out, err
}
