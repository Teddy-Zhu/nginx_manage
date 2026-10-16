package agent

import (
	"context"
	"encoding/json"
	"io"
	"net/http"

	"nginxpanel/internal/fault"
)

func (s *Server) disasterNginx(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 8192)
	defer r.Body.Close()
	var in DisasterRuntimeRequest
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if decoder.Decode(&in) != nil || decoder.Decode(new(any)) != io.EOF {
		componentReply(w, nil, fault.Invalid("恢复运行请求格式无效"))
		return
	}
	out, err := s.advanceDisasterRuntime(r.Context(), in)
	if err != nil {
		err = fault.Conflict("恢复运行推进未完成：" + err.Error())
	}
	componentReply(w, out, err)
}

func (c *Client) AdvanceDisasterRuntime(ctx context.Context, in DisasterRuntimeRequest) (DisasterRuntimeStatus, error) {
	var out DisasterRuntimeStatus
	err := c.envelopeRequest(ctx, http.MethodPost, "/v1/nginx/disaster", in, &out)
	return out, err
}
