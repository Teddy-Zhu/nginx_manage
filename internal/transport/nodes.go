package transport

import (
	"net/http"

	"nginxpanel/internal/agent"
	"nginxpanel/internal/auth"
	"nginxpanel/internal/fault"
	"nginxpanel/internal/nginxconfig"
	"nginxpanel/internal/nodes"
	"nginxpanel/internal/remoteapi"
	"nginxpanel/internal/transport/apigen"
	"nginxpanel/migrations"
)

func (s *Server) nodePrincipal(w http.ResponseWriter, r *http.Request, recent bool) (auth.Principal, bool) {
	if r.Header.Get(nodes.RemoteHopHeader) != "" {
		s.fail(w, r, fault.New(http.StatusForbidden, "REMOTE_FORWARDING_REJECTED", "不允许递归转发节点管理请求"))
		return auth.Principal{}, false
	}
	return s.authorize(w, r, recent, "nodes.manage", "read")
}

func (s *Server) ListNodes(w http.ResponseWriter, r *http.Request) {
	p, ok := s.nodePrincipal(w, r, false)
	if !ok {
		return
	}
	result, err := s.Nodes.List(r.Context(), p)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, result)
}

func (s *Server) GetNode(w http.ResponseWriter, r *http.Request, id apigen.ID) {
	p, ok := s.nodePrincipal(w, r, false)
	if !ok {
		return
	}
	result, err := s.Nodes.Get(r.Context(), p, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, result)
}

func (s *Server) CreateNode(w http.ResponseWriter, r *http.Request, params apigen.CreateNodeParams) {
	p, ok := s.nodePrincipal(w, r, true)
	if !ok {
		return
	}
	var in nodes.CreateInput
	if err := decode(w, r, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	result, err := s.Nodes.Create(r.Context(), p, r.Context().Value(requestIDKey).(string), params.IdempotencyKey, in)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.respond(w, r, http.StatusCreated, "OK", "节点连接已登记", result)
}

func (s *Server) RefreshNode(w http.ResponseWriter, r *http.Request, id apigen.ID, _ apigen.RefreshNodeParams) {
	p, ok := s.nodePrincipal(w, r, false)
	if !ok {
		return
	}
	result, err := s.Nodes.Refresh(r.Context(), p, r.Context().Value(requestIDKey).(string), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, result)
}

func (s *Server) DeleteNode(w http.ResponseWriter, r *http.Request, id apigen.ID, params apigen.DeleteNodeParams) {
	p, ok := s.nodePrincipal(w, r, true)
	if !ok {
		return
	}
	result, err := s.Nodes.Delete(r.Context(), p, r.Context().Value(requestIDKey).(string), params.IdempotencyKey, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, result)
}

// These two endpoints identify and revoke only the presented machine Token.
// They do not require auth.manage and cannot enumerate other credentials.
func (s *Server) GetRemoteIdentity(w http.ResponseWriter, r *http.Request) {
	p, ok := s.authorize(w, r, false, "read")
	if !ok {
		return
	}
	if !p.Machine {
		s.fail(w, r, auth.ErrForbidden)
		return
	}
	schema, err := migrations.LatestVersion()
	if err != nil {
		s.fail(w, r, err)
		return
	}
	expires, err := s.Auth.CredentialExpiry(r.Context(), p)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, nodes.Identity{NodeID: s.NodeID, CredentialID: p.ID, Scopes: p.GrantScopes, ExpiresAt: expires, APIVersion: 1, DatabaseSchema: schema, AgentProtocol: agent.Protocol, ParserVersion: nginxconfig.ParserVersion, PolicyVersion: s.Config.Policy.Version, RemoteProtocol: remoteapi.Protocol})
}

func (s *Server) RevokeRemoteAuthorization(w http.ResponseWriter, r *http.Request, params apigen.RevokeRemoteAuthorizationParams) {
	if params.XNginxpanelTargetNode != s.NodeID {
		s.fail(w, r, fault.New(http.StatusConflict, "NODE_IDENTITY_CHANGED", "目标永久节点身份不匹配"))
		return
	}
	p, ok := s.authorize(w, r, false)
	if !ok {
		return
	}
	if !p.Machine {
		s.fail(w, r, auth.ErrForbidden)
		return
	}
	if err := s.Auth.RevokeOwnCredential(r.Context(), p, r.Context().Value(requestIDKey).(string)); err != nil {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, map[string]any{"credential_id": p.ID, "revoked": true})
}
