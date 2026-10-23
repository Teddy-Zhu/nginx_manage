package transport

import (
	"errors"
	"net/http"

	"nginxpanel/internal/agent"
	"nginxpanel/internal/fault"
	"nginxpanel/internal/nginxconfig"
	"nginxpanel/internal/secure"
	"nginxpanel/internal/storage/dbgen"
	"nginxpanel/internal/transport/apigen"
)

func (s *Server) DiffConfigTree(w http.ResponseWriter, r *http.Request, _ apigen.DiffConfigTreeParams) {
	if _, ok := s.authorize(w, r, "config.secrets"); !ok {
		return
	}
	var in nginxconfig.DiffRequest
	if err := decode(w, r, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	out, err := s.Config.Diff(r.Context(), in)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, out)
}

func (s *Server) externalSnapshot(r *http.Request, filePath string) (agent.ExternalSnapshot, nginxconfig.Tree, error) {
	head, err := dbgen.New(s.DB).GetConfigHead(r.Context())
	if err != nil {
		return agent.ExternalSnapshot{}, nginxconfig.Tree{}, err
	}
	tree := nginxconfig.Tree{Files: nginxconfig.InitialFiles()}
	if head.AppliedRevision.Valid {
		tree, err = s.Config.Get(r.Context(), head.AppliedRevision.String)
		if err != nil {
			return agent.ExternalSnapshot{}, tree, err
		}
	}
	out, err := s.Agent.Inspect(r.Context(), agent.InspectRequest{Protocol: agent.Protocol, RevisionID: tree.RevisionID, Files: tree.Files, Path: filePath})
	if err != nil {
		var status *agent.HTTPError
		if errors.As(err, &status) && status.Status == 409 {
			err = fault.Conflict("当前发布副本、修订身份或生成清单无法安全核对；请先处理未确认任务或在本机检查受管目录")
		} else if errors.Is(err, agent.ErrRequestTooLarge) {
			err = fault.Invalid("当前修订超过 Agent 序列化请求预算")
		} else {
			err = fault.Unavailable("无法读取本机受管发布快照")
		}
	}
	return out, tree, err
}
func (s *Server) InspectNginxExternal(w http.ResponseWriter, r *http.Request, params apigen.InspectNginxExternalParams) {
	if _, ok := s.authorize(w, r, "config.secrets"); !ok {
		return
	}
	filePath := ""
	if params.Path != nil {
		filePath = *params.Path
	}
	out, _, err := s.externalSnapshot(r, filePath)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, out)
}
func (s *Server) CaptureNginxExternal(w http.ResponseWriter, r *http.Request, params apigen.CaptureNginxExternalParams) {
	p, ok := s.authorize(w, r, "config.write", "config.secrets")
	if !ok {
		return
	}
	var in nginxconfig.CaptureRequest
	if err := decode(w, r, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	out, err := s.Config.CaptureExternal(r.Context(), p, r.Context().Value(requestIDKey).(string), params.IdempotencyKey, in, func() (nginxconfig.CapturedFile, error) {
		snapshot, base, err := s.externalSnapshot(r, in.Path)
		if err != nil {
			return nginxconfig.CapturedFile{}, err
		}
		if snapshot.Snapshot != in.Snapshot {
			return nginxconfig.CapturedFile{}, fault.Conflict("磁盘快照已变化，请重新查看差异")
		}
		if !snapshot.Complete || snapshot.Detail == nil || !snapshot.Detail.CaptureAllowed {
			return nginxconfig.CapturedFile{}, fault.Conflict("此文件无法安全捕获为草稿，请在本机处理文件类型、权限或预算问题")
		}
		capture := nginxconfig.CapturedFile{File: nginxconfig.File{ID: secure.ID(), Path: in.Path, Content: snapshot.Detail.DraftContent}}
		for _, file := range base.Files {
			if file.Path == in.Path {
				capture.Base = file
				capture.File.ID = file.ID
				break
			}
		}
		for _, file := range snapshot.Files {
			if file.Path == in.Path {
				capture.Removed = file.Status == "missing"
				break
			}
		}
		return capture, nil
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.respond(w, r, 201, "OK", "外部内容已保存为独立草稿", out)
}

func (s *Server) RestoreNginxExternal(w http.ResponseWriter, r *http.Request, params apigen.RestoreNginxExternalParams) {
	p, ok := s.authorize(w, r, "config.write", "config.secrets", "security.write")
	if !ok {
		return
	}
	var in nginxconfig.RestoreRequest
	if err := decode(w, r, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	out, err := s.Config.RestoreManaged(r.Context(), p, r.Context().Value(requestIDKey).(string), params.IdempotencyKey, in, func() (string, error) {
		snapshot, _, err := s.externalSnapshot(r, "")
		if err != nil {
			return "", err
		}
		if !snapshot.Complete || snapshot.Integrity || snapshot.Snapshot != in.Snapshot {
			return "", fault.Conflict("外部冲突快照已变化或无法完整核对，请重新检查")
		}
		return snapshot.RevisionID, nil
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.respond(w, r, 202, "OK", "受管恢复已加入任务队列", out)
}
