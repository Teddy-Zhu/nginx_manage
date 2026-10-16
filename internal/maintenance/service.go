package maintenance

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"time"

	"nginxpanel/internal/auth"
	"nginxpanel/internal/fault"
	"nginxpanel/internal/protocol"
	"nginxpanel/internal/secure"
)

const columns = "task_id,phase,deadline,root_requested,root_epoch,last_error,created_at,updated_at,COALESCE(owner_task_id,'')"

func readSession(row interface{ Scan(...any) error }) (*Session, error) {
	var s Session
	err := row.Scan(&s.TaskID, &s.Phase, &s.Deadline, &s.RootRequested, &s.RootEpoch, &s.Error, &s.CreatedAt, &s.UpdatedAt, &s.OwnerTaskID)
	return &s, err
}
func (s *Service) publish(session *Session, phase, reason string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.session = session
	s.phase = phase
	s.reason = reason
}
func (s *Service) rootStatus(ctx context.Context) (RootStatus, error) {
	if s.Agent == nil {
		return RootStatus{}, errors.New("未连接本机 Agent")
	}
	call, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	return s.Agent.MaintenanceStatus(call)
}

// Init closes admission until the independent Agent journal has been reconciled.
func (s *Service) Init(ctx context.Context) error {
	s.publish(nil, "unavailable", "正在核对独立维护记录")
	return s.step(ctx)
}
func (s *Service) Start(ctx context.Context, p auth.Principal, requestID, key string, in StartInput) (Session, error) {
	return s.start(ctx, p, requestID, key, in, "", nil)
}

// StartLinked drains everything except the authorized coordinator itself. The
// child and its parent link commit together, before either worker can proceed.
func (s *Service) StartLinked(ctx context.Context, p auth.Principal, requestID, key string, in StartInput, ownerTaskID string, link func(*sql.Tx, Session) error) (Session, error) {
	if !validID(ownerTaskID) || link == nil {
		return Session{}, fault.Invalid("维护父任务关联无效")
	}
	return s.start(ctx, p, requestID, key, in, ownerTaskID, link)
}

func (s *Service) start(ctx context.Context, p auth.Principal, requestID, key string, in StartInput, ownerTaskID string, link func(*sql.Tx, Session) error) (Session, error) {
	var out Session
	if err := p.Require("system.write"); err != nil {
		return out, err
	}
	if in.DrainSeconds < 30 || in.DrainSeconds > 300 {
		return out, fault.Invalid("等待时限须为 30 至 300 秒")
	}
	if key == "" || len(key) > 128 || strings.ContainsAny(key, "\x00\r\n") {
		return out, fault.Invalid("幂等键无效")
	}
	raw, err := json.Marshal(struct {
		Action      string
		Input       StartInput
		OwnerTaskID string
	}{"maintenance.enter", in, ownerTaskID})
	if err != nil {
		return out, err
	}
	hash := secure.Hash(raw)
	s.control.Lock()
	defer s.control.Unlock()
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return out, err
	}
	defer tx.Rollback()
	var prior string
	var sealed []byte
	err = tx.QueryRowContext(ctx, "SELECT request_hash,response FROM idempotency_keys WHERE principal=? AND key=?", p.ID, key).Scan(&prior, &sealed)
	if err == nil {
		if prior != hash {
			return out, fault.Conflict("同一幂等键不能用于不同请求")
		}
		plain, e := s.Vault.Open(sealed, "idempotency:"+p.ID+":"+key)
		if e != nil {
			return out, e
		}
		if e = json.Unmarshal(plain, &out); e != nil {
			return out, e
		}
		if link != nil {
			if e = link(tx, out); e != nil {
				return out, e
			}
			return out, tx.Commit()
		}
		return out, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return out, err
	}
	s.mu.Lock()
	allowed := s.phase == "open" && s.root.Available && s.root.ID == ""
	if allowed {
		s.phase = "draining"
	}
	s.mu.Unlock()
	if !allowed {
		return out, fault.Conflict("维护未就绪，或已有维护及待恢复记录")
	}
	committed := false
	commitAttempted := false
	defer func() {
		if !committed {
			if commitAttempted {
				s.publish(nil, "unavailable", "维护提交结果待核对")
			} else {
				s.publish(nil, "open", "")
			}
		}
	}()
	var count int
	if err = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM maintenance_sessions").Scan(&count); err != nil {
		return out, err
	}
	if count >= 64 {
		return out, fault.Conflict("维护记录达到 64 项保留上限，须本机维护")
	}
	now := time.Now().Unix()
	out = Session{TaskID: secure.ID(), OwnerTaskID: ownerTaskID, Phase: "draining", Deadline: now + in.DrainSeconds, CreatedAt: now, UpdatedAt: now}
	if err = s.insert(ctx, tx, p, out); err != nil {
		return out, err
	}
	if link != nil {
		if err = link(tx, out); err != nil {
			return out, err
		}
	}
	response, err := json.Marshal(out)
	if err != nil {
		return out, err
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO idempotency_keys(principal,key,request_hash,response,created_at) VALUES(?,?,?,?,?)", p.ID, key, hash, s.Vault.Seal(response, "idempotency:"+p.ID+":"+key), now); err != nil {
		return out, err
	}
	if err = audit(ctx, tx, p, requestID, out.TaskID, "maintenance.enter", "queued"); err != nil {
		return out, err
	}
	commitAttempted = true
	if err = tx.Commit(); err != nil {
		return out, err
	}
	committed = true
	s.publish(&out, "draining", "")
	return out, nil
}
func (s *Service) insert(ctx context.Context, tx *sql.Tx, p auth.Principal, in Session) error {
	if _, err := tx.ExecContext(ctx, "INSERT INTO tasks(id,kind,resource_id,state,stage,operation_id,created_at,updated_at) VALUES(?,'maintenance.enter','host','running',?,?,?,?)", in.TaskID, in.Phase, in.TaskID, in.CreatedAt, in.UpdatedAt); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, "INSERT INTO maintenance_sessions(task_id,principal,phase,deadline,root_requested,root_epoch,last_error,created_at,updated_at,owner_task_id) VALUES(?,?,?,?,?,?,?,?,?,NULLIF(?,''))", in.TaskID, p.ID, in.Phase, in.Deadline, in.RootRequested, in.RootEpoch, in.Error, in.CreatedAt, in.UpdatedAt, in.OwnerTaskID)
	return err
}
func audit(ctx context.Context, tx *sql.Tx, p auth.Principal, requestID, id, action, outcome string) error {
	_, err := tx.ExecContext(ctx, "INSERT INTO audit_logs(id,request_id,principal,action,resource_id,outcome,created_at) VALUES(?,?,?,?,?,?,?)", secure.ID(), requestID, p.ID, action, id, outcome, time.Now().Unix())
	return err
}

// Release is also the explicit recovery path for an orphan root lock after a DB
// rollback. Only an administrator may release a lock absent from this database.
func (s *Service) Release(ctx context.Context, p auth.Principal, requestID, id string) (Session, error) {
	var out Session
	if err := p.Require("system.write"); err != nil {
		return out, err
	}
	if !validID(id) {
		return out, fault.Invalid("维护标识无效")
	}
	s.control.Lock()
	defer s.control.Unlock()
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return out, err
	}
	defer tx.Rollback()
	var installations int
	var backups int
	if err = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM backup_records b JOIN tasks t ON t.id=b.task_id WHERE b.maintenance_id=? AND t.state NOT IN('succeeded','failed','cancelled','rolled_back') AND t.stage IN('queued','draining','capturing')", id).Scan(&backups); err != nil {
		return out, err
	}
	if backups != 0 {
		return out, fault.Conflict("原备份仍在捕获一致性快照，不能释放维护锁")
	}
	if err = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM nginx_installations i JOIN tasks t ON t.id=i.task_id WHERE i.maintenance_id=? AND t.state NOT IN ('succeeded','failed','cancelled')", id).Scan(&installations); err != nil {
		return out, err
	}
	if installations != 0 {
		return out, fault.Conflict("原 Nginx 安装任务仍在执行或待恢复，不能释放维护锁")
	}
	var updates int
	if err = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM panel_updates i JOIN tasks t ON t.id=i.task_id WHERE i.maintenance_id=? AND t.state NOT IN ('succeeded','failed','rolled_back','cancelled')", id).Scan(&updates); err != nil {
		return out, err
	}
	if updates != 0 {
		return out, fault.Conflict("原面板更新仍在执行或待恢复，不能手工释放维护锁")
	}
	session, err := readSession(tx.QueryRowContext(ctx, "SELECT "+columns+" FROM maintenance_sessions WHERE task_id=?", id))
	if errors.Is(err, sql.ErrNoRows) {
		if err = p.Require("auth.manage"); err != nil {
			return out, err
		}
		s.mu.Lock()
		root := s.root
		active := s.session
		s.mu.Unlock()
		if active != nil || root.ID != id {
			return out, fault.Conflict("独立维护标识不匹配，或有其他维护待恢复")
		}
		now := time.Now().Unix()
		session = &Session{TaskID: id, Phase: "releasing", Deadline: now, RootRequested: true, RootEpoch: root.Epoch, CreatedAt: now, UpdatedAt: now}
		if err = s.insert(ctx, tx, p, *session); err != nil {
			return out, err
		}
	} else if err != nil {
		return out, err
	} else {
		var owner string
		if err = tx.QueryRowContext(ctx, "SELECT principal FROM maintenance_sessions WHERE task_id=?", id).Scan(&owner); err != nil {
			return out, err
		}
		if owner != p.ID {
			if err = p.Require("auth.manage"); err != nil {
				return out, err
			}
		}
		if session.Phase == "released" || session.Phase == "failed" {
			return *session, nil
		}
		session.Phase = "releasing"
		session.UpdatedAt = time.Now().Unix()
		if _, err = tx.ExecContext(ctx, "UPDATE maintenance_sessions SET phase='releasing',updated_at=? WHERE task_id=?", session.UpdatedAt, id); err != nil {
			return out, err
		}
		if _, err = tx.ExecContext(ctx, "UPDATE tasks SET state='running',stage='releasing',updated_at=? WHERE id=?", session.UpdatedAt, id); err != nil {
			return out, err
		}
	}
	if err = audit(ctx, tx, p, requestID, id, "maintenance.release", "queued"); err != nil {
		return out, err
	}
	if err = tx.Commit(); err != nil {
		return out, err
	}
	s.publish(session, "releasing", session.Error)
	return *session, nil
}
func validID(id string) bool {
	if len(id) != 36 {
		return false
	}
	for i, c := range id {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return false
			}
		} else if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
func (s *Service) save(ctx context.Context, in *Session) error {
	state := "running"
	switch in.Phase {
	case "held":
		state = "waiting_confirmation"
	case "released":
		state = "succeeded"
	case "failed":
		state = "failed"
	case "recovery_required":
		state = "recovery_required"
	}
	s.mu.Lock()
	prior := s.session
	unchanged := prior != nil && prior.TaskID == in.TaskID && prior.Phase == in.Phase && prior.RootRequested == in.RootRequested && prior.RootEpoch == in.RootEpoch && prior.Error == in.Error
	s.mu.Unlock()
	if unchanged {
		copy := *in
		s.publish(&copy, in.Phase, in.Error)
		return nil
	}
	in.UpdatedAt = time.Now().Unix()
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, "UPDATE maintenance_sessions SET phase=?,root_requested=?,root_epoch=?,last_error=?,updated_at=? WHERE task_id=?", in.Phase, in.RootRequested, in.RootEpoch, in.Error, in.UpdatedAt, in.TaskID); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "UPDATE tasks SET state=?,stage=?,last_error=?,agent_accepted=?,updated_at=? WHERE id=?", state, in.Phase, in.Error, in.RootEpoch != "", in.UpdatedAt, in.TaskID); err != nil {
		return err
	}
	if err = audit(ctx, tx, auth.Principal{ID: "system:maintenance"}, in.TaskID, in.TaskID, "maintenance."+in.Phase, state); err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	phase := in.Phase
	if phase == "released" || phase == "failed" {
		s.publish(nil, "open", "")
	} else {
		copy := *in
		s.publish(&copy, phase, in.Error)
	}
	return nil
}
func (s *Service) busy(ctx context.Context, id string) (bool, error) {
	var n int
	err := s.DB.QueryRowContext(ctx, `SELECT
 (SELECT COUNT(*) FROM tasks WHERE id!=? AND id!=COALESCE((SELECT owner_task_id FROM maintenance_sessions WHERE task_id=?),'') AND state NOT IN ('succeeded','failed','rolled_back','cancelled'))+
 (SELECT COUNT(*) FROM migration_plans WHERE state IN ('applying','recovery_required'))`, id, id).Scan(&n)
	return n != 0, err
}
func (s *Service) step(ctx context.Context) error {
	s.control.Lock()
	defer s.control.Unlock()
	stored, err := readSession(s.DB.QueryRowContext(ctx, "SELECT "+columns+" FROM maintenance_sessions WHERE phase NOT IN ('released','failed')"))
	if errors.Is(err, sql.ErrNoRows) {
		stored = nil
	} else if err != nil {
		s.mu.Lock()
		s.phase, s.reason = "unavailable", "无法核对持久维护记录"
		s.mu.Unlock()
		return err
	}
	s.mu.Lock()
	s.session = stored
	if stored != nil && s.phase == "open" {
		s.phase = "unavailable"
	}
	s.mu.Unlock()
	root, err := s.rootStatus(ctx)
	if err != nil {
		s.mu.Lock()
		s.reason = "无法核对 Agent 维护状态"
		if s.session == nil {
			s.phase = "unavailable"
		} else if s.phase == "held" {
			s.phase = "root_acquiring"
		}
		s.mu.Unlock()
		return nil
	}
	if root.Busy < 0 || !validID(root.Epoch) || (root.ID != "" && !validID(root.ID)) || !validRoot(root) {
		s.mu.Lock()
		s.phase = "recovery_required"
		s.reason = "Agent 维护状态无效"
		s.mu.Unlock()
		return nil
	}
	s.mu.Lock()
	s.root = root
	var session *Session
	if s.session != nil {
		copy := *s.session
		session = &copy
	}
	s.mu.Unlock()
	if session == nil {
		if root.ID != "" || root.Phase == "recovery_required" {
			s.publish(nil, "recovery_required", "发现独立维护记录，须管理员核对后恢复写入")
		} else {
			s.publish(nil, "open", "")
		}
		return nil
	}
	if root.ID != "" && root.ID != session.TaskID {
		session.Phase, session.Error = "recovery_required", "Agent 维护标识与数据库不一致，须本机恢复"
		return s.save(ctx, session)
	}
	if session.Phase != "held" && session.Phase != "releasing" && session.Phase != "recovery_required" && time.Now().Unix() >= session.Deadline {
		if session.RootEpoch != "" {
			session.Phase, session.Error = "recovery_required", "独立维护锁重启后无法重新确认，写入保持关闭"
			return s.save(ctx, session)
		}
		session.Error = "等待在途操作结束超时，未进入独占维护"
		if session.RootRequested {
			session.Phase = "releasing"
		} else {
			session.Phase = "failed"
		}
		if err = s.save(ctx, session); err != nil {
			return err
		}
		if session.Phase == "failed" {
			return nil
		}
	}
	if session.Phase == "releasing" {
		if session.RootRequested {
			call, cancel := context.WithTimeout(ctx, 3*time.Second)
			ack, e := s.Agent.ReleaseMaintenance(call, RootRequest{Protocol: protocol.Agent, OperationID: session.TaskID})
			cancel()
			if e != nil {
				s.publish(session, "releasing", "等待 Agent 确认释放，写入保持关闭")
				return nil
			}
			if ack.ID != session.TaskID || ack.Phase != "released" || !validID(ack.Epoch) {
				s.publish(session, "releasing", "Agent 释放确认无效")
				return nil
			}
		}
		session.Phase = "released"
		if session.Error != "" {
			session.Phase = "failed"
		}
		return s.save(ctx, session)
	}
	if session.Phase == "recovery_required" {
		s.publish(session, "recovery_required", session.Error)
		return nil
	}
	if session.Phase == "held" {
		if root.ID == session.TaskID && root.Phase == "held" && root.Epoch == session.RootEpoch && root.Busy == 0 {
			if root.Completion != nil {
				session.Phase = "releasing"
				if root.Completion.Outcome != "succeeded" {
					session.Error = "独立维护操作未成功，已由原事务完成补偿或无副作用中止"
				}
				return s.save(ctx, session)
			}
			s.publish(session, "held", "")
			return nil
		}
		if root.ID != session.TaskID {
			session.Phase, session.Error = "recovery_required", "Agent 维护记录缺失，须显式恢复写入"
			return s.save(ctx, session)
		}
		session.Phase = "root_acquiring"
		if err = s.save(ctx, session); err != nil {
			return err
		}
	}
	if session.Phase == "draining" {
		// Stop progress atomically with observing zero shared holders. If queued work
		// remains, reopen only progress so accepted parent/child operations can drain.
		s.mu.Lock()
		if s.active != 0 {
			s.mu.Unlock()
			return nil
		}
		s.phase = "root_acquiring"
		s.mu.Unlock()
		busy, e := s.busy(ctx, session.TaskID)
		if e != nil {
			s.publish(session, "draining", "")
			return e
		}
		if busy {
			s.publish(session, "draining", "等待已接收任务结束")
			return nil
		}
		session.Phase, session.RootRequested = "root_acquiring", true
		if err = s.save(ctx, session); err != nil {
			return err
		}
	}
	if session.Phase == "root_acquiring" {
		if !session.RootRequested {
			session.Phase, session.Error = "recovery_required", "维护请求意图缺失，写入保持关闭"
			return s.save(ctx, session)
		}
		if !root.Available {
			s.publish(session, "root_acquiring", root.Reason)
			return nil
		}
		call, cancel := context.WithTimeout(ctx, 3*time.Second)
		ack, e := s.Agent.AcquireMaintenance(call, RootRequest{Protocol: protocol.Agent, OperationID: session.TaskID})
		cancel()
		if e != nil {
			s.publish(session, "root_acquiring", "等待 Agent 独立维护确认")
			return nil
		}
		s.mu.Lock()
		s.root = ack
		s.mu.Unlock()
		if session.RootEpoch == "" && time.Now().Unix() >= session.Deadline {
			session.Phase, session.Error = "releasing", "等待在途操作结束超时，未进入独占维护"
			return s.save(ctx, session)
		}
		if ack.ID == session.TaskID && ack.Phase == "held" && ack.Available && ack.Busy == 0 && validID(ack.Epoch) {
			session.Phase, session.RootEpoch, session.Error = "held", ack.Epoch, ""
			return s.save(ctx, session)
		}
	}
	return nil
}
func validRoot(root RootStatus) bool {
	if c := root.Completion; c != nil {
		if !validID(c.OperationID) || len(c.RequestSHA256) != 64 || (c.Outcome != "succeeded" && c.Outcome != "rolled_back" && c.Outcome != "failed") || !root.Available || root.ID == "" || root.Phase != "held" && root.Phase != "closing" || root.Busy != 0 {
			return false
		}
		for _, ch := range c.RequestSHA256 {
			if !(ch >= '0' && ch <= '9' || ch >= 'a' && ch <= 'f') {
				return false
			}
		}
	}
	switch root.Phase {
	case "open":
		return root.ID == ""
	case "closing":
		return root.ID != ""
	case "held":
		return root.ID != "" && root.Busy == 0
	case "recovery_required":
		return true
	default:
		return false
	}
}
func (s *Service) Run(ctx context.Context) error {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	reported := false
	for {
		if err := s.step(ctx); err != nil && ctx.Err() == nil {
			if !reported {
				slog.Warn("maintenance reconciliation failed", "error", err)
			}
			reported = true
		} else {
			reported = false
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}
