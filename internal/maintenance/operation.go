package maintenance

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"nginxpanel/internal/auth"
	"nginxpanel/internal/fault"
	"nginxpanel/internal/protocol"
	"nginxpanel/internal/secure"
)

// Submit keeps exclusive preparation inside a concrete task. The task owns the
// guard until it settles; callers never enter or leave a separate system mode.
func (s *Service) Submit(ctx context.Context, p auth.Principal, requestID string, create func(string) (string, error)) error {
	if s == nil {
		return fault.Unavailable("系统操作服务未配置")
	}
	session, err := s.start(ctx, p, requestID, "operation:"+secure.ID(), StartInput{DrainSeconds: 30}, "", nil)
	if err != nil {
		return err
	}
	if err = s.wait(ctx, session.TaskID); err != nil {
		return errors.Join(err, s.finish(p, requestID, session.TaskID))
	}
	id, err := create(session.TaskID)
	if err != nil {
		return errors.Join(err, s.finish(p, requestID, session.TaskID))
	}
	linked, _, err := s.operationTask(ctx, session.TaskID)
	if errors.Is(err, sql.ErrNoRows) {
		// Another request committed the same idempotency receipt before this
		// guard was acquired; its original task already owns the work.
		return s.finish(p, requestID, session.TaskID)
	}
	if err != nil {
		return err
	}
	if linked != id {
		return fault.Conflict("操作任务关联不一致，请查看操作记录")
	}
	_, err = s.DB.ExecContext(ctx, "UPDATE maintenance_sessions SET owner_task_id=?,updated_at=? WHERE task_id=? AND (owner_task_id IS NULL OR owner_task_id=?)", id, time.Now().Unix(), session.TaskID, id)
	return err
}

func (s *Service) operationTask(ctx context.Context, id string) (taskID, state string, err error) {
	err = s.DB.QueryRowContext(ctx, `SELECT t.id,t.state FROM tasks t JOIN (
 SELECT task_id FROM nginx_installations WHERE maintenance_id=?
 UNION ALL SELECT task_id FROM nginx_switches WHERE maintenance_id=?
 UNION ALL SELECT task_id FROM panel_updates WHERE maintenance_id=?
 UNION ALL SELECT task_id FROM agent_upgrades WHERE maintenance_id=?
 UNION ALL SELECT task_id FROM panel_image_upgrades WHERE maintenance_id=?
) o ON o.task_id=t.id LIMIT 1`, id, id, id, id, id).Scan(&taskID, &state)
	return
}

// Temporary protects one synchronous operation and releases it when complete.
// Interrupted cleanup retains its original guard for a retry; previews never
// leave the system waiting for a user to confirm them.
func (s *Service) Temporary(ctx context.Context, p auth.Principal, requestID, sessionID string, run func(RootStatus) error) error {
	if s == nil {
		return fault.Unavailable("系统操作服务未配置")
	}
	var session Session
	if sessionID != "" {
		var owner string
		if err := s.DB.QueryRowContext(ctx, "SELECT principal FROM maintenance_sessions WHERE task_id=?", sessionID).Scan(&owner); err != nil {
			return err
		}
		if owner != p.ID && !p.Has("auth.manage") {
			return auth.ErrForbidden
		}
		session.TaskID = sessionID
	} else {
		var err error
		session, err = s.start(ctx, p, requestID, "operation:"+secure.ID(), StartInput{DrainSeconds: 30}, "", nil)
		if err != nil {
			return err
		}
	}
	var err error
	if err = s.wait(ctx, session.TaskID); err == nil {
		root, done, heldErr := s.Held(session.TaskID)
		if heldErr != nil {
			err = heldErr
		} else {
			func() {
				defer done()
				err = run(root)
			}()
		}
	}
	cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// A partially completed cleanup must keep its original guard so an explicit
	// retry can continue it. Do not first mark its database session as releasing.
	if _, releaseErr := s.Agent.ReleaseMaintenance(cleanup, RootRequest{Protocol: protocol.Agent, OperationID: session.TaskID}); releaseErr != nil {
		return errors.Join(err, releaseErr)
	}
	return errors.Join(err, s.finish(p, requestID, session.TaskID))
}

func (s *Service) wait(ctx context.Context, id string) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		if err := s.step(ctx); err != nil {
			return err
		}
		view := s.View()
		if view.Session == nil || view.Session.TaskID != id {
			return fault.Conflict("操作准备已结束，请重试")
		}
		if view.Phase == "held" {
			return nil
		}
		if view.Phase == "recovery_required" || view.Phase == "releasing" {
			return fault.Conflict("已有系统操作需要处理，请查看操作记录")
		}
		select {
		case <-ctx.Done():
			return fault.Conflict("其他操作尚未结束，请稍后重试")
		case <-ticker.C:
		}
	}
}

func (s *Service) finish(p auth.Principal, requestID, id string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := s.Release(ctx, p, requestID, id); err != nil {
		return err
	}
	return s.step(ctx)
}
