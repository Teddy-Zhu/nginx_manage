package agent

import (
	"context"
	"errors"
	"strings"
	"time"
)

// A sent marker is durable before invoking the official client. Recovery only
// observes this operation; neither a lost reply nor an expired ban resends it.
func (f *fail2banJailsExecutor) advanceAddress(ctx context.Context) error {
	leave, err := f.lock(true)
	if err != nil {
		return err
	}
	defer leave()
	records, err := f.journal().List()
	if err != nil {
		return err
	}
	var pending *Record
	other := false
	for _, record := range records {
		if !pendingNginxRecord(record) {
			continue
		}
		if record.Kind != fail2banAddressKind {
			other = true
			continue
		}
		if pending != nil {
			return errors.New("存在多个未结束的手动封禁操作")
		}
		copy := record
		pending = &copy
	}
	if pending == nil {
		return nil
	}
	if other {
		return ErrBusy
	}
	record := *pending
	i := record.Fail2banAddress
	finish := func(stage, message string) error {
		record.State, record.Stage, record.Error = "failed", stage, message
		return f.persist(record)
	}
	if !validFail2banAddressIntent(record) {
		return finish("invalid_intent", "持久手动操作合同损坏，未重新派发")
	}
	if !i.Sent && record.Deadline <= time.Now().Unix() {
		return finish("authorization_expired", "手动操作排队超过五分钟，未派发")
	}
	current, err := f.addressContext(ctx, i.Request.Input.Query())
	if err != nil {
		return finish("runtime_unconfirmed", "无法核对原引擎与动作来源；未重新派发")
	}
	if !current.matches(i) {
		return finish("target_changed", "原实例、服务代次、配置或动作授权已变化；未重新派发")
	}
	input := i.Request.Input
	if !i.Sent {
		if input.Action == "ban" && !current.canBan {
			return finish("action_unavailable", "该地址受保护或动作依据不可用，未派发封禁")
		}
		state, expires, permanent := fail2banAddressState(current.bans, input.IP)
		if input.Action == "ban" && state == "banned" {
			i.Submission, i.EngineState, i.ObservedAt, i.ExpiresAt, i.Permanent = "not_needed", state, time.Now().Unix(), expires, permanent
			record.State, record.Stage = "succeeded", "engine_confirmed"
			f.refreshAddressAction(current.backend)
			return f.persist(record)
		}
		i.Sent, i.Submission = true, "unknown"
		i.Invocation, i.SocketInode = current.live.invocation, current.live.inode
		record.Stage = "command_pending"
		if err = f.persist(record); err != nil {
			return err
		}
		verb := "banip"
		if input.Action == "unban" {
			verb = "unbanip"
		}
		var raw []byte
		var commandErr error
		if current.existing != nil {
			args := append(fail2banReadArgs(current.existing.Capture.Binding.Socket, "set"), input.Jail, verb, input.IP)
			raw, commandErr = current.existing.Program.run(ctx, args, 4096)
		} else {
			args := append(fail2banReadArgs(fail2banManagedSocket, "set"), input.Jail, verb, input.IP)
			raw, commandErr = fail2banManagedExec(ctx, current.r.python(), current.r.args(true, args...), 6*time.Second, 4096)
		}
		if commandErr == nil {
			switch strings.TrimSpace(string(raw)) {
			case "0":
				value := 0
				i.Receipt = &value
			case "1":
				value := 1
				i.Receipt = &value
			}
			if i.Receipt != nil {
				i.Submission = "acknowledged"
			}
		}
		record.Stage = "observing"
		if err = f.persist(record); err != nil {
			return err
		}
	}
	f.refreshAddressAction(current.backend)
	// An interrupted invocation may have changed the engine, but its intent is
	// never inverted or replayed. Confirm current state independently of receipt.
	proof, err := f.addressProof(ctx, current, i)
	if err != nil {
		return finish("state_unconfirmed", "官方客户端可能已执行，当前引擎状态无法确认；原操作不会重发")
	}
	i.EngineState, i.ExpiresAt, i.Permanent = fail2banAddressState(proof, input.IP)
	i.ObservedAt = time.Now().Unix()
	wanted := "banned"
	if input.Action == "unban" {
		wanted = "clear"
	}
	if i.EngineState != wanted {
		return finish("state_not_reached", "当前引擎状态未满足请求，可能已过期或产生新的封禁；原操作不会重发")
	}
	record.State, record.Stage, record.Error = "succeeded", "engine_confirmed", ""
	if i.Submission == "unknown" {
		record.Stage = "state_confirmed_receipt_unknown"
	}
	if err = f.persist(record); err != nil {
		return err
	}
	return nil
}

func (f *fail2banJailsExecutor) refreshAddressAction(action string) {
	if action == "nginx-client" && f.server.fail2banNginx != nil {
		f.server.fail2banNginx.enqueue()
	}
	if action == "host-input" && f.server.fail2banHostSync != nil {
		f.server.fail2banHostSync.enqueue()
	}
}
