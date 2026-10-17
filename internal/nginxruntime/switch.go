package nginxruntime

import (
	"context"
	"errors"
)

// SwitchedSelection checks only the root-owned selection receipt against a
// durable operation's two permitted identities. It does not approve execution
// of a candidate whose files or signing trust may since have become invalid.
func SwitchedSelection(data, operationID string, before, candidate Binding) (Binding, error) {
	if !installationID.MatchString(operationID) || before.DataDir != data || candidate.DataDir != data {
		return Binding{}, errors.New("组件选择核对参数无效")
	}
	current, err := readBinding(data)
	if err != nil {
		return Binding{}, err
	}
	if SelectionHash(current) != SelectionHash(before) && (current.OperationID != operationID || CandidateHash(current) != CandidateHash(candidate)) {
		return Binding{}, errors.New("组件选择已偏离本次操作")
	}
	return current, nil
}

// VerifyRetained checks the immutable selection retained by a root operation
// before stopping a running component for which it is the recovery target.
func VerifyRetained(ctx context.Context, b Binding) error {
	if b.Schema != Schema || b.BoundAt <= 0 || b.Owner != "local" && b.Owner != "managed" || !digest.MatchString(b.SHA256) || !versionValue.MatchString(b.Version) || (b.Owner == "managed") != (b.Signed != nil) {
		return errors.New("保留的组件选择无效")
	}
	if _, err := bindingPath(b.DataDir); err != nil {
		return err
	}
	_, err := verifySelection(ctx, b)
	return err
}

// SwitchPrepared requires an independent, durable maintenance operation. It
// replaces only the exact prior selection, never a subsequently chosen runtime.
func SwitchPrepared(ctx context.Context, in Input, operationID string, before, approved Binding) (Binding, error) {
	if !installationID.MatchString(operationID) || in.Binary != "" || in.Uninstalled || in.PlanID == "" || in.AssetID == "" || before.DataDir != in.DataDir || before.Owner != "local" && before.Owner != "managed" {
		return Binding{}, errors.New("运行组件切换请求无效")
	}
	if err := in.Validate(); err != nil {
		return Binding{}, err
	}
	unlock, err := LockSelection(in.DataDir)
	if err != nil {
		return Binding{}, err
	}
	defer unlock()
	current, _, err := Selection(ctx, in.DataDir)
	if err != nil {
		return Binding{}, err
	}
	if current.OperationID == operationID && CandidateHash(current) == CandidateHash(approved) {
		return current, nil
	}
	if SelectionHash(current) != SelectionHash(before) {
		return Binding{}, errors.New("原组件选择已变化，停止覆盖")
	}
	candidate, err := Admit(ctx, in)
	if err != nil {
		return Binding{}, err
	}
	if CandidateHash(candidate) != CandidateHash(approved) || candidate.SHA256 == before.SHA256 {
		return Binding{}, errors.New("候选组件与原批准不一致或未改变程序")
	}
	candidate.OperationID = operationID
	return publishBinding(ctx, candidate, true)
}

// RestoreSwitched restores the exact receipt retained by the root journal.
// Current candidate trust is deliberately unnecessary for compensation; the
// original executable and its own installed provenance must still verify.
func RestoreSwitched(ctx context.Context, operationID string, before, candidate Binding) (Binding, error) {
	if !installationID.MatchString(operationID) || before.DataDir != candidate.DataDir || before.Schema != Schema || before.Owner != "local" && before.Owner != "managed" || before.BoundAt <= 0 {
		return Binding{}, errors.New("组件补偿记录无效")
	}
	unlock, err := LockSelection(before.DataDir)
	if err != nil {
		return Binding{}, err
	}
	defer unlock()
	current, err := readBinding(before.DataDir)
	if err != nil {
		return Binding{}, err
	}
	if SelectionHash(current) != SelectionHash(before) && (current.OperationID != operationID || CandidateHash(current) != CandidateHash(candidate)) {
		return Binding{}, errors.New("当前组件不属于原切换，拒绝补偿覆盖")
	}
	if err = VerifyRetained(ctx, before); err != nil {
		return Binding{}, err
	}
	if SelectionHash(current) == SelectionHash(before) {
		return current, nil
	}
	return publishBinding(ctx, before, true)
}
