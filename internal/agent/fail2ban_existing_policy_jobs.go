package agent

import (
	"context"
	"errors"
	"os"
	"time"

	"nginxpanel/internal/fail2ban"
	"nginxpanel/internal/fault"
)

const fail2banExistingPolicyJobKind = "nginx.fail2ban-existing-policy-job"

type fail2banExistingPolicyJob struct {
	Request         fail2ban.ExistingPolicyRequest `json:"request"`
	CreatedAt       int64                          `json:"created_at"`
	Plan            *fail2ban.ExistingPolicyPlan   `json:"plan,omitempty"`
	CancelRequested bool                           `json:"cancel_requested"`
	CancelError     string                         `json:"cancel_error"`
}

func validFail2banExistingPolicyJobRequest(r Record) error {
	job := r.Fail2banExistingPolicyJob
	if job == nil || job.CreatedAt <= 0 || len(job.CancelError) > 8192 || job.CancelRequested && job.CancelError != "" {
		return errors.New("已有 jail 排队请求依据无效")
	}
	in, err := job.Request.Normalize()
	if err != nil || in.OperationID != r.OperationID || in.Hash() != r.RequestHash || in.Hash() != job.Request.Hash() {
		return errors.New("已有 jail 排队请求合同无效")
	}
	return nil
}

func validFail2banExistingPolicyJobRecord(r Record) error {
	if r.Kind != fail2banExistingPolicyJobKind || r.Fail2banExistingPolicy != nil {
		return errors.New("已有 jail 排队操作类型无效")
	}
	if err := validFail2banExistingPolicyJobRequest(r); err != nil {
		return err
	}
	job := r.Fail2banExistingPolicyJob
	if job.CancelError != "" {
		return errors.New("尚未执行的参数请求含有运行取消结果")
	}
	if r.State == "succeeded" {
		if job.Request.Action != "preview" || r.Stage != "preview_confirmed" || r.Error != "" || job.CancelRequested || job.Plan == nil || !job.Plan.Valid() || job.Plan.AdoptionID != job.Request.AdoptionID || !equalFail2banExistingPolicy(job.Plan.After, job.Request.Policy) || job.Plan.At < job.CreatedAt {
			return errors.New("已有 jail 预览结果无效")
		}
		return nil
	}
	if job.Plan != nil {
		return errors.New("未确认的参数预览包含候选结果")
	}
	if r.State == "running" && r.Stage == "queued" && !job.CancelRequested && r.Error == "" {
		return nil
	}
	if r.State == "failed" {
		if r.Stage == "cancelled" && job.CancelRequested && r.Error == "" {
			return nil
		}
		if !job.CancelRequested && r.Error != "" && (r.Stage == "expired" || r.Stage == job.Request.Action+"_rejected") {
			return nil
		}
	}
	return errors.New("已有 jail 排队操作状态无效")
}

func fail2banExistingPolicyJobView(r Record) fail2ban.ExistingPolicyOperation {
	job := r.Fail2banExistingPolicyJob
	out := fail2ban.ExistingPolicyOperation{ID: r.OperationID, RequestHash: r.RequestHash, Action: job.Request.Action, AdoptionID: job.Request.AdoptionID, Target: job.Request.Target, State: r.State, Stage: r.Stage, Error: r.Error, Plan: job.Plan, CancelRequested: job.CancelRequested, CancelError: job.CancelError}
	if job.Plan != nil {
		out.Target = job.Plan.Target
	}
	return out
}

// Both admission and execution check the saved preview. Its target freezes the
// local adoption, configuration, native profile, process and stop impact.
func checkFail2banExistingPolicyPreview(j *Journal, in fail2ban.ExistingPolicyRequest) error {
	r, err := j.Get(in.PreviewID)
	if err != nil {
		return fault.Conflict("原参数预览不存在，须重新预览")
	}
	if err = validFail2banExistingPolicyJobRecord(r); err != nil {
		return err
	}
	job := r.Fail2banExistingPolicyJob
	if r.State != "succeeded" || job.Request.Action != "preview" || job.Plan == nil {
		return fault.Conflict("原参数预览尚未成功")
	}
	p := job.Plan
	now := time.Now().Unix()
	if now < p.At || now-p.At > 300 || in.AdoptionID != p.AdoptionID || in.Target != p.Target || !equalFail2banExistingPolicy(in.Policy, p.After) || in.ConfirmStop != p.StopConfirmation {
		return fault.Conflict("预览已过期、参数已变更或停用未明确确认，须重新预览")
	}
	return nil
}

func (f *fail2banJailsExecutor) submitExistingPolicy(ctx context.Context, input fail2ban.ExistingPolicyRequest) (fail2ban.ExistingPolicyOperation, error) {
	var out fail2ban.ExistingPolicyOperation
	in, err := input.Normalize()
	if err != nil {
		return out, err
	}
	leave, err := f.lock(false)
	if err != nil {
		return out, err
	}
	defer leave()
	if old, e := f.journal().Get(in.OperationID); e == nil {
		if old.RequestHash != in.Hash() || old.Fail2banExistingPolicyJob == nil {
			return out, fault.Conflict("已有 jail 操作 UUID 已用于其他请求")
		}
		return f.existingPolicyOperation(in.OperationID)
	} else if !os.IsNotExist(e) {
		return out, e
	}
	if err = fail2banManagedIdle(f.server.DataDir, ""); err != nil {
		return out, err
	}
	admit, err := fail2banHostSyncAdmission(f.server.DataDir, false)
	if err != nil {
		return out, err
	}
	defer admit()
	if _, err = existingPolicyAdoption(f.server.DataDir, in.AdoptionID); err != nil {
		return out, err
	}
	if in.Action == "apply" {
		if err = checkFail2banExistingPolicyPreview(f.journal(), in); err != nil {
			return out, err
		}
	}
	if err = ctx.Err(); err != nil {
		return out, err
	}
	r := Record{OperationID: in.OperationID, RequestHash: in.Hash(), Kind: fail2banExistingPolicyJobKind, State: "running", Stage: "queued", Fail2banExistingPolicyJob: &fail2banExistingPolicyJob{Request: in, CreatedAt: time.Now().Unix()}}
	if err = validFail2banExistingPolicyJobRecord(r); err != nil {
		return out, err
	}
	if err = f.persist(r); err != nil {
		return out, err
	}
	f.enqueue()
	return fail2banExistingPolicyJobView(r), nil
}

func (f *fail2banJailsExecutor) existingPolicyOperation(id string) (fail2ban.ExistingPolicyOperation, error) {
	var out fail2ban.ExistingPolicyOperation
	if !validID(id) {
		return out, fault.Invalid("已有 jail 操作 UUID 无效")
	}
	r, err := f.journal().Get(id)
	if err != nil {
		if os.IsNotExist(err) {
			return out, fault.New(404, "FAIL2BAN_EXISTING_OPERATION_MISSING", "已有 jail 参数操作记录不存在")
		}
		return out, err
	}
	if r.Kind == fail2banExistingPolicyJobKind {
		if err = validFail2banExistingPolicyJobRecord(r); err != nil {
			return out, err
		}
		return fail2banExistingPolicyJobView(r), nil
	}
	if r.Kind != fail2banExistingPolicyKind {
		return out, fault.Conflict("操作 UUID 已用于其他任务")
	}
	c, err := validFail2banExistingPolicyRecord(f.server.DataDir, r)
	if err != nil {
		return out, err
	}
	return fail2banExistingPolicyOperation(r, c), nil
}

func (f *fail2banJailsExecutor) cancelExistingPolicy(ctx context.Context, id string) (fail2ban.ExistingPolicyOperation, error) {
	var out fail2ban.ExistingPolicyOperation
	if !validID(id) {
		return out, fault.Invalid("已有 jail 操作 UUID 无效")
	}
	leave, err := f.lock(true)
	if err != nil {
		return out, err
	}
	defer leave()
	if out, err = f.existingPolicyOperation(id); err != nil {
		return out, err
	}
	if out.State == "succeeded" {
		return out, fault.Conflict("原操作已完成；恢复参数须新建预览和应用")
	}
	if out.State == "failed" {
		return out, nil
	}
	r, err := f.journal().Get(id)
	if err != nil {
		return out, err
	}
	job := r.Fail2banExistingPolicyJob
	if job == nil {
		return out, fault.Conflict("本机 root 直接发起的操作须由本机 root 取消")
	}
	if err = ctx.Err(); err != nil {
		return out, err
	}
	job.CancelRequested, job.CancelError = true, ""
	if r.Kind == fail2banExistingPolicyJobKind {
		// Before conversion there can be no live file or native submission.
		r.State, r.Stage, r.Error = "failed", "cancelled", ""
	}
	if err = f.persist(r); err != nil {
		return out, err
	}
	f.enqueue()
	return f.existingPolicyOperation(id)
}

// The executor already holds the shared Nginx/host/binding locks. The single
// journal UUID transitions atomically to the existing captured apply intent.
func (f *fail2banJailsExecutor) advanceExistingPolicyJob(ctx context.Context, r Record) error {
	if err := validFail2banExistingPolicyJobRecord(r); err != nil {
		return existingPolicyRecovery(f.journal(), r, err)
	}
	job := r.Fail2banExistingPolicyJob
	fail := func(stage string, err error) error {
		r.State, r.Stage, r.Error = "failed", stage, fail2banExistingPolicyError(err)
		return f.persist(r)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	now := time.Now().Unix()
	if now < job.CreatedAt || now-job.CreatedAt > 300 {
		return fail("expired", errors.New("排队参数请求已过期，须重新预览"))
	}
	in := job.Request
	if in.Action == "apply" {
		if err := checkFail2banExistingPolicyPreview(f.journal(), in); err != nil {
			return fail("apply_rejected", err)
		}
	}
	original, err := existingPolicyAdoption(f.server.DataDir, in.AdoptionID)
	if err != nil {
		return fail(in.Action+"_rejected", err)
	}
	c, err := planFail2banExistingPolicyLocked(ctx, f.server.DataDir, in.AdoptionID, Fail2banExistingJailInput{Profile: original.Plan.Profile, Policy: in.Policy})
	if err != nil {
		if ctx.Err() != nil {
			return err
		}
		return fail(in.Action+"_rejected", err)
	}
	if !c.Plan.Valid() || c.Plan.At < job.CreatedAt {
		return fail(in.Action+"_rejected", errors.New("参数预览结果或生成时钟无效"))
	}
	if in.Action == "preview" {
		job.Plan = &c.Plan
		r.State, r.Stage = "succeeded", "preview_confirmed"
		return f.persist(r)
	}
	if c.Plan.Target != in.Target || c.Plan.StopConfirmation != in.ConfirmStop {
		return fail("apply_rejected", errors.New("目标或停用影响在预览后变化，须重新预览"))
	}
	if err = checkFail2banExistingPolicyPreview(f.journal(), in); err != nil {
		return fail("apply_rejected", err)
	}
	// A failed journal sync may already have published the converted record.
	// Never overwrite it with a failed queue record; resume from disk next tick.
	if _, _, err = prepareFail2banExistingPolicyRecord(f.server.DataDir, f.journal(), r.OperationID, c, job); err != nil {
		current, readErr := f.journal().Get(r.OperationID)
		if readErr != nil {
			return errors.Join(err, readErr)
		}
		if current.Kind == fail2banExistingPolicyJobKind && current.State == "running" && current.RequestHash == r.RequestHash {
			if contractErr := validFail2banExistingPolicyJobRecord(current); contractErr != nil {
				return errors.Join(err, contractErr)
			}
			// The original queue is still authoritative and no live writes
			// were possible. Report preparation failure without retrying it.
			r = current
			return fail("apply_rejected", err)
		}
		return err
	}
	f.enqueue()
	return nil
}

func fail2banExistingPolicyError(err error) string {
	value := []rune(err.Error())
	return string(value[:min(len(value), 2048)])
}
