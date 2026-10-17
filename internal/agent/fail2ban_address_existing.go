package agent

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"time"

	"nginxpanel/internal/fail2ban"
	"nginxpanel/internal/fault"
	"nginxpanel/internal/secure"
)

type fail2banAddressSample struct {
	value fail2ban.AddressStatus
	err   error
}

func (f *fail2banJailsExecutor) readAddressStatus(ctx context.Context, in fail2ban.AddressQuery) (fail2ban.AddressStatus, error) {
	if err := in.Validate(); err != nil {
		return fail2ban.AddressStatus{}, err
	}
	if in.EngineOwner != "existing" {
		return f.addressStatus(ctx, in)
	}
	key := in.EngineOwner + "/" + in.AdoptionID + "/" + in.Jail + "/" + in.IP
	sample, err := f.addressReads.readWithTimeout(ctx, f.ctx, &f.addressBudget, key, 90*time.Second, func(call context.Context) fail2banAddressSample {
		value, err := f.addressStatus(call, in)
		return fail2banAddressSample{value: value, err: err}
	})
	if err != nil {
		return fail2ban.AddressStatus{}, err
	}
	return sample.value, sample.err
}

func fail2banExistingAddressEngine(c *fail2banExistingCapture, selected fail2banExistingPolicySelection) string {
	return secure.Hash([]byte("nginxpanel:existing-address:v1:" + c.Binding.ID + ":" + c.Binding.ClientSHA256 + ":" + selected.NativeProof))
}

// Admission captures only the local ownership selection. Expensive live proof
// runs in the durable root job before any official write can be sent.
func (f *fail2banJailsExecutor) existingAddressIntent(in fail2ban.AddressRequest) (*fail2banAddressIntent, error) {
	c, err := existingPolicyAdoption(f.server.DataDir, in.Input.AdoptionID)
	if err != nil {
		return nil, err
	}
	if c.Plan.Profile.Name != in.Input.Jail {
		return nil, fault.Conflict("接管记录与目标 jail 不一致")
	}
	selected, err := loadFail2banExistingPolicy(f.server.DataDir, c, in.Input.AdoptionID)
	if err != nil {
		return nil, err
	}
	if !selected.Policy.Enabled {
		return nil, fault.Conflict("已停用的 jail 不能执行单 jail 手动操作")
	}
	return &fail2banAddressIntent{Request: in, Installation: c.Binding.ID, Selection: selected.ID, Engine: fail2banExistingAddressEngine(c, selected), Submission: "not_sent", EngineState: "unknown"}, nil
}

func (f *fail2banJailsExecutor) existingAddressContext(ctx context.Context, in fail2ban.AddressQuery) (fail2banAddressContext, error) {
	out := fail2banAddressContext{action: "unknown", backend: "existing-ssh", reason: "已核对官方引擎；SSH 动作的实际内核阻断需独立确认"}
	var evidence fail2banExistingRuntimeEvidence
	live, err := readFail2banExistingRuntimeLocked(ctx, f.server.DataDir, in.AdoptionID, nil, &evidence)
	if err != nil {
		return out, err
	}
	if live.Name != in.Jail || !live.Policy.Enabled {
		return out, fault.Conflict("目标接管 jail 未运行或名称不匹配")
	}
	if evidence.Program.managed != nil {
		return out, errors.New("已有 jail 意外指向受管引擎")
	}
	out.existing, out.live, out.target = &evidence, evidence.Live, live.Target
	out.installation, out.selection = live.BindingID, live.PolicyID
	out.engine = fail2banExistingAddressEngine(evidence.Capture, evidence.Selection)
	out.banTime, out.bans = live.Policy.BanTime, live.Bans
	ip, err := netip.ParseAddr(in.IP)
	if err != nil {
		return out, err
	}
	out.protected = !ip.IsGlobalUnicast()
	local, err := net.InterfaceAddrs()
	if err != nil {
		return out, err
	}
	for _, address := range local {
		prefix, err := netip.ParsePrefix(address.String())
		if err != nil {
			return out, errors.New("本机接口地址无法完整核对")
		}
		out.protected = out.protected || prefix.Addr().Unmap() == ip
	}
	for _, value := range live.Policy.IgnoreIPs {
		if prefix, err := netip.ParsePrefix(value); err == nil {
			out.protected = out.protected || prefix.Contains(ip)
		} else if address, err := netip.ParseAddr(value); err == nil {
			out.protected = out.protected || address.Unmap() == ip
		}
	}
	out.canBan = !out.protected
	if len(out.bans) >= 1024 {
		if _, exists := out.bans[in.IP]; !exists {
			out.canBan = false
			out.reason += "；当前 jail 已达到封禁观察上限，仅允许解封"
		}
	}
	return out, ctx.Err()
}

func validFail2banAddressIntent(record Record) bool {
	i := record.Fail2banAddress
	if i == nil || !i.Request.Valid() || i.Request.OperationID != record.OperationID || i.Request.Hash() != record.RequestHash || !validID(i.Installation) || !validID(i.Selection) || !fail2banDigest.MatchString(i.Engine) {
		return false
	}
	if i.Request.Input.EngineOwner == "managed" || i.Sent {
		return fail2banInvocation.MatchString(i.Invocation) && i.SocketInode != ""
	}
	return i.Invocation == "" && i.SocketInode == ""
}

func (current fail2banAddressContext) matches(i *fail2banAddressIntent) bool {
	checkLive := i.Sent || i.Request.Input.EngineOwner == "managed"
	return current.installation == i.Installation && current.selection == i.Selection && current.engine == i.Engine && current.target == i.Request.Input.Target && (!checkLive || current.live.invocation == i.Invocation && current.live.inode == i.SocketInode)
}

func (f *fail2banJailsExecutor) addressProof(ctx context.Context, current fail2banAddressContext, i *fail2banAddressIntent) (map[string]fail2banBanTime, error) {
	if current.existing != nil {
		after, err := f.addressContext(ctx, i.Request.Input.Query())
		if err != nil {
			return nil, err
		}
		if !after.matches(i) {
			return nil, errors.New("读取后原接管、参数、服务或动作来源变化")
		}
		return after.bans, nil
	}
	proof, err := readFail2banJailDetails(ctx, current.r, current.bundle, current.jail)
	if err == nil {
		err = verifyFail2banManaged(ctx, current.r, true)
	}
	if err == nil {
		live, liveErr := readFail2banLiveService(ctx, current.r.binding())
		if liveErr != nil || !sameFail2banLive(current.live, live) {
			err = errors.New("服务身份变化")
		}
	}
	return proof, err
}
