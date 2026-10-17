package agent

import (
	"context"
	"encoding/xml"
	"errors"
	"slices"

	"github.com/godbus/dbus/v5"
	"nginxpanel/internal/firewall"
)

// Pin the implementation's actual method signature before admitting a write.
// The official server takes policy + dictionary; timeout is a dictionary key,
// and is deliberately not used as a substitute for independent recovery.
func (b *firewalldBus) policyWriteSupported(path dbus.ObjectPath, iface, name, signature string) error {
	var raw string
	if err := b.call(path, "org.freedesktop.DBus.Introspectable.Introspect").Store(&raw); err != nil {
		return err
	}
	if len(raw) > 256<<10 {
		return errors.New("firewalld 接口说明超过预算")
	}
	var node struct {
		Interfaces []struct {
			Name    string `xml:"name,attr"`
			Methods []struct {
				Name string `xml:"name,attr"`
				Args []struct {
					Type      string `xml:"type,attr"`
					Direction string `xml:"direction,attr"`
				} `xml:"arg"`
			} `xml:"method"`
		} `xml:"interface"`
	}
	if xml.Unmarshal([]byte(raw), &node) != nil {
		return errors.New("firewalld 接口说明无效")
	}
	for _, i := range node.Interfaces {
		if i.Name == iface {
			for _, m := range i.Methods {
				if m.Name == name {
					in, out := "", ""
					for _, a := range m.Args {
						if a.Direction == "out" {
							out += a.Type
						} else if a.Direction == "in" || a.Direction == "" {
							in += a.Type
						} else {
							return errors.New("firewalld 参数方向无效")
						}
					}
					if in == signature && out == "" {
						return nil
					}
				}
			}
		}
	}
	return errors.New("firewalld policy 写入接口不受支持")
}
func (f *hostFirewall) firewalldCallEnded() error {
	c := f.firewalldState.Call
	if c == nil || c.Ended {
		return nil
	}
	if !networkdCallEnded(c.Peer) {
		return errors.New("原 firewalld 请求结果未知且处理进程尚未结束，禁止重放或覆盖")
	}
	c.Ended = true
	return f.saveFirewalld()
}

func (f *hostFirewall) writeFirewalld(plane, target string, baseline firewalldRegistrationSnapshot) error {
	v := f.firewalldState
	if err := f.firewalldCallEnded(); err != nil {
		return err
	}
	if !slices.Contains([]string{"runtime", "permanent"}, plane) || !slices.Contains([]string{"confirmed", "candidate"}, target) || target == "candidate" && v.Candidate == nil {
		return errors.New("firewalld 写入意图无效")
	}
	record := v.Confirmed
	if target == "candidate" {
		record = v.Candidate
	}
	program, err := firewalldProgram(record)
	if err != nil {
		return err
	}
	machine, _, err := firewalldHostIdentity()
	if err != nil || machine != v.MachineHash {
		return errors.New("firewalld 恢复材料与当前宿主机不一致")
	}
	b, err := openFirewalldBus(context.Background())
	if err != nil {
		return err
	}
	defer b.close()
	path, iface, method, sig := firewalldRoot, firewalldName+".policy", "setPolicySettings", "sa{sv}"
	if plane == "permanent" {
		path, iface, method, sig = baseline.Path, firewalldName+".config.policy", "update", "a{sv}"
	}
	if err = b.policyWriteSupported(path, iface, method, sig); err != nil {
		return err
	}
	current, err := b.registrationSnapshot()
	if err != nil || !firewalldActive(current) {
		return errors.New("firewalld 写入前无法完整核对目标")
	}
	if current.Policy.Runtime.Hash != baseline.Policy.Runtime.Hash || current.Policy.Permanent.Hash != baseline.Policy.Permanent.Hash || plane == "permanent" && current.Path != baseline.Path {
		return errors.New("firewalld 提交基线已变化")
	}
	var panic bool
	if err = b.call(firewalldRoot, firewalldName+".queryPanicMode").Store(&panic); err != nil || panic {
		return errors.New("firewalld panic 状态无法排除")
	}
	if err = b.unchangedOwner(); err != nil {
		return err
	}
	v.Call = &firewalldMutation{Plane: plane, Target: target, BusID: b.busID, BusOwner: b.owner, Peer: b.process}
	if err = f.saveFirewalld(); err != nil {
		return err
	}
	if err = b.unchangedOwner(); err != nil {
		v.Call.Ended = true // The method has not been dispatched.
		return errors.Join(err, f.saveFirewalld())
	}
	if target == "candidate" && f.expiredLocked() {
		v.Call.Ended = true
		return errors.Join(errors.New("firewalld 提交前确认期限已到"), f.saveFirewalld())
	}
	settings := map[string]dbus.Variant{"rich_rules": dbus.MakeVariant(append([]string{}, program.Settings.RichRules...))}
	if plane == "runtime" {
		err = b.call(path, iface+"."+method, firewall.FirewalldHostPolicy, settings).Err
	} else {
		err = b.call(path, iface+"."+method, settings).Err
	}
	v.Call.Ended = err == nil || firewalldCompletedError(err) != ""
	// Receipt must be durable before compensation or another plane is written.
	return errors.Join(err, f.saveFirewalld())
}

// A failed multi-rule call can leave a subset of the intended change. Recovery
// may remove only exact expressions admitted by the durable old/new programs;
// different settings, third-party rules and missing objects are never adopted.
func (f *hostFirewall) firewalldRecoverable(settings map[string]dbus.Variant) bool {
	rules, ok := firewalldOwnedRules(settings, f.firewalldState.Owner)
	if !ok {
		return false
	}
	allowed := map[string]bool{}
	for _, r := range []*firewallPolicyRecord{f.firewalldState.Confirmed, f.firewalldState.Candidate} {
		p, err := firewalldProgram(r)
		if err != nil {
			return false
		}
		for _, rule := range p.Settings.RichRules {
			allowed[rule] = true
		}
	}
	seen := map[string]bool{}
	for _, rule := range rules {
		if !allowed[rule] || seen[rule] {
			return false
		}
		seen[rule] = true
	}
	return true
}
