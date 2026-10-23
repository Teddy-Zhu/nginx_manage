package firewall

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"strconv"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"github.com/google/nftables/userdata"
	"golang.org/x/sys/unix"
	"nginxpanel/internal/fault"
)

const NFTHostTable = "nginxpanel_host"
const NFTHostChain = "input"
const NFTHostPriority = 10

// NFTProgram contains concrete expressions but never opens a netlink socket.
// Execution must separately prove ownership and establish independent recovery.
type NFTProgram struct {
	Sets    []NFTAddressSet
	Table   *nftables.Table
	Chain   *nftables.Chain
	Rules   []*nftables.Rule
	Entries []PreviewEntry
	Hash    string
}

func ctState(mask uint32) []expr.Any {
	return []expr.Any{
		&expr.Ct{Key: expr.CtKeySTATE, Register: 1},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: binaryutil.NativeEndian.PutUint32(mask), Xor: []byte{0, 0, 0, 0}},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: []byte{0, 0, 0, 0}},
	}
}
func matchInterface(name string) []expr.Any {
	return []expr.Any{&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: append([]byte(name), 0)}}
}

func CompileNFT(policy Policy) (*NFTProgram, error) {
	normalized, e := policy.Normalize()
	if e != nil {
		return nil, e
	}
	if normalized.Backend != "direct-nftables" {
		return nil, fault.Unavailable("所选后端的编译适配尚不可用")
	}
	for _, r := range normalized.Rules {
		if r.Enabled && r.Scope != "host_input" {
			return nil, fault.Unavailable("Docker 发布端口须使用单独的转发路径适配，不能编译为主机 INPUT 规则")
		}
	}
	table := &nftables.Table{Name: NFTHostTable, Family: nftables.TableFamilyINet}
	accept := nftables.ChainPolicyAccept
	chain := &nftables.Chain{Name: NFTHostChain, Table: table, Hooknum: nftables.ChainHookInput, Priority: nftables.ChainPriorityRef(NFTHostPriority), Type: nftables.ChainTypeFilter, Policy: &accept}
	program := &NFTProgram{Table: table, Chain: chain, Rules: []*nftables.Rule{}, Entries: []PreviewEntry{}}
	appendRule := func(expressions []expr.Any, label string) {
		program.Rules = append(program.Rules, &nftables.Rule{Table: table, Chain: chain, Exprs: expressions, UserData: userdata.AppendString(nil, userdata.TypeComment, "nginxpanel:v1:"+label)})
	}
	appendRule(append(matchInterface("lo"), &expr.Verdict{Kind: expr.VerdictReturn}), "loopback")
	appendRule(append(ctState(expr.CtStateBitESTABLISHED|expr.CtStateBitRELATED), &expr.Verdict{Kind: expr.VerdictReturn}), "existing-connections")
	for _, r := range normalized.Rules {
		if !r.Enabled {
			continue
		}
		for _, family := range []string{"ipv4", "ipv6"} {
			if r.Family != "both" && r.Family != family {
				continue
			}
			sources := []string{""}
			var addressSet *NFTAddressSet
			if len(r.Sources) > 0 {
				var present bool
				addressSet, present = program.sourceSet(r.Sources, family)
				if !present {
					continue
				}
				if addressSet != nil {
					sources = []string{"@" + addressSet.Name}
				}
			}
			for _, source := range sources {
				for _, port := range r.Ports {
					if len(program.Rules) >= MaxEntries {
						return nil, fault.Invalid("防火墙规则展开后超过 8192 条内核规则，请缩小端口和来源组合")
					}
					expressions := ctState(expr.CtStateBitNEW)
					nfproto := byte(unix.NFPROTO_IPV4)
					if family == "ipv6" {
						nfproto = unix.NFPROTO_IPV6
					}
					expressions = append(expressions, &expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{nfproto}})
					if r.Interface != "" {
						expressions = append(expressions, matchInterface(r.Interface)...)
					}
					if addressSet != nil {
						offset := uint32(12)
						if family == "ipv6" {
							offset = 8
						}
						expressions = append(expressions, &expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: offset, Len: addressSet.KeyLen}, &expr.Lookup{SourceRegister: 1, SetName: addressSet.Name, SetID: addressSet.ID})
					}
					proto := byte(unix.IPPROTO_TCP)
					if r.Protocol == "udp" {
						proto = unix.IPPROTO_UDP
					}
					if r.Protocol != "any" {
						expressions = append(expressions, &expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{proto}}, &expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2})
						if port.From == port.To {
							expressions = append(expressions, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.BigEndian.PutUint16(uint16(port.From))})
						} else {
							expressions = append(expressions, &expr.Range{Op: expr.CmpOpEq, Register: 1, FromData: binaryutil.BigEndian.PutUint16(uint16(port.From)), ToData: binaryutil.BigEndian.PutUint16(uint16(port.To))})
						}
					}
					switch r.Action {
					case "allow":
						expressions = append(expressions, &expr.Verdict{Kind: expr.VerdictReturn})
					case "deny":
						expressions = append(expressions, &expr.Verdict{Kind: expr.VerdictDrop})
					case "reject":
						reject := &expr.Reject{Type: unix.NFT_REJECT_ICMPX_UNREACH, Code: unix.NFT_REJECT_ICMPX_PORT_UNREACH}
						if proto == unix.IPPROTO_TCP {
							reject.Type = unix.NFT_REJECT_TCP_RST
							reject.Code = 0
						}
						expressions = append(expressions, reject)
					}
					appendRule(expressions, r.ID+":"+strconv.Itoa(len(program.Entries)))
					program.Entries = append(program.Entries, PreviewEntry{RuleID: r.ID, Family: family, Protocol: r.Protocol, Source: source, Ports: port, Action: r.Action, Interface: r.Interface, Priority: r.Priority})
				}
			}
		}
	}
	return finishNFT(program)
}

func finishNFT(program *NFTProgram) (*NFTProgram, error) {
	hash := sha256.New()
	frame := func(raw []byte) { hash.Write(binary.BigEndian.AppendUint32(nil, uint32(len(raw)))); hash.Write(raw) }
	frame([]byte("inet/" + program.Table.Name + "/" + program.Chain.Name + "/input/" + strconv.Itoa(int(*program.Chain.Priority)) + "/accept"))
	for _, set := range program.Sets {
		frame([]byte(set.Name))
		frame(binary.BigEndian.AppendUint32(nil, set.ID))
		frame(binary.BigEndian.AppendUint32(nil, set.KeyLen))
		for _, element := range set.Elements {
			frame(element.Key)
			if element.End {
				frame([]byte{1})
			} else {
				frame([]byte{0})
			}
		}
	}
	for _, r := range program.Rules {
		frame(r.UserData)
		frame(binary.BigEndian.AppendUint32(nil, uint32(len(r.Exprs))))
		for _, expression := range r.Exprs {
			raw, e := expr.Marshal(byte(nftables.TableFamilyINet), expression)
			if e != nil {
				return nil, e
			}
			frame(raw)
		}
	}
	program.Hash = hex.EncodeToString(hash.Sum(nil))
	return program, nil
}
