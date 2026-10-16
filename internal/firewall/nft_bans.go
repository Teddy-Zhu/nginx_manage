package firewall

import (
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/google/nftables/userdata"
	"golang.org/x/sys/unix"
	"nginxpanel/internal/fault"
)

const NFTBanLimit = 1024
const NFTBanProtectionLimit = 1024

// NFTBanSet is a fresh engine sample plus a separately approved protection
// set. It is not a port policy or authority to install a table.
type NFTBanSet struct {
	Addresses []string `json:"addresses"`
	Protected []string `json:"protected"`
}

func (s NFTBanSet) Normalize() (NFTBanSet, error) {
	out := NFTBanSet{Addresses: []string{}, Protected: []string{}}
	if s.Addresses == nil || s.Protected == nil || len(s.Addresses) > NFTBanLimit || len(s.Protected) > NFTBanProtectionLimit {
		return out, fault.Invalid("宿主机封禁集合或保护来源超出限制")
	}
	seen := map[string]bool{}
	for _, value := range s.Protected {
		value = strings.TrimSpace(value)
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			ip, ipErr := netip.ParseAddr(value)
			if ipErr != nil || ip.Zone() != "" {
				return out, fault.Invalid("宿主机保护来源须为数值 IP/CIDR")
			}
			ip = ip.Unmap()
			prefix = netip.PrefixFrom(ip, ip.BitLen())
		}
		if prefix.Addr().Is4In6() || prefix.Addr().Zone() != "" {
			return out, fault.Invalid("宿主机保护网段须使用原生数值地址族")
		}
		value = prefix.Masked().String()
		if !seen[value] {
			out.Protected = append(out.Protected, value)
			seen[value] = true
		}
	}
	sort.Strings(out.Protected)
	seen = map[string]bool{}
	for _, value := range s.Addresses {
		ip, err := netip.ParseAddr(strings.TrimSpace(value))
		if err != nil || ip.Zone() != "" {
			return out, fault.Invalid("宿主机封禁只支持数值单个 IP")
		}
		ip = ip.Unmap()
		if !ip.IsGlobalUnicast() {
			return out, fault.Invalid("宿主机封禁包含广播、回环、多播或本地链路地址")
		}
		for _, value := range out.Protected {
			prefix, _ := netip.ParsePrefix(value)
			if prefix.Contains(ip) {
				return out, fault.Invalid("宿主机封禁包含受保护来源")
			}
		}
		value = ip.String()
		if !seen[value] {
			out.Addresses = append(out.Addresses, value)
			seen[value] = true
		}
	}
	sort.Strings(out.Addresses)
	return out, nil
}

func nftBanSource(prefix netip.Prefix) []expr.Any {
	ip := prefix.Addr()
	family, offset := byte(unix.NFPROTO_IPV4), uint32(12)
	if ip.Is6() {
		family, offset = unix.NFPROTO_IPV6, 8
	}
	address := ip.AsSlice()
	length := uint32(len(address))
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{family}},
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: offset, Len: length},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: length, Mask: net.CIDRMask(prefix.Bits(), ip.BitLen()), Xor: make([]byte, length)},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: address},
	}
}

// CompileNFTBans drops matching host-input packets, including established
// traffic. Protection returns apply only to this chain, not to other owners.
// Addresses, table identity, hook, priority and expressions are all typed.
func CompileNFTBans(set NFTBanSet) (*NFTProgram, error) {
	set, err := set.Normalize()
	if err != nil {
		return nil, err
	}
	layout, _ := NFTFail2banInput.Layout()
	table := &nftables.Table{Name: layout.Table, Family: nftables.TableFamilyINet}
	accept := nftables.ChainPolicyAccept
	chain := &nftables.Chain{Name: layout.Chain, Table: table, Hooknum: nftables.ChainHookInput, Priority: nftables.ChainPriorityRef(nftables.ChainPriority(layout.Priority)), Type: nftables.ChainTypeFilter, Policy: &accept}
	program := &NFTProgram{Table: table, Chain: chain, Rules: []*nftables.Rule{}, Entries: []PreviewEntry{}}
	add := func(expressions []expr.Any, label string) {
		program.Rules = append(program.Rules, &nftables.Rule{Table: table, Chain: chain, Exprs: expressions, UserData: userdata.AppendString(nil, userdata.TypeComment, "nginxpanel:fail2ban:v1:"+label)})
	}
	add(append(matchInterface("lo"), &expr.Verdict{Kind: expr.VerdictReturn}), "loopback")
	for i, value := range set.Protected {
		prefix, _ := netip.ParsePrefix(value)
		add(append(nftBanSource(prefix), &expr.Verdict{Kind: expr.VerdictReturn}), "protected:"+strconv.Itoa(i))
	}
	for i, value := range set.Addresses {
		ip, _ := netip.ParseAddr(value)
		add(append(nftBanSource(netip.PrefixFrom(ip, ip.BitLen())), &expr.Verdict{Kind: expr.VerdictDrop}), "ban:"+strconv.Itoa(i))
	}
	add([]expr.Any{&expr.Verdict{Kind: expr.VerdictReturn}}, "end")
	return finishNFT(program)
}

// Preparation only encodes. A root executor must prove this target's separate
// ownership, save intent/recovery and recheck the baseline before submitting.
func PrepareNFTBans(set NFTBanSet, baseline KernelView, marker string) (NFTCreateBatch, error) {
	if !validNFTBanMarker(marker) {
		return NFTCreateBatch{}, fault.Invalid("宿主机封禁独立标识无效")
	}
	program, err := CompileNFTBans(set)
	if err != nil {
		return NFTCreateBatch{}, err
	}
	return prepareNFTTransaction(NFTFail2banInput, program, baseline, marker, baseline.TableExists, false)
}

// PrepareNFTBanEmpty removes this target's hook and rules while retaining the
// owned table. The root executor must prove the old complete program first.
func PrepareNFTBanEmpty(baseline KernelView, marker string) (NFTCreateBatch, error) {
	if !validNFTBanMarker(marker) || !baseline.TableExists {
		return NFTCreateBatch{}, fault.Invalid("宿主机动作空表事务标识或基线无效")
	}
	return prepareNFTTransaction(NFTFail2banInput, nil, baseline, marker, true, true)
}

func validNFTBanMarker(marker string) bool {
	return len(marker) >= 32 && len(marker) <= 192 && strings.HasPrefix(marker, "nginxpanel:fail2ban:") && !strings.ContainsAny(marker, "\x00\r\n")
}
