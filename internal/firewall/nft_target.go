package firewall

import "errors"

// NFTTarget is a closed set of independently owned tables. It is never decoded
// from a caller-supplied table, chain, hook or priority.
type NFTTarget uint8

const (
	NFTPortInput NFTTarget = iota
	NFTFail2banInput
)

const NFTFail2banTable = "nginxpanel_fail2ban"
const NFTFail2banPriority = -10

type NFTLayout struct {
	Table, Chain string
	Priority     int
}

func (t NFTTarget) Layout() (NFTLayout, error) {
	switch t {
	case NFTPortInput:
		return NFTLayout{NFTHostTable, NFTHostChain, NFTHostPriority}, nil
	case NFTFail2banInput:
		return NFTLayout{NFTFail2banTable, "input", NFTFail2banPriority}, nil
	default:
		return NFTLayout{}, errors.New("unsupported fixed nftables target")
	}
}
