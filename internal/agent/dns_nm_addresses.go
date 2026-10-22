package agent

import (
	"context"
	"errors"
	"os"
	"strconv"
	"strings"
	"time"
)

// Reapply may restart IPv6 duplicate address detection even for a DNS-only
// change. Its reply precedes address usability and installation of local routes.
func nmWaitIPv6Addresses(ctx context.Context, iface string) error {
	tick := time.NewTicker(250 * time.Millisecond)
	defer tick.Stop()
	for {
		data, err := os.ReadFile("/proc/net/if_inet6")
		if err != nil {
			return err
		}
		ready, err := nmIPv6AddressesReady(string(data), iface)
		if err != nil || ready {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
		}
	}
}

func nmIPv6AddressesReady(data, iface string) (bool, error) {
	ready := true
	for _, line := range strings.Split(data, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if len(fields) != 6 {
			return false, errors.New("invalid kernel IPv6 address state")
		}
		if fields[5] != iface {
			continue
		}
		flags, err := strconv.ParseUint(fields[4], 16, 32)
		if err != nil {
			return false, err
		}
		if flags&0x08 != 0 { // IFA_F_DADFAILED
			return false, errors.New("IPv6 duplicate address detection failed")
		}
		if flags&0x40 != 0 { // IFA_F_TENTATIVE
			ready = false
		}
	}
	return ready, nil
}
