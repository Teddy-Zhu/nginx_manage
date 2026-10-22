package agent

import "testing"

func TestNMIPv6AddressReadiness(t *testing.T) {
	const stable = "fd420005000000000000000000000011 03 40 00 80 enp0s3\n"
	const tentative = "fd420005000000000000000000000012 03 40 00 40 enp0s3\n"
	const failed = "fd420005000000000000000000000013 03 40 00 48 enp0s3\n"
	for _, tc := range []struct {
		name, data  string
		ready, fail bool
	}{
		{"stable", stable, true, false},
		{"tentative", stable + tentative, false, false},
		{"failure-after-tentative", tentative + failed, false, true},
		{"other-interface", stable + "fd420005000000000000000000000014 04 40 00 48 p5wg0\n", true, false},
		{"no-addresses", "", true, false},
		{"invalid-flags", "fd420005000000000000000000000011 03 40 00 invalid enp0s3\n", false, true},
		{"invalid-record", "invalid\n", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ready, err := nmIPv6AddressesReady(tc.data, "enp0s3")
			if ready != tc.ready || (err != nil) != tc.fail {
				t.Fatalf("ready=%v error=%v", ready, err)
			}
		})
	}
}
