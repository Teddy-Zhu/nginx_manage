package releases

import "testing"

func TestCompareVersions(t *testing.T) {
	for _, test := range []struct {
		current, target string
		want            int
	}{
		{"1.2.3", "1.2.10", -1},
		{"2.0.0", "1.9.9", 1},
		{"1.2.3", "1.2.3", 0},
		{"1.2.3+local", "1.2.3+release", 0},
		{"1.2.3-dev", "1.2.3", -1},
		{"1.2.3", "1.2.3-dev", 1},
		{"1.2.3-dev", "1.2.3-100.1-dev", -1},
		{"1.2.3-99.1-dev", "1.2.3-100.1-dev", -1},
		{"1.2.3-100.2-dev", "1.2.3-100.10-dev", -1},
		{"1.2.3-101.1-dev", "1.2.3-100.10-dev", 1},
		{"1.2.3-100.1-dev+build", "1.2.3-100.1-dev", 0},
		{"1.2.3-beta.2", "1.2.3-beta.10", -1},
		{"1.2.4-dev", "1.2.3", 1},
	} {
		t.Run(test.current+"/"+test.target, func(t *testing.T) {
			got, err := CompareVersions(test.current, test.target)
			if err != nil || got != test.want {
				t.Fatalf("got %d, %v; want %d", got, err, test.want)
			}
		})
	}
	for _, invalid := range []string{"", "unknown", "v1.2.3", "1.2", "1.02.3", "1.2.3-1.01-dev"} {
		if _, err := CompareVersions(invalid, "1.2.3"); err == nil {
			t.Fatalf("accepted invalid current version %q", invalid)
		}
		if _, err := CompareVersions("1.2.3", invalid); err == nil {
			t.Fatalf("accepted invalid target version %q", invalid)
		}
	}
}
