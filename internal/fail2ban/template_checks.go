package fail2ban

import (
	"errors"
	"net/netip"
	"path/filepath"
	"slices"
	"strings"
)

func NewTemplateCheck(id string) TemplateCheck {
	filter, samples := FilterIdentity(id)
	return TemplateCheck{Template: id, FilterSHA256: filter, SamplesSHA256: samples, ExpectedIPs: ExpectedSampleIPs(id), MatchedIPs: []string{}}
}
func ValidateTemplateChecks(in TemplateCheckInput, checks []TemplateCheck) error {
	normalized, err := in.Normalize()
	if err != nil {
		return err
	}
	if len(checks) != len(normalized.Templates) {
		return errors.New("invalid Fail2ban template result count")
	}
	for i, c := range checks {
		want := NewTemplateCheck(normalized.Templates[i])
		if c.Template != want.Template || c.At <= 0 || c.FilterSHA256 != want.FilterSHA256 || c.SamplesSHA256 != want.SamplesSHA256 || !slices.Equal(c.ExpectedIPs, want.ExpectedIPs) || c.ExpectedIPs == nil || c.MatchedIPs == nil || len(c.MatchedIPs) > len(FilterSamples(c.Template)) || len(c.Reason) > 1024 || len(c.ToolVersion) > 64 || len(c.Scope) > 32 || c.Scope == "" || c.Source != "host-agent" && c.Source != "development-agent" {
			return errors.New("invalid Fail2ban template identity")
		}
		if c.Available {
			if c.Scope != "host" || c.Source != "host-agent" || c.ToolVersion != RegexVersion || len(c.ToolSHA256) != 64 || strings.Trim(c.ToolSHA256, "0123456789abcdef") != "" || !filepath.IsAbs(c.ToolPath) || filepath.Clean(c.ToolPath) != c.ToolPath || len(c.ToolPath) > 512 || c.Passed != slices.Equal(c.ExpectedIPs, c.MatchedIPs) || c.Passed && c.Reason != "" || !c.Passed && c.Reason == "" {
				return errors.New("invalid Fail2ban template verification")
			}
		} else if c.Passed || len(c.MatchedIPs) > 0 || c.Reason == "" {
			return errors.New("invalid unavailable Fail2ban template result")
		}
		for _, ip := range c.MatchedIPs {
			addr, err := netip.ParseAddr(ip)
			if err != nil || addr.Zone() != "" || addr.Unmap().String() != ip {
				return errors.New("invalid Fail2ban template address")
			}
		}
	}
	return nil
}
