package agent

import (
	"bytes"
	"errors"
	"path/filepath"
	"strings"

	"nginxpanel/internal/hostdns"
)

func (d *HostDNS) netplanPersistSource() error {
	c, n := d.checkpoint, d.checkpoint.Netplan
	if _, err := d.netplanSourcesCheck(false); err != nil {
		return err
	}
	if _, err := networkDirectoryState(filepath.Dir(n.File)); err != nil {
		return err
	}
	current, err := readDNSFile(n.File)
	if err != nil {
		return err
	}
	if !sameDNSFile(current, n.Before) {
		return errors.New("netplan source changed before persistence")
	}
	return writeHostDNSFile(n.File, current, n.After, c.Status.OperationID)
}

func (d *HostDNS) netplanRestoreSource() error {
	c, n := d.checkpoint, d.checkpoint.Netplan
	if _, err := networkDirectoryState(filepath.Dir(n.File)); err != nil {
		return err
	}
	current, err := readDNSFile(n.File)
	if err != nil {
		return err
	}
	if sameDNSFile(current, n.Before) {
		return nil
	}
	if !sameDNSFile(current, n.After) {
		return errors.New("external netplan source change prevents automatic restoration")
	}
	// Restore the upstream source before waiting for an uncertain D-Bus call.
	// A reboot must not regenerate an unconfirmed persistent candidate.
	return writeHostDNSFile(n.File, current, n.Before, c.Status.OperationID)
}

func (c *dnsCheckpoint) validateNetplan() error {
	n := c.Netplan
	if n == nil || c.Networkd == nil || c.NM != nil || c.Plan.Owner != "netplan" || !hostdns.NetworkdTarget(c.Plan.Input.Target) || n.ProfileHash != "" || n.AppliedHash != "" || n.WrittenHash != "" {
		return errors.New("invalid netplan recovery identity")
	}
	iface := strings.TrimPrefix(c.Plan.Input.Target, "networkd:")
	id, generated := netplanGeneratedID("networkd", c.Networkd.File)
	if !generated || id != iface || c.Networkd.Base != c.Networkd.File {
		return errors.New("netplan generated recovery file does not identify its link")
	}
	if err := c.validateNetplanSource(iface, c.Plan.Input.Config, c.Networkd.Routes); err != nil {
		return err
	}
	before, e1 := stripNetworkDNS(c.Before.Data)
	after, e2 := stripNetworkDNS(c.After.Data)
	if e1 != nil || e2 != nil || !bytes.Equal(before, after) {
		return errors.New("netplan generated snapshot changes non-DNS configuration")
	}
	for i, file := range []dnsFile{c.Before, c.After} {
		projection, err := networkDNSProjection([]networkSource{{Path: c.Networkd.File, File: file}})
		config := c.Plan.Before
		if i == 1 {
			config = c.Plan.Input.Config
		}
		expected := networkConfigState(config, c.Networkd.Routes)
		if err != nil || projection == nil || !networkSame(&expected, ptrNetworkConfigState(projection)) {
			return errors.New("netplan generated DNS differs from the approved plan")
		}
	}
	return nil
}

func (c *dnsCheckpoint) validateNetplanSource(iface string, config hostdns.Config, routes []string) error {
	n := c.Netplan
	if n == nil || c.Plan.Owner != "netplan" || !netplanSnapshotPath(n.File) || filepath.Dir(n.File) != "/etc/netplan" || len(n.Sources) < 1 || len(n.Sources) > 64 || !filepath.IsAbs(n.Tool.Path) || len(n.Tool.Path) > 512 || !netplanProofHash(n.Tool.SHA256) {
		return errors.New("invalid netplan source identity")
	}
	for _, file := range []dnsFile{n.Before, n.After} {
		if file.UID != 0 || file.Mode&^uint32(0777) != 0 || file.Mode&0022 != 0 || len(file.Data) > hostdns.SourceLimit {
			return errors.New("invalid netplan source snapshot")
		}
	}
	seen := map[string]bool{}
	selected := false
	previous := ""
	for _, proof := range n.Sources {
		base := filepath.Base(proof.Path)
		if !netplanSnapshotPath(proof.Path) || seen[base] || previous != "" && previous >= base || len(proof.Hash) != 64 || strings.Trim(proof.Hash, "0123456789abcdef") != "" {
			return errors.New("invalid netplan source inventory proof")
		}
		seen[base], previous = true, base
		if proof.Path == n.File {
			selected = proof.Hash == n.Before.hash()
		}
	}
	if !selected {
		return errors.New("netplan snapshot is not in its frozen source inventory")
	}
	expected, err := renderNetplanDNS(n.Before.Data, iface, config, routes)
	want := n.Before
	want.Data = expected
	if err != nil || !sameDNSFile(want, n.After) {
		return errors.New("netplan source snapshot differs from the approved DNS edit")
	}
	return nil
}

func netplanProofHash(hash string) bool {
	return len(hash) == 64 && strings.Trim(hash, "0123456789abcdef") == ""
}
