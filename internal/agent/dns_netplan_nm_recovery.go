package agent

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"strings"

	"nginxpanel/internal/hostdns"
	"nginxpanel/internal/secure"
)

func (d *HostDNS) netplanNMFileKnown(file dnsFile) bool {
	c := d.checkpoint
	return sameDNSFile(file, c.Before) || sameDNSFile(file, c.After) || c.Netplan.WrittenHash != "" && file.hash() == c.Netplan.WrittenHash
}

func (d *HostDNS) netplanNMSession(t *nmTarget) error {
	c, n := d.checkpoint, d.checkpoint.Netplan
	if nmNonDNSHash(t.Persistent) != n.ProfileHash || nmNonDNSHash(t.Applied) != n.AppliedHash {
		return errors.New("non-DNS connection settings changed")
	}
	file, err := readDNSFile(t.Filename)
	if err != nil || secure.Hash(file.Data) != t.FileHash || !d.netplanNMFileKnown(file) {
		return errors.New("netplan generated connection changed externally")
	}
	if c.NM.Method4 != t.View.Method4 || c.NM.Method6 != t.View.Method6 {
		return errors.New("netplan connection IP method changed")
	}
	return d.netplanSourceEither()
}

// The version-checked NM write can normalize a /run keyfile. Capture that
// completed write before consuming the pending intent, so recovery recognizes
// it while restoring the original or native candidate file atomically.
func (d *HostDNS) netplanNMCapture(b *dnsBus, previous *nmTarget, want nmDNS) error {
	n := d.checkpoint.NM
	if n.Pending == nil || !n.Pending.Persistent {
		return errors.New("missing netplan connection write intent")
	}
	next, err := openDNSBus(context.Background())
	if err != nil {
		return err
	}
	defer next.close()
	if next.busID != b.busID || next.owner != b.owner {
		return errors.New("NetworkManager changed during generated connection write")
	}
	t, err := nmFindSource(next, d.checkpoint.Plan.Input.Target, true)
	if err != nil {
		return err
	}
	if t.Profile != previous.Profile || t.Active != previous.Active || t.Filename != n.Filename || t.ProfileVersion <= n.Pending.Version || nmNonDNSHash(t.Persistent) != d.checkpoint.Netplan.ProfileHash || nmNonDNSHash(t.Applied) != d.checkpoint.Netplan.AppliedHash {
		return errors.New("generated connection write identity changed")
	}
	current, err := nmCapture(t.Persistent)
	if err != nil || !nmSame(current, want) {
		return errors.New("generated connection DNS write was not observed")
	}
	file, err := readDNSFile(t.Filename)
	if err != nil || file.Mode&0077 != 0 || secure.Hash(file.Data) != t.FileHash {
		return errors.New("generated connection write file cannot be confirmed")
	}
	attributes := d.checkpoint.Before
	attributes.Data = file.Data
	if !sameDNSFile(attributes, file) {
		return errors.New("generated connection file attributes changed")
	}
	if err = d.netplanNMObservedFile(file, t); err != nil {
		return err
	}
	if err = next.unchangedOwner(); err != nil {
		return err
	}
	d.checkpoint.Netplan.WrittenHash = file.hash()
	return d.persist()
}

func (d *HostDNS) netplanNMCanonical(persistent bool) error {
	c := d.checkpoint
	if _, err := networkDirectoryState(filepath.Dir(c.NM.Filename)); err != nil {
		return err
	}
	file, err := readDNSFile(c.NM.Filename)
	if err != nil {
		return err
	}
	if !d.netplanNMFileKnown(file) {
		return errors.New("external generated connection change prevents restoration")
	}
	want := c.Before
	if persistent {
		want = c.After
	}
	if sameDNSFile(file, want) {
		return nil
	}
	return writeHostDNSFile(c.NM.Filename, file, want, c.Status.OperationID)
}

func (d *HostDNS) netplanNMCheck(t *nmTarget, persistent bool) (string, error) {
	c := d.checkpoint
	s, err := d.netplanSourcesCheck(persistent)
	if err != nil {
		return "", err
	}
	file, err := readDNSFile(c.NM.Filename)
	want := c.Before
	if persistent {
		want = c.After
	}
	if err != nil || !sameDNSFile(file, want) || secure.Hash(file.Data) != t.FileHash {
		return "", errors.New("netplan generated connection persistence is unconfirmed")
	}
	return netplanViewHash(s, t.View.SourceHash), nil
}

func (c *dnsCheckpoint) validateNetplanNM() error {
	n := c.Netplan
	if n == nil || c.NM == nil || c.Networkd != nil || c.Plan.Owner != "netplan" || hostdns.NetworkdTarget(c.Plan.Input.Target) || !hostdns.ValidTarget(c.Plan.Input.Target) || !netplanProofHash(n.ProfileHash) || !netplanProofHash(n.AppliedHash) || n.WrittenHash != "" && !netplanProofHash(n.WrittenHash) {
		return errors.New("invalid netplan NetworkManager recovery identity")
	}
	parts := strings.SplitN(c.Plan.Input.Target, "@", 2)
	id, ok := netplanGeneratedID("NetworkManager", c.NM.Filename)
	if len(parts) != 2 || !ok || id != parts[1] {
		return errors.New("netplan generated connection does not identify its interface")
	}
	for _, file := range []dnsFile{c.Before, c.After} {
		if file.UID != 0 || file.Mode&^uint32(0777) != 0 || file.Mode&0077 != 0 || len(file.Data) > hostdns.SourceLimit {
			return errors.New("invalid netplan generated connection snapshot")
		}
	}
	want := c.Before
	want.Data = c.After.Data
	if !sameDNSFile(want, c.After) || !bytes.Equal(stripNetplanNMDNS(c.Before.Data), stripNetplanNMDNS(c.After.Data)) {
		return errors.New("netplan generated connection changes non-DNS fields")
	}
	_, routes, err := netplanNMFile(c.Before.Data)
	if err != nil {
		return err
	}
	settings, err := netplanNMFileSettings(c.Before.Data)
	if err != nil || nmString(settings, "ipv4", "method") != c.NM.Method4 || nmString(settings, "ipv6", "method") != c.NM.Method6 {
		return errors.New("netplan generated snapshot has different IP methods")
	}
	if err = netplanNMGeneratedMatches(c.Before, c.Plan.Before, routes); err != nil {
		return err
	}
	if err = netplanNMGeneratedMatches(c.After, c.Plan.Input.Config, routes); err != nil {
		return err
	}
	flat, err := netplanNMFlat(c.Plan.Input.Config)
	if err != nil {
		return err
	}
	return c.validateNetplanSource(parts[1], flat, routes)
}
