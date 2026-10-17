package agent

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"golang.org/x/sys/unix"
	"nginxpanel/internal/firewall"
	"nginxpanel/internal/secure"
)

type ufwFileCommit struct {
	Family, CandidateID, PreviousID, Phase string
	Original                               dnsFile
	Candidate, Previous                    *dnsFile
}

func ufwPersistentSource(family string) (string, error) {
	if family == "ipv4" {
		return "/etc/ufw/user.rules", nil
	}
	if family == "ipv6" {
		return "/etc/ufw/user6.rules", nil
	}
	return "", errors.New("UFW 持久文件地址族无效")
}

func ufwPersistentTemp(id string) string {
	return filepath.Join("/etc/ufw", ".nginxpanel-ufw-"+id+".tmp")
}

func validUFWConfirmationSource(source string) bool {
	peer, err := netip.ParseAddr(source)
	return err == nil && !peer.IsLoopback() && !peer.IsUnspecified() && !peer.Is4In6() && peer.Zone() == "" && peer.String() == source
}

func validUFWFileImage(file dnsFile) bool {
	if file.UID != 0 || file.Mode&^uint32(0777) != 0 || file.Mode&0022 != 0 || file.Ino == 0 || file.Xattrs == nil || len(file.Data) == 0 || len(file.Data) > firewall.UFWReadBytes || !utf8.Valid(file.Data) || bytes.IndexByte(file.Data, 0) >= 0 {
		return false
	}
	total := 0
	for name, value := range file.Xattrs {
		total += len(name) + len(value)
		if name == "" || len(name) > 255 || strings.ContainsRune(name, 0) || !utf8.ValidString(name) || total > 8192 {
			return false
		}
	}
	return true
}

func ufwSnapshotMatchesFile(snapshot ufwFileSnapshot, file dnsFile) bool {
	return snapshot.Present && snapshot.Hash == secure.Hash(file.Data) && snapshot.Bytes == int64(len(file.Data)) && snapshot.Device == file.Dev && snapshot.Inode == file.Ino && snapshot.Mode == file.Mode && snapshot.Modified == file.Mtime
}

func validateUFWFileCommits(v *ufwChangeCheckpoint, seen map[string]bool) error {
	invalid := errors.New("UFW 持久文件意图或原文件属性无效")
	if len(v.Files) != len(v.Transition.Materials) {
		return invalid
	}
	for index, file := range v.Files {
		material := v.Transition.Materials[index]
		if file.Family != material.Family || !validID(file.CandidateID) || !validID(file.PreviousID) || seen[file.CandidateID] || seen[file.PreviousID] || file.CandidateID == file.PreviousID || !validUFWFileImage(file.Original) || !bytes.Equal(file.Original.Data, material.Before) {
			return invalid
		}
		seen[file.CandidateID], seen[file.PreviousID] = true, true
		path, _ := ufwPersistentSource(file.Family)
		found := false
		for _, snapshot := range v.Transition.Files {
			if snapshot.Path == path {
				found = ufwSnapshotMatchesFile(snapshot, file.Original)
			}
		}
		if !found {
			return invalid
		}
		if (file.Candidate != nil || file.Phase == "preparing_candidate") && !validUFWConfirmationSource(v.Operation.ConfirmedSource) {
			return errors.New("UFW 候选持久文件缺少原新连接确认")
		}
		if file.Previous != nil || file.Phase == "preparing_previous" {
			if !v.Rollback || file.Candidate == nil {
				return errors.New("UFW 原持久文件恢复缺少候选安装意图")
			}
		}
		if v.Operation.State == "succeeded" && (file.Candidate == nil || file.Previous != nil || file.Phase != "candidate_installed") {
			return errors.New("UFW 确认结果缺少全部持久文件安装回执")
		}
		for position, image := range []*dnsFile{file.Candidate, file.Previous} {
			if image == nil {
				continue
			}
			expected := file.Original
			if position == 0 {
				expected.Data = material.After
			}
			if !validUFWFileImage(*image) || !sameDNSFile(expected, *image) {
				return invalid
			}
		}
		switch file.Phase {
		case "idle", "preparing_candidate":
			if file.Candidate != nil || file.Previous != nil {
				return invalid
			}
		case "candidate_prepared", "candidate_installed":
			if file.Candidate == nil || file.Previous != nil {
				return invalid
			}
		case "preparing_previous":
			if file.Previous != nil {
				return invalid
			}
		case "previous_prepared", "previous_installed":
			if file.Previous == nil {
				return invalid
			}
		default:
			return invalid
		}
	}
	return nil
}

func captureUFWFileCommits(ctx context.Context, v *ufwChangeCheckpoint) error {
	for _, material := range v.Transition.Materials {
		if err := ctx.Err(); err != nil {
			return err
		}
		path, _ := ufwPersistentSource(material.Family)
		original, err := readProtectedTextFile(path, firewall.UFWReadBytes)
		if err != nil || !bytes.Equal(original.Data, material.Before) {
			return errors.New("UFW 受理前无法完整保存原用户文件及属性")
		}
		file := ufwFileCommit{Family: material.Family, CandidateID: secure.ID(), PreviousID: secure.ID(), Phase: "idle", Original: original}
		for _, id := range []string{file.CandidateID, file.PreviousID} {
			if _, err := os.Lstat(ufwPersistentTemp(id)); !os.IsNotExist(err) {
				return errors.New("UFW 本次持久临时文件已存在或无法核对")
			}
		}
		v.Files = append(v.Files, file)
	}
	return nil
}

func syncUFWDirectory() error {
	fd, err := unix.Open("/etc/ufw", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), "/etc/ufw")
	defer f.Close()
	return f.Sync()
}

func prepareUFWPersistentFile(id string, desired dnsFile) (dnsFile, error) {
	var out dnsFile
	if !validID(id) {
		return out, errors.New("UFW 持久文件操作 ID 无效")
	}
	path := ufwPersistentTemp(id)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return out, err
	}
	defer f.Close()
	if err = writeProtectedTextFile(f, desired); err != nil {
		return out, err
	}
	if err = f.Close(); err != nil {
		return out, err
	}
	out, err = readProtectedTextFile(path, firewall.UFWReadBytes)
	if err != nil || !sameDNSFile(out, desired) {
		return out, errors.New("UFW 持久临时文件内容或属性未完整核对")
	}
	return out, syncUFWDirectory()
}

// A prepared inode is published before rename, making a missing reply
// distinguishable from an unrelated file with the same textual configuration.
func installUFWPersistentFile(source, id string, expected, prepared dnsFile) error {
	current, err := readProtectedTextFile(source, firewall.UFWReadBytes)
	if err != nil || current.hash() != expected.hash() {
		return errors.New("UFW 持久目标在替换前变化，禁止覆盖")
	}
	temp := ufwPersistentTemp(id)
	image, err := readProtectedTextFile(temp, firewall.UFWReadBytes)
	if err != nil || image.hash() != prepared.hash() {
		return errors.New("UFW 原持久临时文件身份或内容变化")
	}
	if err = os.Rename(temp, source); err != nil {
		return err
	}
	if err = syncUFWDirectory(); err != nil {
		return err
	}
	current, err = readProtectedTextFile(source, firewall.UFWReadBytes)
	if err != nil || current.hash() != prepared.hash() {
		return errors.New("UFW 原持久文件替换结果未核对")
	}
	return nil
}

func cleanUFWPersistentTemp(id string, prepared *dnsFile) error {
	if !validID(id) {
		return errors.New("UFW 持久临时文件操作 ID 无效")
	}
	path := ufwPersistentTemp(id)
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || stat.Uid != 0 || stat.Nlink != 1 || info.Mode().Perm()&0022 != 0 || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || info.Size() > firewall.UFWReadBytes {
		return errors.New("UFW 原持久临时文件属性无法核对，保留现场")
	}
	if prepared != nil {
		current, err := readProtectedTextFile(path, firewall.UFWReadBytes)
		if err != nil || current.hash() != prepared.hash() {
			return errors.New("UFW 原持久临时文件与准备回执不一致，保留现场")
		}
	}
	if err = os.Remove(path); err != nil {
		return err
	}
	return syncUFWDirectory()
}

// Caller holds ufw-business.lock. Candidate persistence is admitted only after
// a durable new-connection confirmation; compensation never renews its deadline.
func persistUFWFilesLocked(ctx context.Context, dataDir string, v *ufwChangeCheckpoint, target string) error {
	if target != "candidate" && target != "previous" {
		return errors.New("UFW 持久文件目标无效")
	}
	if target == "candidate" {
		if !validUFWConfirmationSource(v.Operation.ConfirmedSource) || v.Rollback || v.Operation.State != "running" || v.Operation.Stage != "persisting_confirmed" || v.Operation.Deadline <= time.Now().Unix() {
			return errors.New("UFW 候选文件尚未取得有效的新连接确认")
		}
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, time.Unix(v.Operation.Deadline, 0))
		defer cancel()
	} else if !v.Rollback || !slices.Contains([]string{"compensating", "recovery_required"}, v.Operation.State) {
		return errors.New("UFW 原持久文件尚未进入补偿状态")
	}
	unlock, err := (&Journal{Dir: "/run/nginxpanel-host"}).rootLock("firewall-registration.lock")
	if err != nil {
		return err
	}
	defer unlock()
	manager, err := lockUFWManager()
	if err != nil {
		return err
	}
	defer manager.Close()
	parent, err := loadUFWReceipt(dataDir, v.Operation.ID)
	if err != nil || !ufwChangeReceiptMatches(parent, v) || ufwRestoreProcessPending(dataDir) {
		return errors.New("UFW 原业务回执或子进程尚未完成核对")
	}
	if err = checkUFWChangeSources(ctx, dataDir, v); err != nil {
		return err
	}
	if target == "candidate" {
		for _, material := range v.Transition.Materials {
			image, err := readUFWTransitionKernel(ctx, &v.Transition, material.Family, dataDir)
			if err != nil || !sameUFWReloadImage(image, material.AfterKernel) {
				return errors.New("UFW 候选内核状态未核对，禁止持久化")
			}
		}
	}
	for index := range v.Files {
		if err = ctx.Err(); err != nil {
			return err
		}
		file := &v.Files[index]
		path, _ := ufwPersistentSource(file.Family)
		current, err := readProtectedTextFile(path, firewall.UFWReadBytes)
		if err != nil {
			return err
		}
		prepared, id, data := file.Candidate, file.CandidateID, v.Transition.Materials[index].After
		if target == "previous" {
			prepared, id, data = file.Previous, file.PreviousID, file.Original.Data
		}
		if prepared != nil && current.hash() == prepared.hash() || target == "previous" && current.hash() == file.Original.hash() {
			if prepared != nil && current.hash() == prepared.hash() && file.Phase != target+"_installed" {
				file.Phase = target + "_installed"
				if err = saveUFWChange(dataDir, v); err != nil {
					return err
				}
			}
			if err = errors.Join(cleanUFWPersistentTemp(file.CandidateID, file.Candidate), cleanUFWPersistentTemp(file.PreviousID, file.Previous)); err != nil {
				return err
			}
			continue
		}
		expected := file.Original
		if target == "previous" {
			if file.Candidate == nil {
				return errors.New("UFW 当前持久文件无本操作安装证明，禁止恢复覆盖")
			}
			expected = *file.Candidate
		}
		if current.hash() != expected.hash() {
			return errors.New("UFW 持久文件存在外部修改，禁止覆盖")
		}
		if prepared == nil {
			// A crash may leave an incomplete temporary inode before its
			// preparation receipt. Only this frozen, previously absent path
			// may be cleaned and recreated; published inodes are never reused.
			if file.Phase == "preparing_"+target {
				if err = cleanUFWPersistentTemp(id, nil); err != nil {
					return err
				}
			}
			file.Phase = "preparing_" + target
			if err = saveUFWChange(dataDir, v); err != nil {
				return err
			}
			desired := file.Original
			desired.Data = data
			image, err := prepareUFWPersistentFile(id, desired)
			if err != nil {
				return err
			}
			prepared = &image
			if target == "candidate" {
				file.Candidate = prepared
			} else {
				file.Previous = prepared
			}
			file.Phase = target + "_prepared"
			if err = saveUFWChange(dataDir, v); err != nil {
				return err
			}
		}
		if err = ctx.Err(); err != nil {
			return err
		}
		if err = verifyUFWManagerLock(manager); err != nil {
			return err
		}
		if err = installUFWPersistentFile(path, id, expected, *prepared); err != nil {
			return err
		}
		file.Phase = target + "_installed"
		if err = saveUFWChange(dataDir, v); err != nil {
			return err
		}
		if target == "previous" {
			if err = cleanUFWPersistentTemp(file.CandidateID, file.Candidate); err != nil {
				return err
			}
		}
	}
	if err = checkUFWChangeSources(ctx, dataDir, v); err != nil {
		return err
	}
	if err = checkUFWPersistentFiles(ctx, v, target); err != nil {
		return err
	}
	if target == "candidate" {
		for _, material := range v.Transition.Materials {
			image, err := readUFWTransitionKernel(ctx, &v.Transition, material.Family, dataDir)
			if err != nil || !sameUFWReloadImage(image, material.AfterKernel) {
				return errors.New("UFW 持久化后的完整候选内核状态未核对")
			}
		}
	}
	if err = verifyUFWManagerLock(manager); err != nil {
		return err
	}
	return ctx.Err()
}

func checkUFWPersistentFiles(ctx context.Context, v *ufwChangeCheckpoint, target string) error {
	if target != "candidate" && target != "previous" {
		return errors.New("UFW 持久文件核对目标无效")
	}
	for _, file := range v.Files {
		if err := ctx.Err(); err != nil {
			return err
		}
		path, _ := ufwPersistentSource(file.Family)
		current, err := readProtectedTextFile(path, firewall.UFWReadBytes)
		if err != nil {
			return err
		}
		if target == "candidate" {
			if file.Candidate == nil || current.hash() != file.Candidate.hash() {
				return errors.New("UFW 最终候选持久文件未完整核对")
			}
		} else if current.hash() != file.Original.hash() && (file.Previous == nil || current.hash() != file.Previous.hash()) {
			return errors.New("UFW 最终原持久文件未完整核对")
		}
	}
	return nil
}

func checkUFWChangeSources(ctx context.Context, dataDir string, v *ufwChangeCheckpoint) error {
	authority, err := ufwRegistrationAuthority(dataDir)
	if err != nil || authority.NextClaim.Owner != v.Transition.Owner || authority.NextClaim.MachineHash != v.Transition.MachineHash || authority.NextClaim.OperationID != v.Transition.RegistrationOperationID {
		return errors.New("UFW 原业务的宿主机授权发生变化")
	}
	binary, err := ufwTool()
	if err != nil || binary != v.Transition.Tools.Files[0].File.Path {
		return errors.New("UFW 原 CLI 路径发生变化")
	}
	configuration, err := readUFWConfiguration(ctx, binary, v.Transition.IPv6)
	if err != nil || len(configuration.Files) != len(v.Transition.Files) {
		return errors.New("UFW 固定配置清单无法完整读取")
	}
	for index, observed := range configuration.Files {
		matched := false
		for _, file := range v.Files {
			path, _ := ufwPersistentSource(file.Family)
			if path != observed.Path {
				continue
			}
			current, err := readProtectedTextFile(path, firewall.UFWReadBytes)
			if err != nil || !ufwSnapshotMatchesFile(observed, current) {
				return errors.New("UFW 用户文件在完整源核对期间变化")
			}
			for _, allowed := range []*dnsFile{&file.Original, file.Candidate, file.Previous} {
				matched = matched || allowed != nil && current.hash() == allowed.hash()
			}
			if !matched {
				return errors.New("UFW 用户文件不属于原文件或本次持久化回执，禁止覆盖")
			}
		}
		if !matched && observed != v.Transition.Files[index] {
			return errors.New("UFW 固定源配置发生外部变化，禁止覆盖")
		}
	}
	return v.Transition.Tools.verify(ctx)
}
