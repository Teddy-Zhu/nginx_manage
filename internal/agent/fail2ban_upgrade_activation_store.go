package agent

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
	"nginxpanel/internal/secure"
)

func readFail2banUpgradeActivationJSON(path string, out any) error {
	raw, err := listenerRead(path, fail2banUpgradeActivationLimit)
	if err != nil {
		return err
	}
	if err = decodeFail2banNginxJSON(raw, out); err != nil {
		return err
	}
	canonical, err := json.Marshal(out)
	if err != nil || !bytes.Equal(raw, canonical) {
		return errors.New("升级启动材料格式或字段变化")
	}
	return nil
}

func writeFail2banUpgradeActivationJSON(path string, value any) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return writeFail2banJailImmutable(path, raw, fail2banUpgradeActivationLimit)
}

// Intent decoding is separate so a failed candidate recovery can require the
// original switch branch before following any recovery source reference.
func readFail2banUpgradeActivationIntent(data, id string) (fail2banUpgradeActivationIntent, error) {
	var i fail2banUpgradeActivationIntent
	if !validID(id) {
		return i, errors.New("升级启动 UUID 无效")
	}
	dir := filepath.Join(fail2banUpgradeActivations(data), id)
	if err := fail2banStatePrivateDir(dir, false); err != nil {
		return i, err
	}
	if err := readFail2banUpgradeActivationJSON(filepath.Join(dir, "intent.json"), &i); err != nil {
		return i, err
	}
	return i, nil
}

func readFail2banUpgradeActivation(data, id string) (fail2banUpgradeActivationIntent, fail2banUpgradeSelection, error) {
	var s fail2banUpgradeSelection
	i, err := readFail2banUpgradeActivationIntent(data, id)
	if err != nil {
		return i, s, err
	}
	s, err = readFail2banUpgradeSelection(data, i.Request.SwitchID, i.Request.RestoreID)
	if err != nil {
		return i, s, err
	}
	return i, s, i.validate(data, id, s)
}

func (i fail2banUpgradeActivationIntent) facts() (f fail2banUpgradeActivationFacts, err error) {
	read := func(name string, out any) (bool, error) {
		e := readFail2banUpgradeActivationJSON(filepath.Join(i.dir(), name), out)
		if os.IsNotExist(e) {
			return false, nil
		}
		return e == nil, e
	}
	var execution fail2banUpgradeActivationMarker
	if f.Execution, err = read("execution.json", &execution); err != nil {
		return f, err
	}
	if f.Execution && execution != i.marker() {
		return f, errors.New("升级启动执行标识不匹配")
	}
	var claim fail2banUpgradeActivationClaim
	if present, e := read("prestart.json", &claim); e != nil {
		return f, e
	} else if present {
		if !f.Execution || claim.fail2banUpgradeActivationMarker != i.marker() || claim.At < i.CreatedAt || claim.At > i.deadline() || claim.At > time.Now().Unix()+300 || !fail2banInvocation.MatchString(claim.Invocation) || !validID(claim.Nonce) {
			return f, errors.New("升级服务启动许可无效")
		}
		f.Claim = &claim
	}
	var started fail2banUpgradeActivationStarted
	if present, e := read("started.json", &started); e != nil {
		return f, e
	} else if present {
		if f.Claim == nil || started.fail2banUpgradeActivationMarker != i.marker() || started.At < f.Claim.At || started.At > time.Now().Unix()+300 || started.Invocation != f.Claim.Invocation || started.SocketInode == "" || started.PID < 2 {
			return f, errors.New("升级启动运行回执无效")
		}
		inode, e := strconv.ParseUint(started.SocketInode, 10, 64)
		if e != nil || inode == 0 || started.At > i.deadline() {
			return f, errors.New("升级启动 Socket 或观测时间无效")
		}
		f.Started = &started
	}
	var stop fail2banUpgradeActivationStop
	if present, e := read("stop.json", &stop); e != nil {
		return f, e
	} else if present {
		if stop.fail2banUpgradeActivationMarker != i.marker() || stop.At < i.CreatedAt || stop.At > time.Now().Unix()+300 || f.Claim != nil && stop.At < f.Claim.At || f.Started != nil && stop.At < f.Started.At || stop.Reason != "cancelled" && stop.Reason != "start_failed" && stop.Reason != "start_unconfirmed" && stop.Reason != "protection_timeout" {
			return f, errors.New("升级启动停止意图无效")
		}
		f.Stop = &stop
	}
	var receipt fail2banUpgradeActivationReceipt
	if present, e := read("receipt.json", &receipt); e != nil {
		return f, e
	} else if present {
		if receipt.fail2banUpgradeActivationMarker != i.marker() || receipt.CompletedAt < i.CreatedAt || receipt.CompletedAt > time.Now().Unix()+300 {
			return f, errors.New("升级启动完成回执无效")
		}
		switch receipt.Outcome {
		case "verified":
			if f.Started == nil || f.Stop != nil || receipt.Stopped != nil {
				return f, errors.New("保护完成与候选启动或停止意图冲突")
			}
			v, _, e := readFail2banUpgradeVerification(i.Request.DataDir, i.VerificationID)
			if e != nil {
				return f, e
			}
			if e = i.checkProof(v, *f.Started); e != nil {
				return f, e
			}
			if receipt.VerificationSHA256 != v.hash() || receipt.CompletedAt != v.CreatedAt {
				return f, errors.New("升级启动完成未绑定原保护证明")
			}
			audit, e := (&Journal{Dir: filepath.Join(i.Request.DataDir, "agent", "operations")}).Get(i.VerificationID)
			if e != nil || !sameFail2banUpgradePreparationRecord(audit, v.record()) {
				return f, errors.Join(errors.New("升级启动缺少保护证明的独立审计"), e)
			}
		case "stopped":
			if f.Stop == nil || receipt.VerificationSHA256 != "" || receipt.CompletedAt < f.Stop.At || receipt.Stopped == nil {
				return f, errors.New("候选停止回执与原意图不匹配")
			}
			stopped := receipt.Stopped
			service := stopped.Service
			if !service.Available || service.ID != fail2banManagedService || service.Load != "loaded" || service.MainPID == nil || *service.MainPID != 0 || service.Active != "inactive" && service.Active != "failed" || stopped.Invocation != "" && !fail2banInvocation.MatchString(stopped.Invocation) || stopped.Directory.Inode == 0 || !fail2banDigest.MatchString(stopped.FilesSHA256) {
				return f, errors.New("候选停止回执缺少明确的服务及数据库观察")
			}
		default:
			return f, errors.New("升级启动完成结果未知")
		}
		f.Receipt = &receipt
	}
	return f, nil
}

func (i fail2banUpgradeActivationIntent) checkProof(v fail2banUpgradeVerification, started fail2banUpgradeActivationStarted) error {
	if v.Request != i.verification() || v.CreatedAt < started.At || v.CreatedAt > i.deadline() || v.Recovery.Invocation != started.Invocation || v.Managed.EventID != i.SelectedEvent {
		return errors.New("升级保护证明并非原受控启动的运行代次或授权时限")
	}
	if v.Nginx != nil && (v.Nginx.SocketInode != started.SocketInode || v.Nginx.RuntimeSHA256 != i.NginxRuntimeSHA256) {
		return errors.New("升级保护证明的 Socket 或 Nginx 运行来源变化")
	}
	return nil
}

func fail2banUpgradeActivationQuota(store string, add bool) error {
	entries, err := os.ReadDir(store)
	if err != nil {
		return err
	}
	count := 0
	for _, e := range entries {
		if e.Name() != "current.json" {
			count++
		}
	}
	if add {
		count++
	}
	if count > 8 {
		return errors.New("升级启动材料已达 8 项上限，须本机维护")
	}
	var total int64
	budget := int64((1 << 20) - (6 * fail2banUpgradeActivationLimit))
	if add {
		budget = (1 << 20) - (8 * fail2banUpgradeActivationLimit)
	}
	files := 0
	return filepath.WalkDir(store, func(path string, e fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == store {
			return nil
		}
		relative, err := filepath.Rel(store, path)
		if err != nil {
			return err
		}
		files++
		if files > 160 || strings.Count(relative, string(filepath.Separator)) > 1 {
			return errors.New("升级启动材料数量或层级超限")
		}
		if e.IsDir() {
			return fail2banStatePrivateDir(path, false)
		}
		f, info, err := secure.OpenRootFile(path, fail2banUpgradeActivationLimit)
		if err != nil {
			return err
		}
		if err = f.Close(); err != nil {
			return err
		}
		if info.Mode().Perm() != 0600 {
			return errors.New("升级启动材料须为 root 专用 0600 文件")
		}
		total += info.Size()
		if total > budget {
			return errors.New("升级启动材料无法在 1 MiB 内保留完成与原子写入空间")
		}
		return nil
	})
}

func reserveFail2banUpgradeActivation(i fail2banUpgradeActivationIntent) (resultErr error) {
	store := fail2banUpgradeActivations(i.Request.DataDir)
	if err := fail2banStatePrivateDir(store, true); err != nil {
		return err
	}
	if err := syncDir(filepath.Dir(store)); err != nil {
		return err
	}
	if err := fail2banUpgradeActivationQuota(store, true); err != nil {
		return err
	}
	tmp, err := os.MkdirTemp(store, ".activation-")
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, os.RemoveAll(tmp)) }()
	if err = writeFail2banUpgradeActivationJSON(filepath.Join(tmp, "intent.json"), i); err != nil {
		return err
	}
	if err = syncDir(tmp); err != nil {
		return err
	}
	if err = unix.Renameat2(unix.AT_FDCWD, tmp, unix.AT_FDCWD, i.dir(), unix.RENAME_NOREPLACE); err != nil {
		return err
	}
	return syncDir(store)
}
