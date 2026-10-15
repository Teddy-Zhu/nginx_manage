package nginxruntime

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
	"nginxpanel/internal/secure"
)

// LockSelection serializes native and container installation admission for the
// same dedicated Nginx slot. The caller must re-read the selection while held.
func LockSelection(data string) (func(), error) {
	name, err := bindingPath(data)
	if err != nil {
		return nil, err
	}
	if os.Geteuid() != 0 {
		return nil, errors.New("安装绑定写入需要本机 root")
	}
	if err = secure.RootDirectory(filepath.Dir(name), 0755); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(filepath.Dir(name), ".binding.lock"), os.O_CREATE|os.O_RDWR|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0600)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err == nil {
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || st.Uid != 0 || st.Nlink != 1 {
			err = errors.New("安装绑定锁不可信")
		}
	}
	if err == nil {
		err = unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
	}
	if err != nil {
		f.Close()
		return nil, err
	}
	return func() { unix.Flock(int(f.Fd()), unix.LOCK_UN); f.Close() }, nil
}

func SelectionHash(b Binding) string { raw, _ := json.Marshal(b); return secure.Hash(raw) }

// InstallPrepared is a first installation, never an existing runtime switch.
// The caller must hold the durable maintenance grant and installation journal.
func InstallPrepared(ctx context.Context, in Input, operationID, beforeSHA256 string, approved Binding) (Binding, error) {
	if !installationID.MatchString(operationID) || !digest.MatchString(beforeSHA256) || in.Binary != "" || in.Uninstalled || in.PlanID == "" || in.AssetID == "" {
		return Binding{}, errors.New("首次安装请求无效")
	}
	if err := in.Validate(); err != nil {
		return Binding{}, err
	}
	unlock, err := LockSelection(in.DataDir)
	if err != nil {
		return Binding{}, err
	}
	defer unlock()
	current, _, err := Selection(ctx, in.DataDir)
	if err != nil {
		return Binding{}, err
	}
	if current.OperationID == operationID && matches(current, in) && CandidateHash(current) == CandidateHash(approved) {
		return current, nil
	}
	if current.Owner != "uninstalled" || SelectionHash(current) != beforeSHA256 {
		return Binding{}, errors.New("未安装登记已变化，拒绝替换当前选择")
	}
	b, err := Admit(ctx, in)
	if err != nil {
		return Binding{}, err
	}
	if CandidateHash(b) != CandidateHash(approved) {
		return Binding{}, errors.New("首次安装候选与已确认资产不同")
	}
	b.OperationID = operationID
	return publishBinding(ctx, b, true)
}

func CandidateHash(b Binding) string { b.BoundAt = 0; b.OperationID = ""; return SelectionHash(b) }
