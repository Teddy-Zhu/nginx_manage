package agent

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
	"nginxpanel/internal/panelruntime"
	"nginxpanel/internal/secure"
)

func agentUpgradeSync(name string) error {
	f, err := os.Open(name)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}
func readAgentLink() (string, error) {
	if err := secure.RootDirectory(agentBootstrapRoot, 0755); err != nil {
		return "", err
	}
	name := filepath.Join(agentBootstrapRoot, "current")
	info, err := os.Lstat(name)
	if err != nil {
		return "", err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || info.Mode()&os.ModeSymlink == 0 || st.Uid != 0 || st.Nlink != 1 {
		return "", errors.New("Agent 程序指针不是 root 持有的独立链接")
	}
	link, err := os.Readlink(name)
	if err != nil {
		return "", err
	}
	if !agentProgramLinkValid(link) {
		return "", errors.New("Agent 程序指针超出固定发布目录")
	}
	return link, nil
}
func readAgentProgram() (AgentProgram, error) {
	link, err := readAgentLink()
	if err != nil {
		return AgentProgram{}, err
	}
	p := AgentProgram{Link: link}
	p.BinarySHA256, err = secure.HashRootFile(p.binary(), panelruntime.BinaryLimit)
	if err != nil {
		return AgentProgram{}, err
	}
	if !agentProgramValid(p) {
		return AgentProgram{}, errors.New("Agent 程序文件或选择身份无效")
	}
	return p, nil
}
func readCoreProgram(data string) (AgentProgram, error) {
	snapshot, err := panelruntime.Read(data)
	if err != nil {
		return AgentProgram{}, err
	}
	p := AgentProgram{
		Link:         "core-releases/" + snapshot.Release.ID,
		DataDir:      data,
		BinarySHA256: snapshot.Release.BinarySHA256,
	}
	if !agentProgramValid(p) {
		return AgentProgram{}, errors.New("核心程序与当前 root 发布快照不一致")
	}
	if err := checkAgentProgram(p); err != nil {
		return AgentProgram{}, err
	}
	return p, nil
}
func checkAgentProgram(p AgentProgram) error {
	if !agentProgramValid(p) {
		return errors.New("Agent 程序恢复身份无效")
	}
	f, info, err := secure.OpenRootFile(p.binary(), panelruntime.BinaryLimit)
	if err != nil {
		return err
	}
	err = f.Close()
	if err != nil {
		return err
	}
	if info.Mode().Perm()&0111 == 0 {
		return errors.New("Agent 程序没有执行权限")
	}
	hash, err := secure.HashRootFile(p.binary(), panelruntime.BinaryLimit)
	if err != nil {
		return err
	}
	if hash != p.BinarySHA256 {
		return errors.New("Agent 程序偏离原恢复散列")
	}
	return nil
}
func publishAgentProgram(ctx context.Context, source string, expected string) (AgentProgram, error) {
	p := AgentProgram{Link: "agent-releases/" + expected, BinarySHA256: expected}
	if !agentProgramValid(p) {
		return p, errors.New("Agent 目标散列无效")
	}
	root := filepath.Join(agentBootstrapRoot, "agent-releases")
	if _, err := os.Lstat(root); os.IsNotExist(err) {
		if err := os.Mkdir(root, 0755); err != nil {
			return p, err
		}
		if err := os.Chmod(root, 0755); err != nil {
			return p, err
		}
		if err := agentUpgradeSync(agentBootstrapRoot); err != nil {
			return p, err
		}
	}
	if err := secure.RootDirectory(root, 0755); err != nil {
		return p, err
	}
	if _, err := os.Lstat(filepath.Dir(p.binary())); err == nil {
		return p, checkAgentProgram(p)
	} else if !os.IsNotExist(err) {
		return p, err
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return p, err
	}
	if len(entries) >= 8 {
		return p, errors.New("Agent 发布目录达到 8 项上限，须本机维护")
	}
	f, info, err := secure.OpenRootFile(source, panelruntime.BinaryLimit)
	if err != nil {
		return p, err
	}
	defer f.Close()
	tmp, err := os.MkdirTemp(root, ".stage-")
	if err != nil {
		return p, err
	}
	defer func() {
		if err := os.RemoveAll(tmp); err != nil {
			slog.Error("清理本次 Agent 暂存目录失败", "path", tmp, "error", err)
		}
	}()
	if err = os.Chmod(tmp, 0755); err != nil {
		return p, err
	}
	out, err := os.OpenFile(filepath.Join(tmp, "nginxpanel"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0555)
	if err != nil {
		return p, err
	}
	var n int64
	if err = ctx.Err(); err == nil {
		n, err = io.Copy(out, io.LimitReader(f, panelruntime.BinaryLimit+1))
	}
	if err == nil && (n != info.Size() || !secure.RootFileUnchanged(f, info)) {
		err = errors.New("Agent 产物在复制期间变化")
	}
	if err == nil {
		err = out.Chmod(0555)
	}
	if err == nil {
		err = out.Sync()
	}
	err = errors.Join(err, out.Close())
	if err != nil {
		return p, err
	}
	hash, err := secure.HashRootFile(filepath.Join(tmp, "nginxpanel"), panelruntime.BinaryLimit)
	if err != nil {
		return p, err
	}
	if hash != expected {
		return p, errors.New("Agent 产物不匹配签名暂存程序")
	}
	if err = ctx.Err(); err != nil {
		return p, err
	}
	if err = agentUpgradeSync(tmp); err != nil {
		return p, err
	}
	if err = unix.Renameat2(unix.AT_FDCWD, tmp, unix.AT_FDCWD, filepath.Dir(p.binary()), unix.RENAME_NOREPLACE); err != nil {
		return p, err
	}
	if err = agentUpgradeSync(root); err != nil {
		return p, err
	}
	return p, checkAgentProgram(p)
}

// The fixed root lock is held by the worker across stop, select and readiness.
func selectAgentProgram(id string, before, target AgentProgram) error {
	if !validID(id) || !agentProgramValid(before) {
		return errors.New("Agent 原指针身份无效")
	}
	if err := checkAgentProgram(target); err != nil {
		return err
	}
	actual, err := readAgentLink()
	if err != nil {
		return err
	}
	if actual == target.Link {
		return agentUpgradeSync(agentBootstrapRoot)
	}
	if actual != before.Link {
		return errors.New("Agent 指针不是原选择或本次目标，停止覆盖")
	}
	tmp := filepath.Join(agentBootstrapRoot, ".agent-select-"+id)
	if info, err := os.Lstat(tmp); err == nil {
		st, ok := info.Sys().(*syscall.Stat_t)
		link, readErr := os.Readlink(tmp)
		if !ok || st.Uid != 0 || st.Nlink != 1 || info.Mode()&os.ModeSymlink == 0 || readErr != nil || link != target.Link {
			return errors.New("Agent 临时指针无法确认")
		}
	} else if os.IsNotExist(err) {
		if err := os.Symlink(target.Link, tmp); err != nil {
			return err
		}
	} else {
		return err
	}
	if err := os.Rename(tmp, filepath.Join(agentBootstrapRoot, "current")); err != nil {
		return err
	}
	if err := agentUpgradeSync(agentBootstrapRoot); err != nil {
		return err
	}
	actual, err = readAgentLink()
	if err != nil {
		return err
	}
	if actual != target.Link {
		return errors.New("Agent 指针切换后无法确认")
	}
	return nil
}
