package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
	"nginxpanel/internal/panelrecovery"
	"nginxpanel/internal/secure"
)

// ReadDisasterNginxDescriptor consumes a frozen root descriptor. Neither the
// endpoint nor the unprivileged verifier may choose an executable or policy.
func ReadDisasterNginxDescriptor(ctx context.Context, f *os.File, expected panelrecovery.File) (out ApplyRequest, err error) {
	if expected.Name != "nginx.json" || expected.Size < 1 || expected.Size > panelrecovery.DisasterNginxRequestMax || len(expected.SHA256) != 64 {
		return out, errors.New("恢复 Nginx 材料清单无效")
	}
	info, err := f.Stat()
	if err != nil {
		return out, err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	flags, err := unix.FcntlInt(f.Fd(), unix.F_GETFL, 0)
	if err != nil {
		return out, err
	}
	if !ok || st.Uid != 0 || st.Nlink != 1 || !info.Mode().IsRegular() || info.Mode().Perm() != 0400 || info.Size() != expected.Size || flags&unix.O_ACCMODE != unix.O_RDONLY {
		return out, errors.New("恢复 Nginx 材料须为 root 固定只读文件")
	}
	if err = ctx.Err(); err != nil {
		return out, err
	}
	raw, err := io.ReadAll(io.LimitReader(f, expected.Size+1))
	if err != nil {
		return out, err
	}
	defer clear(raw)
	if int64(len(raw)) != expected.Size || secure.Hash(raw) != expected.SHA256 || !secure.RootFileUnchanged(f, info) || json.Unmarshal(raw, &out) != nil {
		return ApplyRequest{}, errors.New("恢复 Nginx 材料与原批准不一致")
	}
	canonical, err := json.Marshal(out)
	if err != nil {
		return ApplyRequest{}, err
	}
	defer clear(canonical)
	if !bytes.Equal(raw, canonical) || out.Protocol != Protocol {
		return ApplyRequest{}, errors.New("恢复 Nginx 材料不是当前规范请求")
	}
	return out, ctx.Err()
}
