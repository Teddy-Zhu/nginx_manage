package nginxcontainer

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
	"nginxpanel/internal/secure"
)

// The candidate must authenticate against its approved binding while the
// serving instance continues to use the original selection. Only the isolated
// check container receives this read-only overlay.
func candidateBindingMount(b Binding, operation string) (Mount, error) {
	if _, err := checkName(operation); err != nil {
		return Mount{}, err
	}
	name, err := Path(b.DataDir)
	if err != nil {
		return Mount{}, err
	}
	return Mount{Source: filepath.Join(filepath.Dir(name), ".nginx-check-"+operation+".json"), Target: name, ReadOnly: true}, nil
}

func verifyCandidateBinding(b Binding, mount Mount) error {
	raw, err := secure.ReadRootFile(mount.Source, 128<<10)
	if err != nil {
		return err
	}
	info, err := os.Lstat(mount.Source)
	if err != nil {
		return err
	}
	if info.Mode().Perm() != 0444 || !bytes.Equal(raw, canonical(b)) {
		return errors.New("候选校验绑定偏离原批准记录")
	}
	return nil
}

func publishCandidateBinding(ctx context.Context, b Binding, operation string) (Mount, error) {
	mount, err := candidateBindingMount(b, operation)
	if err != nil {
		return mount, err
	}
	if err = verifyCandidateBinding(b, mount); !os.IsNotExist(err) {
		return mount, err
	}
	if err = publicDir(filepath.Dir(mount.Source)); err != nil {
		return mount, err
	}
	f, err := os.CreateTemp(filepath.Dir(mount.Source), ".candidate-bind-")
	if err != nil {
		return mount, err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if _, err = f.Write(canonical(b)); err != nil {
		return mount, err
	}
	if err = f.Chmod(0444); err != nil {
		return mount, err
	}
	if err = f.Sync(); err != nil {
		return mount, err
	}
	if err = f.Close(); err != nil {
		return mount, err
	}
	if err = ctx.Err(); err != nil {
		return mount, err
	}
	if err = unix.Renameat2(unix.AT_FDCWD, f.Name(), unix.AT_FDCWD, mount.Source, unix.RENAME_NOREPLACE); err != nil {
		return mount, err
	}
	return mount, syncDir(filepath.Dir(mount.Source))
}

// RemoveCandidateCheckBinding only removes the matching temporary approval
// after Docker confirms that the operation's check container is absent.
func RemoveCandidateCheckBinding(ctx context.Context, b Binding, revision, operation string) error {
	_, err := ReadCandidateCheck(ctx, b, revision, operation)
	if !os.IsNotExist(err) {
		if err == nil {
			err = errors.New("候选校验容器仍存在，不能清理其绑定")
		}
		return err
	}
	mount, err := candidateBindingMount(b, operation)
	if err != nil {
		return err
	}
	if err = verifyCandidateBinding(b, mount); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	if err = os.Remove(mount.Source); err != nil {
		return err
	}
	return syncDir(filepath.Dir(mount.Source))
}
