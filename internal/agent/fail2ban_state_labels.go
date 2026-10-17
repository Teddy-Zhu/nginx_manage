package agent

import (
	"errors"
	"os"
	"unicode/utf8"

	"golang.org/x/sys/unix"
)

func fail2banStateLabel(fd int) (string, error) {
	buffer := make([]byte, 4096)
	n, err := unix.Fgetxattr(fd, "security.selinux", buffer)
	if errors.Is(err, unix.ENODATA) || errors.Is(err, unix.EOPNOTSUPP) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	if !utf8.Valid(buffer[:n]) {
		return "", errors.New("Fail2ban 状态安全标签编码无效")
	}
	return string(buffer[:n]), nil
}

func setFail2banStateLabel(fd int, label string) error {
	if len(label) > 4096 {
		return errors.New("Fail2ban 状态安全标签超出限制")
	}
	current, err := fail2banStateLabel(fd)
	if err != nil || current == label {
		return err
	}
	if label == "" {
		return unix.Fremovexattr(fd, "security.selinux")
	}
	return unix.Fsetxattr(fd, "security.selinux", []byte(label), 0)
}

func fail2banStateDirectoryLabel(dir string, set *string) (string, error) {
	if err := fail2banStatePrivateDir(dir, false); err != nil {
		return "", err
	}
	fd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return "", err
	}
	f := os.NewFile(uintptr(fd), dir)
	defer f.Close()
	if set != nil {
		if err = setFail2banStateLabel(fd, *set); err != nil {
			return "", err
		}
		if err = f.Sync(); err != nil {
			return "", err
		}
	}
	return fail2banStateLabel(fd)
}
