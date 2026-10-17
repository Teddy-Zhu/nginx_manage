package agent

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os/exec"
	"path/filepath"
	"slices"
	"syscall"
	"time"
)

// A single frozen interpreter avoids one Python import/startup per rule. Go
// still checks every complete official candidate before the next command sees
// it. Frames, individual steps, cumulative bytes and the outer job are bounded.
type ufwDryRunStream struct {
	command    *exec.Cmd
	input      io.WriteCloser
	output     *bufio.Reader
	diagnostic *firewallOutput
	cancel     context.CancelFunc
	ended      bool
}

func (b *ufwToolBinding) dryRunStream(ctx context.Context, root string) (*ufwDryRunStream, error) {
	python, err := b.tool("python")
	if err != nil {
		return nil, err
	}
	names, err := json.Marshal(ufwSourceModules)
	if err != nil {
		return nil, err
	}
	call, cancel := context.WithCancel(ctx)
	command := exec.CommandContext(call, python.File.Path, "-I", "-S", "-B", "-c", ufwFrozenRunner, root, "stream", string(names))
	command.Args[0], command.Dir = python.Invoked, "/"
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C", "LANG=C", "PYTHONDONTWRITEBYTECODE=1", "TMPDIR=" + filepath.Join(root, "tmp")}
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
	command.Cancel = func() error { return syscall.Kill(-command.Process.Pid, syscall.SIGKILL) }
	command.WaitDelay = 250 * time.Millisecond
	input, err := command.StdinPipe()
	if err != nil {
		cancel()
		return nil, err
	}
	output, err := command.StdoutPipe()
	if err != nil {
		input.Close()
		cancel()
		return nil, err
	}
	diagnostic := &firewallOutput{limit: 8 << 10}
	command.Stderr = diagnostic
	stream := &ufwDryRunStream{command: command, input: input, output: bufio.NewReaderSize(output, 64<<10), diagnostic: diagnostic, cancel: cancel}
	if err = command.Start(); err != nil {
		input.Close()
		output.Close()
		cancel()
		return nil, err
	}
	timer := time.AfterFunc(2*time.Second, cancel)
	defer timer.Stop()
	var greeting struct {
		Protocol int `json:"protocol"`
	}
	frame, err := stream.frame()
	if err != nil || ufwToolJSON(frame, &greeting) != nil || greeting.Protocol != 1 {
		stream.abort()
		return nil, errors.New("UFW 固定预演进程未完成有界协议握手")
	}
	return stream, nil
}

func (s *ufwDryRunStream) frame() ([]byte, error) {
	frame := []byte{}
	for {
		part, err := s.output.ReadSlice('\n')
		if len(frame)+len(part) > 6*ufwDryRunOutputBytes {
			return nil, errors.New("UFW 预演响应帧超限")
		}
		frame = append(frame, part...)
		if err == nil {
			return frame, nil
		}
		if !errors.Is(err, bufio.ErrBufferFull) {
			return nil, err
		}
	}
}

func (s *ufwDryRunStream) run(mode string, arguments []string) ([]byte, error) {
	if s.ended || !slices.Contains([]string{"prepend", "delete"}, mode) {
		return nil, errors.New("UFW 预演会话已结束或指令无效")
	}
	request, err := json.Marshal(struct {
		Mode      string   `json:"mode"`
		Arguments []string `json:"arguments"`
	}{mode, arguments})
	if err != nil || len(request) >= 64<<10 {
		return nil, errors.New("UFW 固定预演指令超限")
	}
	timer := time.AfterFunc(2*time.Second, s.cancel)
	defer timer.Stop()
	request = append(request, '\n')
	n, err := s.input.Write(request)
	if err != nil || n != len(request) {
		return nil, errors.New("UFW 固定预演指令未完整发送")
	}
	frame, err := s.frame()
	if err != nil {
		return nil, errors.New("UFW 固定预演中断、超时或响应超限")
	}
	var response struct {
		Output string `json:"output"`
	}
	if ufwToolJSON(frame, &response) != nil || len(response.Output) == 0 || len(response.Output) > ufwDryRunOutputBytes {
		return nil, errors.New("UFW 固定预演响应无效或超限")
	}
	return []byte(response.Output), nil
}

func (s *ufwDryRunStream) finish() error {
	if s.ended {
		return errors.New("UFW 预演会话已结束")
	}
	s.ended = true
	timer := time.AfterFunc(2*time.Second, s.cancel)
	defer timer.Stop()
	closeErr := s.input.Close()
	// EOF is the only accepted tail. Warnings and unexpected bytes cannot be
	// hidden behind the last successfully decoded rule candidate.
	_, tailErr := s.output.ReadByte()
	if tailErr != io.EOF {
		s.cancel()
	}
	waitErr := s.command.Wait()
	s.cancel()
	if closeErr != nil || tailErr != io.EOF || waitErr != nil || s.diagnostic.exceeded || s.diagnostic.data.Len() != 0 {
		return errors.New("UFW 预演未取得无警告的完整结束结果")
	}
	return nil
}

func (s *ufwDryRunStream) abort() {
	if !s.ended {
		s.ended = true
		s.cancel()
		s.input.Close()
		s.command.Wait()
	}
}
