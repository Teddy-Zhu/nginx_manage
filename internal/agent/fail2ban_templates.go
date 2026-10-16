package agent

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"nginxpanel/internal/fail2ban"
	"nginxpanel/internal/fault"
	"nginxpanel/internal/secure"
)

type fail2banTemplateReader struct {
	ctx         context.Context
	data, scope string
	dev         bool
	budget      fail2banReadBudget
	cache       fail2banReadCache[[]fail2ban.TemplateCheck]
}

func (f *fail2banTemplateReader) empty(in fail2ban.TemplateCheckInput, reason string) []fail2ban.TemplateCheck {
	out := []fail2ban.TemplateCheck{}
	for _, id := range in.Templates {
		c := fail2ban.NewTemplateCheck(id)
		c.At = time.Now().Unix()
		c.Source, c.Scope, c.Reason = "host-agent", f.scope, reason
		if c.Scope == "" {
			c.Scope = "unconfirmed"
		}
		if f.dev {
			c.Source, c.Scope = "development-agent", "development"
		}
		out = append(out, c)
	}
	return out
}
func fail2banRegexTool() (fail2ban.Tool, string, error) {
	tool := fail2banTool("fail2ban-regex")
	if !tool.Trusted {
		return tool, "", errors.New("固定系统目录中未发现受信 fail2ban-regex")
	}
	hash, err := secure.HashRootFile(tool.Resolved, 4<<20)
	if err != nil {
		return tool, "", errors.New("fail2ban-regex 文件摘要不可核对")
	}
	return tool, hash, nil
}
func (f *fail2banTemplateReader) read(ctx context.Context, in fail2ban.TemplateCheckInput) ([]fail2ban.TemplateCheck, error) {
	in, err := in.Normalize()
	if err != nil {
		return nil, err
	}
	if f.dev || os.Geteuid() != 0 || (&HostDNS{Dev: f.dev, Scope: f.scope}).hostScopeReason() != "" {
		return f.empty(in, "模板验证须由 root Agent 确认宿主机范围"), nil
	}
	program, err := selectFail2banRegex(f.data)
	if err != nil {
		return f.empty(in, err.Error()), nil
	}
	out, err := f.cache.read(ctx, f.ctx, &f.budget, program.key()+"/"+strings.Join(in.Templates, ","), func(call context.Context) []fail2ban.TemplateCheck { return f.collect(call, in, program) })
	if err != nil {
		return nil, err
	}
	current, checkErr := selectFail2banRegex(f.data)
	if checkErr != nil || current.key() != program.key() {
		return f.empty(in, "验证程序发生变化，请重新验证"), nil
	}
	return out, nil
}
func (f *fail2banTemplateReader) collect(ctx context.Context, in fail2ban.TemplateCheckInput, program fail2banProgram) []fail2ban.TemplateCheck {
	out := f.empty(in, "")
	failAll := func(reason string) []fail2ban.TemplateCheck {
		for i := range out {
			out[i].Available, out[i].Passed, out[i].Reason = false, false, reason
			out[i].MatchedIPs = []string{}
		}
		return out
	}
	for i := range out {
		out[i].Engine = program.engine()
	}
	program, err := program.authenticate(ctx)
	if err != nil {
		return failAll(err.Error())
	}
	for i := range out {
		out[i].ToolPath, out[i].ToolSHA256 = program.tool.Resolved, program.hash
	}
	raw, err := program.run(ctx, []string{"--version"}, 1024)
	if err != nil {
		return failAll("fail2ban-regex 版本无法读取")
	}
	version := strings.TrimSpace(string(raw))
	if actual, ok := strings.CutPrefix(version, "fail2ban-regex "); ok && fail2banVersion.MatchString(actual) {
		for i := range out {
			out[i].ToolVersion = actual
		}
	}
	if version != "fail2ban-regex "+fail2ban.RegexVersion {
		return failAll("当前内置模板验证要求 fail2ban-regex " + fail2ban.RegexVersion)
	}
	for i := range out {
		out[i].ToolVersion = fail2ban.RegexVersion
	}
	base := filepath.Join(fail2banBindingDir(f.data), "template-checks")
	if err = secure.RootDirectory(base, 0700); err != nil {
		return failAll("模板验证工作目录不可用")
	}
	work, err := os.MkdirTemp(base, ".check-")
	if err != nil {
		return failAll("模板验证临时目录不可用")
	}
	defer func() {
		if os.RemoveAll(work) != nil {
			failAll("模板临时材料无法清理，须本机检查")
		}
	}()
	for i, id := range in.Templates {
		filter, filterErr := fail2ban.FilterConfig(id)
		if filterErr != nil {
			return failAll("内置模板无法生成")
		}
		lines := []string{}
		for _, sample := range fail2ban.FilterSamples(id) {
			lines = append(lines, sample.Line)
		}
		filterPath, logPath := filepath.Join(work, "filter.conf"), filepath.Join(work, "samples.log")
		if err = os.WriteFile(filterPath, []byte(filter), 0600); err != nil {
			return failAll("模板材料无法准备")
		}
		if err = os.WriteFile(logPath, []byte(strings.Join(lines, "\n")+"\n"), 0600); err != nil {
			return failAll("模板样例无法准备")
		}
		// Only our fixed filter and fixed, bounded corpus are accepted. The empty
		// private config directory prevents loading distribution jail includes.
		raw, err = program.run(ctx, []string{"--config", work, "--usedns=no", "--encoding=UTF-8", "--maxlines=1", "--out=ip", logPath, filterPath}, 4096)
		if err != nil {
			return failAll("官方模板匹配检查未完成或超出执行预算")
		}
		matched := []string{}
		for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
			if line == "" {
				continue
			}
			ip, parseErr := netip.ParseAddr(line)
			if parseErr != nil || ip.Zone() != "" || len(matched) >= len(lines) {
				return failAll("官方模板检查返回未知或超限结果")
			}
			matched = append(matched, ip.Unmap().String())
		}
		out[i].Available, out[i].MatchedIPs = true, matched
		out[i].Passed = slices.Equal(matched, out[i].ExpectedIPs)
		if !out[i].Passed {
			out[i].Reason = "样例匹配结果与预期不一致"
		}
	}
	if ctx.Err() != nil {
		return failAll("模板检查超出执行预算")
	}
	if err = program.unchanged(ctx, f.data); err != nil {
		return failAll("验证期间程序发生变化，结果不能确认")
	}
	return out
}

type fail2banTemplateRequest struct {
	Protocol  int      `json:"protocol"`
	Templates []string `json:"templates"`
}

func (s *Server) fail2banTemplateHandlers(mux *http.ServeMux, ctx context.Context) {
	f := &fail2banTemplateReader{ctx: ctx, data: s.DataDir, scope: s.MetricsScope, dev: s.Dev}
	mux.HandleFunc("POST /v1/fail2ban/templates/check", func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 1024)
		defer r.Body.Close()
		var in fail2banTemplateRequest
		d := json.NewDecoder(r.Body)
		d.DisallowUnknownFields()
		if d.Decode(&in) != nil || d.Decode(new(any)) != io.EOF || in.Protocol != Protocol {
			dnsReply(w, nil, fault.Invalid("模板验证协议无效"))
			return
		}
		out, err := f.read(r.Context(), fail2ban.TemplateCheckInput{Templates: in.Templates})
		dnsReply(w, out, err)
	})
}
func (c *Client) CheckFail2banTemplates(ctx context.Context, in fail2ban.TemplateCheckInput) ([]fail2ban.TemplateCheck, error) {
	in, err := in.Normalize()
	if err != nil {
		return nil, err
	}
	var out []fail2ban.TemplateCheck
	err = c.envelopeRequest(ctx, http.MethodPost, "/v1/fail2ban/templates/check", fail2banTemplateRequest{Protocol: Protocol, Templates: in.Templates}, &out)
	if err == nil {
		err = fail2ban.ValidateTemplateChecks(in, out)
	}
	return out, err
}
