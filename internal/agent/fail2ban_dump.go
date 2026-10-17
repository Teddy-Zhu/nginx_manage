package agent

import (
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"unicode/utf8"

	"nginxpanel/internal/secure"
)

// The official -d output is Python literals, not JSON. Parse only the bounded
// data grammar used by 1.1.1; never evaluate a Python expression or import code.
type fail2banLiteralReader struct {
	raw         []byte
	pos, values int
}

func (p *fail2banLiteralReader) space() {
	for p.pos < len(p.raw) && strings.ContainsRune(" \t\r\n", rune(p.raw[p.pos])) {
		p.pos++
	}
}
func (p *fail2banLiteralReader) value(depth int) (any, error) {
	p.space()
	p.values++
	if depth > 8 || p.values > 32768 || p.pos >= len(p.raw) {
		return nil, errors.New("官方配置流超出解析预算或不完整")
	}
	switch p.raw[p.pos] {
	case '[', '(':
		end := byte(']')
		if p.raw[p.pos] == '(' {
			end = ')'
		}
		p.pos++
		out := []any{}
		for {
			p.space()
			if p.pos >= len(p.raw) {
				return nil, errors.New("官方配置流序列未结束")
			}
			if p.raw[p.pos] == end {
				p.pos++
				return out, nil
			}
			value, err := p.value(depth + 1)
			if err != nil {
				return nil, err
			}
			out = append(out, value)
			p.space()
			if p.pos < len(p.raw) && p.raw[p.pos] == ',' {
				p.pos++
				continue
			}
			if p.pos >= len(p.raw) || p.raw[p.pos] != end {
				return nil, errors.New("官方配置流序列分隔符未知")
			}
		}
	case '\'', '"':
		return p.quoted()
	}
	start := p.pos
	for p.pos < len(p.raw) && !strings.ContainsRune(",]) \t\r\n", rune(p.raw[p.pos])) {
		p.pos++
	}
	word := string(p.raw[start:p.pos])
	switch word {
	case "True":
		return true, nil
	case "False":
		return false, nil
	case "None":
		return nil, nil
	}
	value, err := strconv.ParseInt(word, 10, 64)
	if err != nil || strconv.FormatInt(value, 10) != word {
		return nil, errors.New("官方配置流包含未知字面量")
	}
	return value, nil
}
func (p *fail2banLiteralReader) quoted() (string, error) {
	quote := p.raw[p.pos]
	p.pos++
	var out strings.Builder
	for p.pos < len(p.raw) {
		c := p.raw[p.pos]
		p.pos++
		if c == quote {
			if out.Len() > 128<<10 || !utf8.ValidString(out.String()) || strings.IndexByte(out.String(), 0) >= 0 {
				return "", errors.New("官方配置流字符串编码或长度无效")
			}
			return out.String(), nil
		}
		if c == '\n' || c == '\r' || c < 32 {
			return "", errors.New("官方配置流字符串包含未转义控制符")
		}
		if c != '\\' {
			out.WriteByte(c)
			continue
		}
		if p.pos >= len(p.raw) {
			return "", errors.New("官方配置流字符串转义未结束")
		}
		escaped := p.raw[p.pos]
		p.pos++
		switch escaped {
		case '\\', '\'', '"':
			out.WriteByte(escaped)
		case 'n':
			out.WriteByte('\n')
		case 'r':
			out.WriteByte('\r')
		case 't':
			out.WriteByte('\t')
		case 'b':
			out.WriteByte('\b')
		case 'f':
			out.WriteByte('\f')
		case 'a':
			out.WriteByte(7)
		case 'v':
			out.WriteByte(11)
		case 'x', 'u', 'U':
			count := 2
			if escaped == 'u' {
				count = 4
			} else if escaped == 'U' {
				count = 8
			}
			if len(p.raw)-p.pos < count {
				return "", errors.New("官方配置流 Unicode 转义不完整")
			}
			n, err := strconv.ParseUint(string(p.raw[p.pos:p.pos+count]), 16, 32)
			if err != nil || !utf8.ValidRune(rune(n)) {
				return "", errors.New("官方配置流 Unicode 转义无效")
			}
			p.pos += count
			out.WriteRune(rune(n))
		default:
			return "", errors.New("官方配置流字符串转义未知")
		}
		if out.Len() > 128<<10 {
			return "", errors.New("官方配置流字符串超过预算")
		}
	}
	return "", errors.New("官方配置流字符串未结束")
}

func parseFail2banDump(raw []byte, jail string) ([][]any, error) {
	if len(raw) == 0 || len(raw) > 2<<20 || !fail2banJailName.MatchString(jail) {
		return nil, errors.New("官方配置流或 jail 标识无效")
	}
	p := fail2banLiteralReader{raw: raw}
	out := [][]any{}
	for {
		p.space()
		if p.pos == len(raw) {
			break
		}
		value, err := p.value(0)
		if err != nil {
			return nil, err
		}
		command, ok := value.([]any)
		if !ok || len(command) < 2 {
			return nil, errors.New("官方配置流命令格式未知")
		}
		verb, first := command[0].(string)
		target, second := command[1].(string)
		if !first || !second {
			return nil, errors.New("官方配置流命令标识无效")
		}
		if target != jail {
			continue
		}
		switch verb {
		case "add", "set", "multi-set", "start":
		default:
			return nil, errors.New("目标 jail 的官方配置流包含未知命令")
		}
		out = append(out, command)
		if len(out) > 256 {
			return nil, errors.New("目标 jail 的官方配置流超过预算")
		}
	}
	return out, nil
}

func fail2banDumpHash(commands [][]any) string {
	raw, _ := json.Marshal(commands)
	return secure.Hash(raw)
}
