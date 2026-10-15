package nginxconfig

import (
	"errors"
	"fmt"
	"io"
	"path"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	crossplane "github.com/nginxinc/nginx-go-crossplane"
	"nginxpanel/internal/limits"
	"nginxpanel/internal/secure"
)

var resourceID = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$`)

// Source spans are retained separately from Crossplane's semantic tree. Never use
// a pretty printer to write an existing document: untouched bytes remain intact.
type lexer struct {
	source           string
	pos, line, count int
}

func (l *lexer) next() (Token, error) {
	for l.pos < len(l.source) {
		c := l.source[l.pos]
		if c == ' ' || c == '\t' || c == '\r' || c == '\n' {
			if c == '\n' {
				l.line++
			}
			l.pos++
			continue
		}
		break
	}
	if l.pos == len(l.source) {
		return Token{}, io.EOF
	}
	start, line := l.pos, l.line
	c := l.source[l.pos]
	if c == '#' {
		for l.pos < len(l.source) && l.source[l.pos] != '\n' {
			l.pos++
		}
		return Token{Value: l.source[start:l.pos], Start: start, End: l.pos, Line: line, Kind: "comment"}, nil
	}
	if strings.ContainsRune("{};", rune(c)) {
		l.pos++
		return Token{Value: string(c), Start: start, End: l.pos, Line: line, Kind: "punctuation"}, nil
	}
	var value strings.Builder
	var quote byte
	for l.pos < len(l.source) {
		c = l.source[l.pos]
		if c == '\\' {
			l.pos++
			if l.pos == len(l.source) {
				return Token{}, errors.New("转义字符不完整")
			}
			c = l.source[l.pos]
			switch c {
			case 'n':
				value.WriteByte('\n')
			case 'r':
				value.WriteByte('\r')
			case 't':
				value.WriteByte('\t')
			case '\\', '\'', '"':
				value.WriteByte(c)
			default:
				value.WriteByte('\\')
				value.WriteByte(c)
			}
			l.pos++
			continue
		}
		if quote != 0 {
			l.pos++
			if c == quote {
				quote = 0
			} else {
				if c == '\n' {
					l.line++
				}
				value.WriteByte(c)
			}
			continue
		}
		if c == '\'' || c == '"' {
			quote = c
			l.pos++
			continue
		}
		if c == '$' && l.pos+1 < len(l.source) && l.source[l.pos+1] == '{' {
			end := strings.IndexByte(l.source[l.pos+2:], '}')
			if end < 0 {
				return Token{}, errors.New("变量引用不完整")
			}
			value.WriteString(l.source[l.pos : l.pos+end+3])
			l.pos += end + 3
			continue
		}
		if strings.ContainsRune(" \t\r\n{};", rune(c)) {
			break
		}
		value.WriteByte(c)
		l.pos++
	}
	if quote != 0 {
		return Token{}, errors.New("引号未闭合")
	}
	return Token{Value: value.String(), Start: start, End: l.pos, Line: line}, nil
}

func (l *lexer) nodes(depth int) ([]*Node, int, error) {
	if depth > limits.Depth {
		return nil, 0, errors.New("配置嵌套层级超过限制")
	}
	nodes := []*Node{}
	marker := ""
	for {
		t, err := l.next()
		if err == io.EOF {
			if depth > 0 {
				return nil, 0, errors.New("缺少闭合大括号")
			}
			if marker != "" {
				return nil, 0, errors.New("资源标记没有对应的配置块")
			}
			return nodes, l.pos, nil
		}
		if err != nil {
			return nil, 0, err
		}
		if t.Kind == "comment" {
			if strings.HasPrefix(t.Value, "# nginxpanel:resource ") {
				if marker != "" {
					return nil, 0, errors.New("资源标记重复")
				}
				marker = strings.TrimSpace(strings.TrimPrefix(t.Value, "# nginxpanel:resource "))
				if !resourceID.MatchString(marker) {
					return nil, 0, errors.New("资源标记无效")
				}
			}
			continue
		}
		if t.Kind == "punctuation" && t.Value == "}" {
			if depth == 0 || marker != "" {
				return nil, 0, errors.New("出现多余的闭合大括号")
			}
			return nodes, t.Start, nil
		}
		if t.Kind == "punctuation" {
			return nil, 0, errors.New("此处需要配置指令")
		}
		n := &Node{Name: t.Value, Start: t.Start, Line: t.Line, Open: -1, Close: -1, ResourceID: marker}
		marker = ""
		if n.ResourceID != "" && n.Name != "server" {
			return nil, 0, errors.New("资源标记必须紧邻 server 块之前")
		}
		l.count++
		if l.count > limits.Directives {
			return nil, 0, errors.New("指令数量超过限制")
		}
		for {
			a, err := l.next()
			if err != nil {
				return nil, 0, errors.New("指令未结束")
			}
			if a.Kind == "comment" {
				n.ArgumentComments = true
				continue
			}
			if a.Kind == "punctuation" && a.Value == ";" {
				n.End = a.End
				break
			}
			if a.Kind == "punctuation" && a.Value == "{" {
				n.Open = a.Start
				children, close, err := l.nodes(depth + 1)
				if err != nil {
					return nil, 0, err
				}
				n.Children = children
				n.Close = close
				n.End = close + 1
				break
			}
			if a.Kind == "punctuation" && a.Value == "}" {
				return nil, 0, errors.New("缺少分号")
			}
			n.Args = append(n.Args, a)
		}
		if n.ResourceID != "" && n.Open < 0 {
			return nil, 0, errors.New("资源标记必须对应配置块")
		}
		nodes = append(nodes, n)
	}
}

func Parse(files []File, policy Policy) (*Parsed, error) {
	if len(files) == 0 || len(files) > limits.Files {
		return nil, errors.New("配置树必须包含 1–128 个文件")
	}
	p := &Parsed{Tree: Tree{Files: append([]File(nil), files...), Resources: []Resource{}, Diagnostics: []Diagnostic{}}, Documents: map[string]*Document{}}
	paths := map[string]File{}
	size := 0
	directives := 0
	for i := range p.Tree.Files {
		f := &p.Tree.Files[i]
		if f.ID == "" || len(f.ID) > 64 || strings.ContainsAny(f.ID, "/\\\x00") {
			return nil, errors.New("逻辑文件 ID 无效")
		}
		if f.Path == "" || f.Path == "." || len(f.Path) > 256 || path.Clean(f.Path) != f.Path || path.IsAbs(f.Path) || f.Path == ".." || strings.HasPrefix(f.Path, "../") || strings.ContainsAny(f.Path, "\\\x00\r\n") {
			return nil, errors.New("配置路径必须是不含路径穿越的受管相对路径")
		}
		if _, ok := p.Documents[f.ID]; ok {
			return nil, errors.New("逻辑文件 ID 重复")
		}
		if _, ok := paths[f.Path]; ok {
			return nil, errors.New("配置文件路径重复")
		}
		if !utf8.ValidString(f.Content) || strings.ContainsRune(f.Content, 0) {
			return nil, errors.New("配置须为不含 NUL 的 UTF-8 文本")
		}
		size += len(f.Content)
		if len(f.Content) > limits.FileBytes || size > limits.TreeBytes {
			return nil, errors.New("配置大小超过限制")
		}
		f.SHA256 = secure.Hash([]byte(f.Content))
		paths[f.Path] = *f
		l := lexer{source: f.Content, line: 1}
		nodes, _, err := l.nodes(0)
		directives += l.count
		if directives > limits.Directives {
			return nil, errors.New("配置树指令数量超过限制")
		}
		if err != nil {
			p.Tree.Diagnostics = append(p.Tree.Diagnostics, Diagnostic{f.ID, l.line, "syntax", err.Error()})
		}
		p.Documents[f.ID] = &Document{File: *f, Nodes: nodes}
	}
	if _, ok := paths["nginx.conf"]; !ok {
		return nil, errors.New("必须包含 nginx.conf")
	}
	if len(p.Tree.Diagnostics) > 0 {
		return p, nil
	}
	// Crossplane reads only the supplied logical tree. No host file is opened.
	payload, err := crossplane.Parse("nginx.conf", &crossplane.ParseOptions{
		Open: func(name string) (io.ReadCloser, error) {
			f, ok := paths[path.Clean(name)]
			if !ok {
				return nil, fmt.Errorf("include is outside managed tree: %s", name)
			}
			return io.NopCloser(strings.NewReader(f.Content)), nil
		},
		Glob: func(pattern string) ([]string, error) {
			matches := []string{}
			for name := range paths {
				ok, err := path.Match(pattern, name)
				if err != nil {
					return nil, err
				}
				if ok {
					matches = append(matches, name)
				}
			}
			sort.Strings(matches)
			return matches, nil
		},
		ParseComments: true, StopParsingOnError: true, ErrorOnUnknownDirectives: false,
		SkipDirectiveContextCheck: false, SkipDirectiveArgsCheck: false,
	})
	if err != nil || payload.Status != "ok" {
		fileID, line := paths["nginx.conf"].ID, 1
		var parseError *crossplane.ParseError
		if errors.As(err, &parseError) {
			if parseError.File != nil {
				if f, ok := paths[*parseError.File]; ok {
					fileID = f.ID
				}
			}
			if parseError.Line != nil {
				line = *parseError.Line
			}
		}
		p.Tree.Diagnostics = append(p.Tree.Diagnostics, Diagnostic{fileID, line, "syntax", "配置解析失败，请检查 include、指令参数与上下文"})
		return p, nil
	}
	p.validate(policy, paths)
	if len(p.Tree.Diagnostics) == 0 {
		p.project()
	}
	return p, nil
}
