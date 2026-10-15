package nginxconfig

import "fmt"

const ParserVersion = "crossplane-0.4.89+spans-1"
const PolicyVersion = "nginxpanel-1"

type File struct {
	ID      string `json:"id"`
	Path    string `json:"path"`
	Content string `json:"content"`
	SHA256  string `json:"sha256"`
}

type Tree struct {
	RevisionID  string       `json:"revision_id"`
	Version     int64        `json:"version"`
	State       string       `json:"state"`
	Files       []File       `json:"files"`
	Resources   []Resource   `json:"resources"`
	Diagnostics []Diagnostic `json:"diagnostics"`
}

type Diagnostic struct {
	FileID  string `json:"file_id"`
	Line    int    `json:"line"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (d Diagnostic) Error() string { return fmt.Sprintf("%s:%d: %s", d.FileID, d.Line, d.Message) }

type Field struct {
	Values   []string `json:"values"`
	Editable bool     `json:"editable"`
	Reason   string   `json:"reason,omitempty"`
}

type Resource struct {
	ID       string           `json:"id"`
	Kind     string           `json:"kind"`
	FileID   string           `json:"file_id"`
	BlockKey string           `json:"block_key"`
	Line     int              `json:"line"`
	Fields   map[string]Field `json:"fields"`
}

type Token struct {
	Value            string
	Start, End, Line int
	Kind             string
}
type Node struct {
	Name                          string
	Args                          []Token
	Children                      []*Node
	Start, End, Open, Close, Line int
	ResourceID                    string
	ArgumentComments              bool
}

type Document struct {
	File  File
	Nodes []*Node
}
type Parsed struct {
	Tree           Tree
	Documents      map[string]*Document
	RequiredScopes []string
}

type Edit struct {
	Start, End int
	Text       string
}
