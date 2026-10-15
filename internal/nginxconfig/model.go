package nginxconfig

import "fmt"

const ParserVersion = "crossplane-0.4.89+spans-4"
const PolicyVersion = "nginxpanel-7"

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
	AccessLists []AccessList `json:"access_lists"`
	WAFPolicies []WAFPolicy  `json:"waf_policies"`
	ModulePaths []string     `json:"module_paths"`
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
	Format   string   `json:"format"`
}

type ResourceMetadata struct {
	Name    string `json:"name"`
	Notes   string `json:"notes"`
	Enabled bool   `json:"enabled"`
}

type Resource struct {
	ID       string           `json:"id"`
	Kind     string           `json:"kind"`
	FileID   string           `json:"file_id"`
	BlockKey string           `json:"block_key"`
	Line     int              `json:"line"`
	Fields   map[string]Field `json:"fields"`
	Metadata ResourceMetadata `json:"metadata"`
}

type Token struct {
	Value            string
	Start, End, Line int
	Kind             string
}
type Node struct {
	Name                                               string
	Args                                               []Token
	Children                                           []*Node
	Start, End, Open, Close, Line                      int
	ResourceID                                         string
	ArgumentComments                                   bool
	Metadata                                           *ResourceMetadata
	MarkerStart, MarkerEnd, MetadataStart, MetadataEnd int
}

func (n *Node) Enabled() bool { return n.Metadata == nil || n.Metadata.Enabled }

type Document struct {
	File  File
	Nodes []*Node
}
type Parsed struct {
	Tree            Tree
	Documents       map[string]*Document
	RequiredScopes  []string
	runtimeExcluded map[string]bool
}

type PatchRequest struct {
	BaseVersion int64               `json:"base_version"`
	Changes     map[string][]string `json:"changes"`
	Metadata    *ResourceMetadata   `json:"metadata,omitempty"`
}

type Edit struct {
	Start, End int
	Text       string
}
