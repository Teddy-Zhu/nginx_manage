package nginxconfig

import (
	"context"
	"encoding/json"
	"path"
	"sort"

	"nginxpanel/internal/auth"
	"nginxpanel/internal/fault"
	"nginxpanel/internal/secure"
)

type DiffRequest struct {
	BaseRevision string `json:"base_revision"`
	Files        []File `json:"files"`
}
type FileDifference struct {
	FileID                     string   `json:"file_id"`
	BeforePath                 string   `json:"before_path"`
	AfterPath                  string   `json:"after_path"`
	Status                     string   `json:"status"`
	BeforeContent              string   `json:"before_content"`
	AfterContent               string   `json:"after_content"`
	AffectedResources          []string `json:"affected_resources"`
	AffectedResourceCount      int      `json:"affected_resource_count"`
	AffectedResourcesTruncated bool     `json:"affected_resources_truncated"`
}
type Difference struct {
	BaseRevision string           `json:"base_revision"`
	Files        []FileDifference `json:"files"`
	Diagnostics  []Diagnostic     `json:"diagnostics"`
}

func (s *Service) Diff(ctx context.Context, in DiffRequest) (Difference, error) {
	base := Tree{Files: InitialFiles()}
	if in.BaseRevision != "" {
		var err error
		base, err = s.Get(ctx, in.BaseRevision)
		if err != nil {
			return Difference{}, err
		}
	}
	before, err := Parse(base.Files, s.Policy)
	if err != nil {
		return Difference{}, err
	}
	after, err := Parse(in.Files, s.Policy)
	if err != nil {
		return Difference{}, fault.Invalid(err.Error())
	}
	out := Difference{BaseRevision: in.BaseRevision, Files: []FileDifference{}, Diagnostics: after.Tree.Diagnostics}
	old, next := map[string]File{}, map[string]File{}
	for _, f := range before.Tree.Files {
		old[f.ID] = f
	}
	for _, f := range after.Tree.Files {
		next[f.ID] = f
	}
	beforeImpact, afterImpact := before.resourceImpacts(), after.resourceImpacts()
	ids := map[string]bool{}
	for id := range old {
		ids[id] = true
	}
	for id := range next {
		ids[id] = true
	}
	for id := range ids {
		a, existsA := old[id]
		b, existsB := next[id]
		if existsA && existsB && a.Path == b.Path && a.Content == b.Content {
			continue
		}
		status := "modified"
		switch {
		case !existsA:
			status = "added"
		case !existsB:
			status = "removed"
		case a.Path != b.Path:
			status = "moved"
		}
		impact := map[string]bool{}
		for _, resource := range beforeImpact[a.Path] {
			impact[resource] = true
		}
		for _, resource := range afterImpact[b.Path] {
			impact[resource] = true
		}
		resources := []string{}
		for resource := range impact {
			resources = append(resources, resource)
		}
		sort.Strings(resources)
		count := len(resources)
		if len(resources) > 100 {
			resources = resources[:100]
		}
		out.Files = append(out.Files, FileDifference{id, a.Path, b.Path, status, a.Content, b.Content, resources, count, count > 100})
	}
	sort.Slice(out.Files, func(i, j int) bool {
		a, b := out.Files[i], out.Files[j]
		ap, bp := a.AfterPath, b.AfterPath
		if ap == "" {
			ap = a.BeforePath
		}
		if bp == "" {
			bp = b.BeforePath
		}
		if ap == bp {
			return a.FileID < b.FileID
		}
		return ap < bp
	})
	return out, nil
}

// Shared global files can affect a whole context. Report potential consumers
// conservatively; unknown variable references must not hide an affected site.
func (p *Parsed) resourceImpacts() map[string][]string {
	contexts, _ := p.includeContexts()
	parents := map[string]map[string]bool{}
	for _, doc := range p.Documents {
		var walk func([]*Node)
		walk = func(nodes []*Node) {
			for _, node := range nodes {
				if node.Name == "include" && len(node.Args) == 1 {
					for _, other := range p.Documents {
						if match, _ := path.Match(node.Args[0].Value, other.File.Path); match {
							if parents[other.File.Path] == nil {
								parents[other.File.Path] = map[string]bool{}
							}
							parents[other.File.Path][doc.File.Path] = true
						}
					}
				}
				walk(node.Children)
			}
		}
		walk(doc.Nodes)
	}
	owned := map[string]bool{}
	for _, resource := range p.Tree.Resources {
		owned[p.Documents[resource.FileID].File.Path] = true
	}
	for _, doc := range p.Documents {
		for _, node := range doc.Nodes {
			if node.ResourceID == "" {
				delete(owned, doc.File.Path)
				break
			}
		}
	}
	out := map[string][]string{}
	for _, doc := range p.Documents {
		name := doc.File.Path
		ancestors := map[string]bool{name: true}
		queue := []string{name}
		for len(queue) > 0 {
			current := queue[0]
			queue = queue[1:]
			for parent := range parents[current] {
				if !ancestors[parent] {
					ancestors[parent] = true
					queue = append(queue, parent)
				}
			}
		}
		for _, r := range p.Tree.Resources {
			if name == "nginx.conf" || ancestors[p.Documents[r.FileID].File.Path] || !owned[name] && contexts[name][r.Kind] {
				out[name] = append(out[name], r.ID)
			}
		}
	}
	return out
}

type CaptureRequest struct {
	BaseVersion int64  `json:"base_version"`
	Snapshot    string `json:"snapshot"`
	Path        string `json:"path"`
}
type CapturedFile struct {
	Base    File
	File    File
	Removed bool
}

func (s *Service) CaptureExternal(ctx context.Context, p auth.Principal, requestID, key string, in CaptureRequest, load func() (CapturedFile, error)) (SaveResult, error) {
	if err := p.Require("config.write", "config.secrets"); err != nil {
		return SaveResult{}, err
	}
	if in.BaseVersion < 0 || len(in.Snapshot) != 64 || !cleanRelative(in.Path) || key == "" || len(key) > 128 {
		return SaveResult{}, fault.Invalid("外部快照请求无效")
	}
	encoded, _ := json.Marshal(struct {
		Action string
		Input  CaptureRequest
	}{"capture_external", in})
	digest := secure.Hash(encoded)
	if out, found, err := s.replay(ctx, p.ID, key, digest); found || err != nil {
		return out, err
	}
	tree, err := s.Current(ctx)
	if err != nil {
		return SaveResult{}, err
	}
	if tree.Version != in.BaseVersion {
		return SaveResult{}, ErrConflict
	}
	capture, err := load()
	if err != nil {
		return SaveResult{}, err
	}
	files := []File{}
	found := false
	for _, file := range tree.Files {
		if file.Path == in.Path || capture.Base.ID != "" && file.ID == capture.Base.ID {
			if capture.Base.ID == "" || file.ID != capture.Base.ID || file.Path != capture.Base.Path || file.Content != capture.Base.Content {
				return SaveResult{}, fault.Conflict("期望配置已修改此文件，请通过差异手动合并")
			}
			found = true
			if !capture.Removed {
				files = append(files, capture.File)
			}
		} else {
			files = append(files, file)
		}
	}
	if !found {
		if capture.Base.ID != "" {
			return SaveResult{}, fault.Conflict("期望配置已移除或移动此文件，请手动合并")
		}
		if !capture.Removed {
			files = append(files, capture.File)
		}
	}
	return s.save(ctx, p, requestID, key, SaveRequest{BaseVersion: in.BaseVersion, Files: files, Draft: true}, digest)
}
