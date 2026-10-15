package nginxconfig

import (
	"encoding/json"
	"errors"
	"io"
	"strings"
	"unicode/utf8"
)

const metadataPrefix = "# nginxpanel:metadata "

func validateMetadata(m ResourceMetadata) error {
	if !utf8.ValidString(m.Name) || !utf8.ValidString(m.Notes) || len([]rune(m.Name)) > 128 || len([]rune(m.Notes)) > 2048 || strings.ContainsAny(m.Name, "\x00\r\n") || strings.ContainsRune(m.Notes, 0) {
		return errors.New("名称或备注无效")
	}
	return nil
}
func decodeMetadata(text string) (ResourceMetadata, error) {
	var m ResourceMetadata
	if len(text) > 16<<10 {
		return m, errors.New("资源元信息超过限制")
	}
	d := json.NewDecoder(strings.NewReader(text))
	d.DisallowUnknownFields()
	if d.Decode(&m) != nil || d.Decode(new(any)) != io.EOF {
		return m, errors.New("资源元信息不是有效 JSON")
	}
	return m, validateMetadata(m)
}
func metadataLine(m ResourceMetadata) string {
	b, _ := json.Marshal(m)
	return metadataPrefix + string(b)
}
func resourceMetadata(n *Node) ResourceMetadata {
	if n.Metadata != nil {
		return *n.Metadata
	}
	return ResourceMetadata{Name: n.ResourceID, Enabled: true}
}

// Each edit changes a known source span. Stable ordering also makes newly
// inserted directives deterministic without reformatting surrounding text.
func (p *Parsed) editFiles(edits map[string][]Edit) ([]File, error) {
	files := append([]File(nil), p.Tree.Files...)
	for i := range files {
		changes := edits[files[i].ID]
		if len(changes) == 0 {
			continue
		}
		text, err := applyEdits(files[i].Content, changes)
		if err != nil {
			return nil, err
		}
		files[i].Content = text
	}
	return files, nil
}

func (m *ResourceMetadata) UnmarshalJSON(data []byte) error {
	var in struct {
		Name    string `json:"name"`
		Notes   string `json:"notes"`
		Enabled *bool  `json:"enabled"`
	}
	d := json.NewDecoder(strings.NewReader(string(data)))
	d.DisallowUnknownFields()
	if err := d.Decode(&in); err != nil {
		return err
	}
	if in.Enabled == nil {
		return errors.New("资源元信息缺少 enabled")
	}
	*m = ResourceMetadata{Name: in.Name, Notes: in.Notes, Enabled: *in.Enabled}
	return validateMetadata(*m)
}
