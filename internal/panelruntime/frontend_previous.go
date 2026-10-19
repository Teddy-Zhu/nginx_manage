package panelruntime

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

type previousProgram struct {
	Schema      int    `json:"schema"`
	OperationID string `json:"operation_id"`
	Before      string `json:"before"`
	After       string `json:"after"`
}

// This record is published before current changes. It only applies when its
// after identity is actually running, including after a compensated update.
func savePreviousProgram(root, before, after, operation string) error {
	raw, err := json.Marshal(previousProgram{Schema, operation, before, after})
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(root, ".previous-frontend-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if _, err = f.Write(raw); err != nil {
		return err
	}
	if err = f.Chmod(0444); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Rename(f.Name(), filepath.Join(root, "previous-program.json")); err != nil {
		return err
	}
	return syncDir(root)
}
func previousBundledFrontend(data, base string) (*FrontendSnapshot, error) {
	root, err := Root(data)
	if err != nil {
		return nil, err
	}
	var previous previousProgram
	err = frontendJSON(filepath.Join(root, "previous-program.json"), &previous, 4096)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if previous.Schema != Schema || !selectionID.MatchString(previous.OperationID) || !digest.MatchString(previous.Before) || !digest.MatchString(previous.After) || previous.Before == previous.After {
		return nil, errors.New("上一面板前端记录无效")
	}
	if previous.After != base {
		return nil, nil
	}
	source, err := bundledFrontend(data, previous.Before)
	return &source, err
}
