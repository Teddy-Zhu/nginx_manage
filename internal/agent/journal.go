package agent

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"

	"nginxpanel/internal/secure"
)

// Journal is separate from the business database and must never be included in
// a business restore. Future reachability operations persist their deadline and
// recovery snapshot before applying any side effect.
type Record struct {
	OperationID      string `json:"operation_id"`
	RequestHash      string `json:"request_hash"`
	Kind             string `json:"kind"`
	State            string `json:"state"`
	Stage            string `json:"stage"`
	BeforeRevision   string `json:"before_revision,omitempty"`
	AfterRevision    string `json:"after_revision,omitempty"`
	Deadline         int64  `json:"deadline,omitempty"`
	UpdatedAt        int64  `json:"updated_at"`
	DiagnosticsCount int    `json:"diagnostics_count"`
}
type Journal struct {
	Dir string
	mu  sync.Mutex
}

func (j *Journal) Get(id string) (Record, error) {
	if !validID(id) {
		return Record{}, errors.New("invalid operation ID")
	}
	b, err := os.ReadFile(filepath.Join(j.Dir, id+".json"))
	if err != nil {
		return Record{}, err
	}
	var r Record
	err = json.Unmarshal(b, &r)
	return r, err
}
func (j *Journal) Put(r Record) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if !validID(r.OperationID) {
		return errors.New("invalid operation ID")
	}
	if err := os.MkdirAll(j.Dir, 0700); err != nil {
		return err
	}
	entries, err := os.ReadDir(j.Dir)
	if err != nil {
		return err
	}
	if len(entries) >= 2048 {
		if _, err := os.Stat(filepath.Join(j.Dir, r.OperationID+".json")); err != nil {
			return errors.New("agent journal capacity reached; local maintenance required")
		}
	}
	r.UpdatedAt = time.Now().Unix()
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	tmp := filepath.Join(j.Dir, ".tmp-"+secure.ID())
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer os.Remove(tmp)
	if _, err = f.Write(b); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err := os.Rename(tmp, filepath.Join(j.Dir, r.OperationID+".json")); err != nil {
		return err
	}
	dir, err := os.Open(j.Dir)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func validID(id string) bool {
	if len(id) != 36 {
		return false
	}
	for i, c := range id {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return false
			}
		} else if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
