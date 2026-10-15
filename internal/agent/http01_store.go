package agent

import (
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"nginxpanel/internal/limits"
	"nginxpanel/internal/nginxconfig"
	"nginxpanel/internal/secure"
)

const http01MaxLeases = limits.Certificates

var http01Token = regexp.MustCompile(`^[A-Za-z0-9_-]{22,256}$`)
var http01Thumbprint = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

type http01Material struct {
	Domain           string `json:"domain"`
	KeyAuthorization string `json:"key_authorization"`
}
type http01Lease struct {
	Epoch     int64                     `json:"epoch"`
	Closed    bool                      `json:"closed"`
	OrderID   string                    `json:"order_id"`
	Revision  string                    `json:"revision"`
	Domains   []string                  `json:"domains"`
	ExpiresAt int64                     `json:"expires_at"`
	Tokens    map[string]http01Material `json:"tokens"`
}

// Material is root-owned and durable, but expiry is enforced by the responder
// on every request. A stopped Agent cannot leave an expired webroot file live.
type http01Store struct {
	dir    string
	mu     sync.RWMutex
	leases map[string]http01Lease
	tokens map[string]string
}

func http01Domain(domain string) bool {
	if len(domain) > 253 || domain != strings.ToLower(domain) || net.ParseIP(domain) != nil || !strings.Contains(domain, ".") {
		return false
	}
	for _, label := range strings.Split(domain, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' || strings.Trim(label, "abcdefghijklmnopqrstuvwxyz0123456789-") != "" {
			return false
		}
	}
	return true
}

func validHTTP01Lease(lease http01Lease) bool {
	if !validID(lease.OrderID) || lease.Epoch < 1 || lease.Epoch > 1_000_000_000 {
		return false
	}
	if lease.Closed {
		return lease.Revision == "" && len(lease.Domains) == 0 && lease.ExpiresAt == 0 && len(lease.Tokens) == 0
	}
	if !validID(lease.OrderID) || !validID(lease.Revision) || lease.ExpiresAt <= 0 || len(lease.Domains) == 0 || len(lease.Domains) > 64 || len(lease.Tokens) > 64 {
		return false
	}
	domains := map[string]bool{}
	for _, domain := range lease.Domains {
		if !http01Domain(domain) || domains[domain] {
			return false
		}
		domains[domain] = true
	}
	for token, material := range lease.Tokens {
		if !http01Token.MatchString(token) || !domains[material.Domain] || !strings.HasPrefix(material.KeyAuthorization, token+".") || !http01Thumbprint.MatchString(strings.TrimPrefix(material.KeyAuthorization, token+".")) {
			return false
		}
	}
	return true
}

func openHTTP01Store(dataDir string) (*http01Store, error) {
	parent := filepath.Join(dataDir, "acme")
	if err := secure.RootDirectory(parent, 0700); err != nil {
		return nil, err
	}
	dir := filepath.Join(parent, "http01")
	if err := secure.RootDirectory(dir, 0700); err != nil {
		return nil, err
	}
	if err := os.Chmod(dir, 0700); err != nil {
		return nil, err
	}
	s := &http01Store{dir: dir, leases: map[string]http01Lease{}, tokens: map[string]string{}}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	if len(entries) > limits.ACMEOrders*2 {
		return nil, errors.New("HTTP-01 material quota exceeded")
	}
	changed := false
	active, retained := 0, 0
	for _, entry := range entries {
		name := entry.Name()
		info, err := os.Lstat(filepath.Join(dir, name))
		if err != nil {
			return nil, err
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 || stat.Nlink != 1 || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() > 256<<10 {
			return nil, errors.New("untrusted HTTP-01 material")
		}
		if strings.HasPrefix(name, ".tmp-") && validID(strings.TrimPrefix(name, ".tmp-")) {
			if err := os.Remove(filepath.Join(dir, name)); err != nil {
				return nil, err
			}
			changed = true
			continue
		}
		id := strings.TrimSuffix(name, ".json")
		if name != id+".json" || !validID(id) {
			return nil, errors.New("invalid HTTP-01 material name")
		}
		retained++
		if retained > limits.ACMEOrders {
			return nil, errors.New("HTTP-01 history quota exceeded")
		}
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return nil, err
		}
		var lease http01Lease
		if err := json.Unmarshal(data, &lease); err != nil || lease.OrderID != id || !validHTTP01Lease(lease) {
			return nil, errors.New("invalid HTTP-01 material")
		}
		if lease.ExpiresAt > time.Now().Add(time.Hour).Unix() {
			return nil, errors.New("HTTP-01 expiry exceeds maximum lifetime")
		}
		if !lease.Closed && lease.ExpiresAt <= time.Now().Unix() {
			lease = closedHTTP01Lease(id, lease.Epoch)
			if err := s.writeLocked(lease); err != nil {
				return nil, err
			}
		}
		if !lease.Closed {
			active++
		}
		if active > http01MaxLeases {
			return nil, errors.New("HTTP-01 material quota exceeded")
		}
		for token := range lease.Tokens {
			if _, exists := s.tokens[token]; exists {
				return nil, errors.New("conflicting HTTP-01 token")
			}
			s.tokens[token] = id
		}
		s.leases[id] = lease
	}
	if changed {
		if err := syncDir(dir); err != nil {
			return nil, err
		}
	}
	return s, nil
}

func (s *http01Store) busy() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, lease := range s.leases {
		if lease.ExpiresAt > time.Now().Unix() {
			return true
		}
	}
	return false
}

func closedHTTP01Lease(id string, epoch int64) http01Lease {
	return http01Lease{OrderID: id, Epoch: epoch, Closed: true, Domains: []string{}, Tokens: map[string]http01Material{}}
}

// Retain a bounded order tombstone, including when cleanup arrives before a
// delayed reserve request. A newer epoch can resume this same CA order safely.
func (s *http01Store) cleanup(id string, epoch int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if old, exists := s.leases[id]; exists {
		if old.Epoch > epoch {
			return nil
		}
		if old.Epoch == epoch && old.Closed {
			return syncDir(s.dir)
		}
	} else if len(s.leases) >= limits.ACMEOrders {
		return errors.New("HTTP-01 history quota exceeded")
	}
	return s.writeLocked(closedHTTP01Lease(id, epoch))
}
func (s *http01Store) writeLocked(lease http01Lease) error {
	data, err := json.Marshal(lease)
	if err != nil {
		return err
	}
	tmp := filepath.Join(s.dir, ".tmp-"+secure.ID())
	defer os.Remove(tmp)
	if err := durableFile(tmp, data, 0600, 0); err != nil {
		return err
	}
	if err := os.Rename(tmp, filepath.Join(s.dir, lease.OrderID+".json")); err != nil {
		return err
	}
	for token := range s.leases[lease.OrderID].Tokens {
		delete(s.tokens, token)
	}
	s.leases[lease.OrderID] = lease
	for token := range lease.Tokens {
		s.tokens[token] = lease.OrderID
	}
	return syncDir(s.dir)
}

func (s *http01Store) reserve(lease http01Lease) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	active := 0
	for id, old := range s.leases {
		if !old.Closed && old.ExpiresAt <= time.Now().Unix() {
			if err := s.writeLocked(closedHTTP01Lease(id, old.Epoch)); err != nil {
				return err
			}
		} else if !old.Closed {
			active++
		}
	}
	if old, ok := s.leases[lease.OrderID]; ok {
		if old.Epoch > lease.Epoch || old.Epoch == lease.Epoch && old.Closed {
			return errors.New("HTTP-01 lease epoch has already been closed")
		}
		if old.Epoch == lease.Epoch {
			if old.Revision != lease.Revision || strings.Join(old.Domains, "\x00") != strings.Join(lease.Domains, "\x00") || old.ExpiresAt != lease.ExpiresAt {
				return errors.New("HTTP-01 lease conflicts with original order")
			}
			return syncDir(s.dir)
		}
		if !old.Closed {
			return errors.New("previous HTTP-01 lease must be cleaned before resuming")
		}
	} else if len(s.leases) >= limits.ACMEOrders {
		return errors.New("HTTP-01 history quota exceeded")
	}
	if active >= http01MaxLeases {
		return errors.New("HTTP-01 lease quota exceeded")
	}
	return s.writeLocked(lease)
}

func (s *http01Store) present(id string, epoch int64, domain, token, authorization string) (http01Lease, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	lease, ok := s.leases[id]
	if !ok || lease.Closed || lease.Epoch != epoch || lease.ExpiresAt <= time.Now().Unix() {
		return lease, errors.New("HTTP-01 lease has expired or is unavailable")
	}
	if owner, exists := s.tokens[token]; exists && owner != id {
		return lease, errors.New("HTTP-01 token belongs to another order")
	}
	if old, exists := lease.Tokens[token]; exists && (old.Domain != domain || old.KeyAuthorization != authorization) {
		return lease, errors.New("HTTP-01 token conflicts with original material")
	}
	// Copy the token map so a failed durable write cannot change live material.
	next := map[string]http01Material{}
	for key, value := range lease.Tokens {
		next[key] = value
	}
	lease.Tokens = next
	lease.Tokens[token] = http01Material{domain, authorization}
	if !validHTTP01Lease(lease) {
		return lease, errors.New("invalid HTTP-01 material")
	}
	return lease, s.writeLocked(lease)
}

func (s *http01Store) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	token := strings.TrimPrefix(r.URL.Path, nginxconfig.HTTP01Prefix)
	if r.URL.RawQuery != "" || r.URL.RawPath != "" || !strings.HasPrefix(r.URL.Path, nginxconfig.HTTP01Prefix) || !http01Token.MatchString(token) {
		http.NotFound(w, r)
		return
	}
	host := strings.ToLower(r.Host)
	if parsed, port, err := net.SplitHostPort(host); err == nil {
		if port != "80" {
			http.NotFound(w, r)
			return
		}
		host = parsed
	}
	host = strings.TrimSuffix(host, ".")
	s.mu.RLock()
	lease := s.leases[s.tokens[token]]
	material, found := lease.Tokens[token]
	if !found || lease.ExpiresAt <= time.Now().Unix() || material.Domain != host {
		s.mu.RUnlock()
		http.NotFound(w, r)
		return
	}
	authorization := material.KeyAuthorization
	s.mu.RUnlock()
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	if r.Method == http.MethodGet {
		_, _ = io.WriteString(w, authorization)
	}
}
