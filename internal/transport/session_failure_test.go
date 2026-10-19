package transport

import (
	"encoding/json"
	"errors"
	"io"
	"net/http/httptest"
	"testing"
	"time"

	"nginxpanel/internal/auth"
	"nginxpanel/internal/secure"
	"nginxpanel/internal/storage"
)

type failingSessionStore struct{ load bool }

func (s failingSessionStore) Find(string) ([]byte, bool, error) {
	if s.load {
		return nil, false, errors.New("session load failed")
	}
	return nil, false, nil
}
func (failingSessionStore) Commit(string, []byte, time.Time) error {
	return errors.New("session commit failed")
}
func (failingSessionStore) Delete(string) error { return nil }

func TestSessionFailuresKeepOneResponseEnvelope(t *testing.T) {
	db, err := storage.Open(t.Context(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	for _, load := range []bool{false, true} {
		name := "commit"
		if load {
			name = "load"
		}
		t.Run(name, func(t *testing.T) {
			a := auth.New(db, true)
			a.Sessions.Store = failingSessionStore{load: load}
			s := &Server{DB: db, Auth: a, NodeID: secure.ID(), Dev: true}
			r := httptest.NewRequest("GET", "/api/v1/me", nil)
			if load {
				r.Header.Set("Cookie", "nginxpanel_session=unavailable-session")
			}
			w := httptest.NewRecorder()
			s.Handler().ServeHTTP(w, r)
			var body Response
			decoder := json.NewDecoder(w.Body)
			if err := decoder.Decode(&body); err != nil {
				t.Fatal(err)
			}
			if w.Code != 500 || body.Code != "INTERNAL_ERROR" || body.Data != nil || body.RequestID == "" || body.RequestID != w.Header().Get("X-Request-ID") || body.NodeID != s.NodeID {
				t.Fatal("session failure did not return the expected error envelope")
			}
			if err := decoder.Decode(new(any)); err != io.EOF {
				t.Fatal("session failure appended a second response")
			}
			if w.Header().Get("Set-Cookie") != "" {
				t.Fatal("failed session was advertised as persisted")
			}
		})
	}
}
