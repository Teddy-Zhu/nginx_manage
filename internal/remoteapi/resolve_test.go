package remoteapi

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"nginxpanel/internal/secure"
)

func privateEndpoint(t *testing.T, before, after time.Time) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "panel.internal"}, NotBefore: before, NotAfter: after, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	requests := new(atomic.Int32)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1); w.WriteHeader(http.StatusNoContent) }))
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	server.StartTLS()
	t.Cleanup(server.Close)
	return server, requests
}

func TestResolvePrivateCertificateWithoutSendingCredentials(t *testing.T) {
	now := time.Now()
	server, requests := privateEndpoint(t, now.Add(-time.Hour), now.Add(time.Hour))
	endpoint, err := Resolve(t.Context(), Endpoint{URL: server.URL, APIKey: secure.Token()})
	if err != nil {
		t.Fatal(err)
	}
	if endpoint.Fingerprint != secure.Hash(server.Certificate().Raw) {
		t.Fatal("initial certificate trust was not recorded")
	}
	if requests.Load() != 0 {
		t.Fatal("certificate discovery sent an HTTP request")
	}
	client, base, err := Client(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, base+"/probe", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+endpoint.APIKey)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent || requests.Load() != 1 {
		t.Fatal("automatic certificate trust did not permit the API request")
	}

	other, otherRequests := privateEndpoint(t, now.Add(-time.Hour), now.Add(time.Hour))
	endpoint.URL = other.URL
	endpoint.Fingerprint = strings.ToUpper(endpoint.Fingerprint)
	resolved, err := Resolve(t.Context(), endpoint)
	if err != nil {
		t.Fatal(err)
	}
	if resolved.Fingerprint != strings.ToLower(endpoint.Fingerprint) {
		t.Fatal("an established pin was replaced")
	}
	changed, changedBase, err := Client(resolved)
	if err != nil {
		t.Fatal(err)
	}
	defer changed.CloseIdleConnections()
	req, err = http.NewRequestWithContext(t.Context(), http.MethodGet, changedBase+"/probe", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+endpoint.APIKey)
	resp, err = changed.Do(req)
	if resp != nil {
		resp.Body.Close()
	}
	if err == nil || otherRequests.Load() != 0 {
		t.Fatal("a changed certificate received credentials")
	}
}

func TestResolveRejectsInvalidCertificateDates(t *testing.T) {
	now := time.Now()
	for _, test := range []struct {
		name          string
		before, after time.Time
	}{
		{"expired", now.Add(-2 * time.Hour), now.Add(-time.Hour)},
		{"not yet valid", now.Add(time.Hour), now.Add(2 * time.Hour)},
	} {
		t.Run(test.name, func(t *testing.T) {
			server, requests := privateEndpoint(t, test.before, test.after)
			if _, err := Resolve(t.Context(), Endpoint{URL: server.URL, APIKey: secure.Token()}); err == nil {
				t.Fatal("accepted an invalid certificate")
			}
			if requests.Load() != 0 {
				t.Fatal("invalid certificate received an HTTP request")
			}
		})
	}
}
