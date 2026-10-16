package secure

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

func Token() string {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b[:])
}

func ID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[:4], b[4:6], b[6:8], b[8:10], b[10:])
}

func Hash(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

type Vault struct {
	aead      cipher.AEAD
	digestKey []byte
}

func LoadKey(filename string) (*Vault, error) {
	info, err := os.Lstat(filename)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("master key must be a private regular file")
	}
	key, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	return NewVault(key)
}

// NewVault also accepts key bytes read from an already authorized descriptor.
// The caller owns and clears the input; the vault retains independent cipher
// and digest state.
func NewVault(key []byte) (*Vault, error) {
	if len(key) != 32 {
		return nil, errors.New("invalid master key length")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte("nginxpanel:vault:request-digest"))
	return &Vault{aead: aead, digestKey: mac.Sum(nil)}, err
}

// Digest compares secret-bearing idempotent requests without storing a fast,
// unkeyed password verifier. Its domain is separate from data encryption.
func (v *Vault) Digest(data []byte, purpose string) string {
	mac := hmac.New(sha256.New, v.digestKey)
	mac.Write([]byte(purpose))
	mac.Write([]byte{0})
	mac.Write(data)
	return hex.EncodeToString(mac.Sum(nil))
}

func CreateKey(filename string) error {
	if err := os.MkdirAll(filepath.Dir(filename), 0700); err != nil {
		return err
	}
	f, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		return err
	}
	if _, err := f.Write(key[:]); err != nil {
		return err
	}
	return f.Sync()
}

func (v *Vault) Seal(data []byte, purpose string) []byte {
	nonce := make([]byte, v.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		panic(err)
	}
	return v.aead.Seal(nonce, nonce, data, []byte(purpose))
}

func (v *Vault) Open(data []byte, purpose string) ([]byte, error) {
	n := v.aead.NonceSize()
	if len(data) < n {
		return nil, errors.New("invalid encrypted data")
	}
	return v.aead.Open(nil, data[:n], data[n:], []byte(purpose))
}
