package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
	"nginxpanel/internal/fault"
)

const argonMemory = 64 * 1024

func HashPassword(password string) (string, error) {
	if utf8.RuneCountInString(password) < 6 {
		return "", fault.Invalid("密码至少需要 6 个字符")
	}
	var salt [16]byte
	if _, err := rand.Read(salt[:]); err != nil {
		return "", err
	}
	hash := argon2.IDKey([]byte(password), salt[:], 3, argonMemory, 2, 32)
	return fmt.Sprintf("$argon2id$v=19$m=65536,t=3,p=2$%s$%s", base64.RawStdEncoding.EncodeToString(salt[:]), base64.RawStdEncoding.EncodeToString(hash)), nil
}

func decodePasswordHash(encoded string) (salt, hash []byte) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" || parts[2] != "v=19" || parts[3] != "m=65536,t=3,p=2" {
		return nil, nil
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil || len(salt) != 16 {
		return nil, nil
	}
	hash, err = base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(hash) != 32 {
		return nil, nil
	}
	return salt, hash
}

func CheckPassword(encoded, password string) bool {
	salt, want := decodePasswordHash(encoded)
	if salt == nil {
		return false
	}
	got := argon2.IDKey([]byte(password), salt, 3, argonMemory, 2, 32)
	return subtle.ConstantTimeCompare(got, want) == 1
}
