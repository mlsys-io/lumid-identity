package common

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
)

// AES-256-GCM encryption for OAuth refresh-tokens stored in the
// google_grants table. The key comes from IDENTITY_GRANT_KEY (a 32-byte
// hex or base64 string). When unset, we derive a key from the active
// signing key's PEM bytes — this is fine for dev but in production the
// env var MUST be set so the cipher survives signing-key rotation.
//
// Format on disk: base64( nonce[12] || ciphertext+tag ).

var (
	grantKey     []byte
	grantKeyOnce sync.Once
	grantKeyErr  error
)

func resolveGrantKey() ([]byte, error) {
	grantKeyOnce.Do(func() {
		raw := os.Getenv("IDENTITY_GRANT_KEY")
		if raw != "" {
			// Try hex (64 chars) then base64.
			if k, err := decodeKey(raw); err == nil {
				grantKey = k
				return
			}
			// Fall through to derivation if the env var is malformed.
		}
		// Derive from active signing key as a last resort.
		Keys.mu.RLock()
		active := Keys.active
		sk := Keys.keys[active]
		Keys.mu.RUnlock()
		if sk == nil || sk.Private == nil {
			grantKeyErr = errors.New(
				"IDENTITY_GRANT_KEY unset and no active signing key — " +
					"set IDENTITY_GRANT_KEY to a 32-byte hex or base64 string",
			)
			return
		}
		// SHA-256 of the modulus bytes — deterministic per signing key.
		h := sha256.Sum256(sk.Private.N.Bytes())
		grantKey = h[:]
	})
	if grantKeyErr != nil {
		return nil, grantKeyErr
	}
	return grantKey, nil
}

func decodeKey(raw string) ([]byte, error) {
	if len(raw) == 64 {
		// hex
		b := make([]byte, 32)
		_, err := fmt.Sscanf(raw, "%x", &b)
		if err == nil {
			return b, nil
		}
	}
	// base64
	b, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return nil, err
	}
	if len(b) != 32 {
		return nil, fmt.Errorf("decoded key length %d, want 32", len(b))
	}
	return b, nil
}

// EncryptGrant encrypts plaintext with the resolved key.
func EncryptGrant(plaintext string) (string, error) {
	key, err := resolveGrantKey()
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ct := gcm.Seal(nil, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(append(nonce, ct...)), nil
}

// DecryptGrant reverses EncryptGrant.
func DecryptGrant(encoded string) (string, error) {
	key, err := resolveGrantKey()
	if err != nil {
		return "", err
	}
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(raw) < gcm.NonceSize() {
		return "", errors.New("ciphertext too short")
	}
	nonce, ct := raw[:gcm.NonceSize()], raw[gcm.NonceSize():]
	pt, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return "", err
	}
	return string(pt), nil
}
