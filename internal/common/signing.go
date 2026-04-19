package common

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"lumid_identity/internal/config"
)

// Keyring holds the set of RS256 keypairs the service knows about.
// Exactly one key is "active" (signs new JWTs); all keys are published
// to JWKS so in-flight JWTs from a just-rotated key still verify.
type SigningKey struct {
	Kid        string
	Private    *rsa.PrivateKey
	Public     *rsa.PublicKey
	Active     bool
	CreatedAt  time.Time
}

type Keyring struct {
	mu     sync.RWMutex
	keys   map[string]*SigningKey
	active string
}

var Keys = &Keyring{keys: map[string]*SigningKey{}}

// LoadKeys reads every *.pem in key_dir. Filename (sans ext) = kid.
// If the directory is empty or missing, we generate a bootstrap key
// and write it so a fresh install just works.
func LoadKeys(c *config.Config) error {
	dir := c.Signing.KeyDir
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create signing key dir: %w", err)
	}
	entries, _ := os.ReadDir(dir)
	loaded := 0
	Keys.mu.Lock()
	defer Keys.mu.Unlock()

	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".pem") {
			continue
		}
		kid := strings.TrimSuffix(e.Name(), ".pem")
		k, err := readPrivatePEM(filepath.Join(dir, e.Name()))
		if err != nil {
			return fmt.Errorf("read key %s: %w", e.Name(), err)
		}
		Keys.keys[kid] = &SigningKey{Kid: kid, Private: k, Public: &k.PublicKey, CreatedAt: time.Now()}
		if Keys.active == "" {
			Keys.active = kid
		}
		loaded++
	}

	if loaded == 0 {
		kid, k, err := generateBootstrapKey(dir)
		if err != nil {
			return err
		}
		Keys.keys[kid] = &SigningKey{Kid: kid, Private: k, Public: &k.PublicKey, Active: true, CreatedAt: time.Now()}
		Keys.active = kid
	}
	Keys.keys[Keys.active].Active = true
	return nil
}

// Active returns the key JWT-signing should use right now.
func (kr *Keyring) Active() *SigningKey {
	kr.mu.RLock()
	defer kr.mu.RUnlock()
	return kr.keys[kr.active]
}

// ByKid finds a key by its id — used during verification.
func (kr *Keyring) ByKid(kid string) *SigningKey {
	kr.mu.RLock()
	defer kr.mu.RUnlock()
	return kr.keys[kid]
}

// All returns every key (for JWKS publication).
func (kr *Keyring) All() []*SigningKey {
	kr.mu.RLock()
	defer kr.mu.RUnlock()
	out := make([]*SigningKey, 0, len(kr.keys))
	for _, k := range kr.keys {
		out = append(out, k)
	}
	return out
}

func readPrivatePEM(path string) (*rsa.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, fmt.Errorf("no PEM block in %s", path)
	}
	k, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err == nil {
		return k, nil
	}
	// Fall back to PKCS#8 for openssl-generated keys.
	k8, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	rk, ok := k8.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("not an RSA key: %s", path)
	}
	return rk, nil
}

func generateBootstrapKey(dir string) (string, *rsa.PrivateKey, error) {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", nil, err
	}
	kid := randHex(8)
	der := x509.MarshalPKCS1PrivateKey(k)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(filepath.Join(dir, kid+".pem"), pemBytes, 0o600); err != nil {
		return "", nil, err
	}
	return kid, k, nil
}

func randHex(n int) string {
	const hex = "0123456789abcdef"
	out := make([]byte, n)
	max := big.NewInt(16)
	for i := range out {
		x, _ := rand.Int(rand.Reader, max)
		out[i] = hex[x.Int64()]
	}
	return string(out)
}
