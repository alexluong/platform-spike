package zitadel

// System API access for instance-per-merchant mode (stack i). One Zitadel deployment serves
// every instance; the app reaches all of them at one internal URL and picks the instance per
// request with x-zitadel-instance-host (Zitadel's InstanceHostHeaders, default list). Calls are
// authenticated with system API users (JWT profile, keys configured in ZITADEL_SYSTEMAPIUSERS),
// whose System memberships apply to every instance: no per-instance credential to store.

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// Keygen writes an RSA key pair per system user into dir (<name>.key, <name>.pub) unless
// present. Zitadel reads the .pub files (ZITADEL_SYSTEMAPIUSERS Path); the app signs with .key.
func Keygen(dir string, names ...string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	for _, n := range names {
		priv := filepath.Join(dir, n+".key")
		if _, err := os.Stat(priv); err == nil {
			continue
		}
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return err
		}
		pub, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(dir, n+".pub"), pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pub}), 0o644); err != nil {
			return err
		}
		// 0644: the app and bootstrap containers read it from a dev volume. Production: a secret store.
		if err := os.WriteFile(priv+".tmp", pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}), 0o644); err != nil {
			return err
		}
		if err := os.Rename(priv+".tmp", priv); err != nil {
			return err
		}
	}
	return nil
}

// sysUser signs short-lived JWTs for one system API user.
type sysUser struct {
	name     string
	audience string // Zitadel's external origin (http://<ExternalDomain>:<ExternalPort>), whatever the instance
	signer   jose.Signer

	mu    sync.Mutex
	token string
	exp   time.Time
}

func loadSysUser(dir, name, audience string) (*sysUser, error) {
	b, err := os.ReadFile(filepath.Join(dir, name+".key"))
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, fmt.Errorf("system key %s: no PEM", name)
	}
	k, err := x509.ParsePKCS1PrivateKey(blk.Bytes)
	if err != nil {
		return nil, err
	}
	s, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: k}, (&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		return nil, err
	}
	return &sysUser{name: name, audience: audience, signer: s}, nil
}

func (u *sysUser) bearer() (string, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.token != "" && time.Until(u.exp) > 5*time.Minute {
		return u.token, nil
	}
	now := time.Now()
	exp := now.Add(time.Hour)
	tok, err := jwt.Signed(u.signer).Claims(jwt.Claims{
		Issuer: u.name, Subject: u.name, Audience: jwt.Audience{u.audience},
		IssuedAt: jwt.NewNumericDate(now.Add(-10 * time.Second)), Expiry: jwt.NewNumericDate(exp),
	}).Serialize()
	if err != nil {
		return "", err
	}
	u.token, u.exp = tok, exp
	return tok, nil
}

// Zitadel is one deployment reached at Base, with every instance behind it.
type Zitadel struct {
	Base        string // internal URL, e.g. http://i-zitadel:8080
	SystemHost  string // the first instance's domain: system API calls need some instance host
	Provisioner *sysUser
	Login       *sysUser
	HTTP        *http.Client
}

// NewZitadel loads the system users' keys.
func NewZitadel(base, systemHost, audience, keysDir string) (*Zitadel, error) {
	prov, err := loadSysUser(keysDir, "provisioner", audience)
	if err != nil {
		return nil, err
	}
	login, err := loadSysUser(keysDir, "login", audience)
	if err != nil {
		return nil, err
	}
	return &Zitadel{Base: base, SystemHost: systemHost, Provisioner: prov, Login: login, HTTP: &http.Client{Timeout: 30 * time.Second}}, nil
}

// At addresses one instance: instanceHost picks it, publicHost (optional) is the origin Zitadel
// builds URLs and the issuer from (must be the instance domain or one of its trusted domains).
type At struct {
	InstanceHost string
	PublicHost   string
}

// Call does a JSON request against one instance (or the system API with At{SystemHost}).
func (z *Zitadel) Call(ctx context.Context, as *sysUser, at At, method, path string, body, out any) error {
	return z.call(ctx, as, at, nil, method, path, body, out)
}

func (z *Zitadel) call(ctx context.Context, as *sysUser, at At, extra map[string]string, method, path string, body, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, z.Base+path, rd)
	if err != nil {
		return err
	}
	if as != nil {
		tok, err := as.bearer()
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("x-zitadel-instance-host", at.InstanceHost)
	if at.PublicHost != "" {
		req.Header.Set("x-zitadel-public-host", at.PublicHost)
	}
	for k, v := range extra {
		req.Header.Set(k, v)
	}
	resp, err := z.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		e := &APIError{Status: resp.StatusCode, Method: method, Path: path, Body: string(raw)}
		var cb struct {
			Code any `json:"code"`
		}
		if json.Unmarshal(raw, &cb) == nil {
			switch c := cb.Code.(type) {
			case string:
				e.Code = c
			case float64: // grpc-gateway REST: numeric gRPC code
				e.Code = grpcCodeName(int(c))
			}
		}
		return e
	}
	if out != nil && len(raw) > 0 {
		return json.Unmarshal(raw, out)
	}
	return nil
}

func grpcCodeName(c int) string {
	names := map[int]string{3: "invalid_argument", 5: "not_found", 6: "already_exists", 7: "permission_denied",
		9: "failed_precondition", 12: "unimplemented", 13: "internal", 14: "unavailable", 16: "unauthenticated"}
	return names[c]
}

// IsNotFound: Zitadel says the object (or the instance) doesn't exist.
func IsNotFound(err error) bool {
	var ae *APIError
	return errors.As(err, &ae) && (ae.Code == "not_found" || ae.Status == http.StatusNotFound)
}
