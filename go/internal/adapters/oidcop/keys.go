package oidcop

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"sync"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/alexluong/platform-spike/go/internal/db"
)

// Signing keys live in idp_signing_keys, shared by every instance. Each instance caches
// them for keyRefresh and reloads early when a token names a kid it doesn't know, so a key
// added by a rotation on another instance (or by the CLI) is picked up without a restart,
// and a retired key stops verifying within keyRefresh.
const (
	keyRefresh  = 30 * time.Second
	keyLockID   = 4243 // pg advisory lock: key creation and rotation
	missBackoff = 5 * time.Second
)

type sigKey struct {
	id       string
	priv     *ecdsa.PrivateKey
	signFrom time.Time
	retireAt *time.Time
}

// keyRing implements the key half of op.Storage and the verifier's oidc.KeySet.
type keyRing struct {
	db  *pgxpool.Pool
	enc cipher.AEAD

	mu       sync.Mutex
	keys     []sigKey
	loadedAt time.Time
	missAt   time.Time
}

func newKeyRing(pool *pgxpool.Pool, secret string) (*keyRing, error) {
	k := sha256.Sum256([]byte("idp-signing-key-encryption:" + secret))
	block, err := aes.NewCipher(k[:])
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &keyRing{db: pool, enc: aead}, nil
}

// ensure creates the first key if there is no live one. Under an advisory lock, so
// instances starting together on an empty table agree on one key (review-g #3).
func (k *keyRing) ensure(ctx context.Context) error {
	return k.locked(ctx, func(tx pgx.Tx) error {
		var n int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM idp_signing_keys WHERE retire_at IS NULL OR retire_at > now()`).Scan(&n); err != nil {
			return err
		}
		if n > 0 {
			return nil
		}
		return k.insert(ctx, tx, time.Now())
	})
}

// rotate publishes a new key that starts signing after publishAhead (every instance and
// any JWKS cache has seen it by then) and retires the current ones retireAfter later
// (tokens they signed have expired by then). For a compromised key, call retire instead.
func (k *keyRing) rotate(ctx context.Context, publishAhead, retireAfter time.Duration) error {
	return k.locked(ctx, func(tx pgx.Tx) error {
		signFrom := time.Now().Add(publishAhead)
		if _, err := tx.Exec(ctx, `UPDATE idp_signing_keys SET retire_at=$1 WHERE retire_at IS NULL`, signFrom.Add(retireAfter)); err != nil {
			return err
		}
		return k.insert(ctx, tx, signFrom)
	})
}

func (k *keyRing) locked(ctx context.Context, f func(pgx.Tx) error) error {
	return pgx.BeginFunc(ctx, k.db, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, keyLockID); err != nil {
			return err
		}
		return f(tx)
	})
}

func (k *keyRing) insert(ctx context.Context, tx pgx.Tx, signFrom time.Time) error {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return err
	}
	nonce := make([]byte, k.enc.NonceSize())
	_, _ = rand.Read(nonce)
	id := db.NewID("key")
	_, err = tx.Exec(ctx, `INSERT INTO idp_signing_keys(id, alg, private_enc, sign_from) VALUES ($1,'ES256',$2,$3)`,
		id, k.enc.Seal(nonce, nonce, der, []byte(id)), signFrom)
	return err
}

// live returns the keys that verify now (published, not retired), reloading when stale.
func (k *keyRing) live(ctx context.Context, force bool) ([]sigKey, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if !force && time.Since(k.loadedAt) < keyRefresh {
		return k.keys, nil
	}
	rows, err := k.db.Query(ctx, `SELECT id, private_enc, sign_from, retire_at FROM idp_signing_keys
		WHERE retire_at IS NULL OR retire_at > now() ORDER BY sign_from`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var keys []sigKey
	for rows.Next() {
		var sk sigKey
		var enc []byte
		if err := rows.Scan(&sk.id, &enc, &sk.signFrom, &sk.retireAt); err != nil {
			return nil, err
		}
		ns := k.enc.NonceSize()
		if len(enc) < ns {
			return nil, fmt.Errorf("signing key %s: short ciphertext", sk.id)
		}
		der, err := k.enc.Open(nil, enc[:ns], enc[ns:], []byte(sk.id))
		if err != nil {
			return nil, fmt.Errorf("signing key %s: decrypt (wrong ISSUER_SECRET?): %w", sk.id, err)
		}
		p, err := x509.ParsePKCS8PrivateKey(der)
		if err != nil {
			return nil, err
		}
		var ok bool
		if sk.priv, ok = p.(*ecdsa.PrivateKey); !ok {
			return nil, fmt.Errorf("signing key %s: not ECDSA", sk.id)
		}
		keys = append(keys, sk)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	k.keys, k.loadedAt = keys, time.Now()
	return keys, nil
}

// signing: the newest key whose sign_from has passed. With no live key at all (every key
// retired, e.g. a leaked key retired by hand), create one rather than fail every login
// until a restart; ensure's lock keeps that to one key across instances.
func (k *keyRing) signing(ctx context.Context) (sigKey, error) {
	keys, err := k.live(ctx, false)
	if err != nil {
		return sigKey{}, err
	}
	if len(keys) == 0 {
		if err := k.ensure(ctx); err != nil {
			return sigKey{}, err
		}
		if keys, err = k.live(ctx, true); err != nil {
			return sigKey{}, err
		}
	}
	now := time.Now()
	for i := len(keys) - 1; i >= 0; i-- {
		if !keys[i].signFrom.After(now) {
			return keys[i], nil
		}
	}
	return sigKey{}, errors.New("no signing key")
}

// VerifySignature implements oidc.KeySet for the in-process verifier: the kid must be a
// live key; an unknown kid forces a reload (at most every missBackoff).
func (k *keyRing) VerifySignature(ctx context.Context, jws *jose.JSONWebSignature) ([]byte, error) {
	if len(jws.Signatures) != 1 {
		return nil, errors.New("expected one signature")
	}
	h := jws.Signatures[0].Header
	if h.Algorithm != string(jose.ES256) {
		return nil, fmt.Errorf("alg %q not allowed", h.Algorithm)
	}
	find := func(keys []sigKey) *ecdsa.PublicKey {
		for _, sk := range keys {
			if sk.id == h.KeyID {
				return &sk.priv.PublicKey
			}
		}
		return nil
	}
	keys, err := k.live(ctx, false)
	if err != nil {
		return nil, err
	}
	pub := find(keys)
	if pub == nil {
		k.mu.Lock()
		retry := time.Since(k.missAt) > missBackoff
		if retry {
			k.missAt = time.Now()
		}
		k.mu.Unlock()
		if retry {
			if keys, err = k.live(ctx, true); err != nil {
				return nil, err
			}
			pub = find(keys)
		}
	}
	if pub == nil {
		return nil, fmt.Errorf("unknown kid %q", h.KeyID)
	}
	return jws.Verify(pub)
}

// op.SigningKey and op.Key views of a sigKey.
type signingKey struct{ sigKey }

func (s signingKey) SignatureAlgorithm() jose.SignatureAlgorithm { return jose.ES256 }
func (s signingKey) Key() any                                    { return s.priv }
func (s signingKey) ID() string                                  { return s.id }

type publicKey struct{ sigKey }

func (p publicKey) ID() string                         { return p.id }
func (p publicKey) Algorithm() jose.SignatureAlgorithm { return jose.ES256 }
func (p publicKey) Use() string                        { return "sig" }
func (p publicKey) Key() any                           { return &p.priv.PublicKey }

var _ op.SigningKey = signingKey{}
var _ op.Key = publicKey{}
