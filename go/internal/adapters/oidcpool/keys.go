package oidcpool

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

// Signing keys live in idp_signing_keys, one set per pool, shared by every instance. Each
// instance caches a pool's keys for keyRefresh once that pool is used, and reloads early when a
// token names a kid it doesn't know, so a key added by a rotation on another instance (or by the
// CLI, or by a merchant being provisioned) is picked up without a restart, and a retired key stops
// verifying within keyRefresh. Pools nobody uses cost nothing in memory.
const (
	keyRefresh  = 30 * time.Second
	keyLockID   = 4243 // pg advisory lock (with hashtext(pool)): key creation and rotation per pool
	missBackoff = 5 * time.Second
)

type sigKey struct {
	id       string
	priv     *ecdsa.PrivateKey
	signFrom time.Time
	retireAt *time.Time
}

type poolKeys struct {
	keys     []sigKey
	loadedAt time.Time
	missAt   time.Time
}

// keyRing holds every pool's keys; the pool comes from the caller (or the request context).
type keyRing struct {
	db  *pgxpool.Pool
	enc cipher.AEAD

	mu    sync.Mutex
	pools map[string]*poolKeys
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
	return &keyRing{db: pool, enc: aead, pools: map[string]*poolKeys{}}, nil
}

func (k *keyRing) seal(plain []byte, aad string) []byte {
	nonce := make([]byte, k.enc.NonceSize())
	_, _ = rand.Read(nonce)
	return k.enc.Seal(nonce, nonce, plain, []byte(aad))
}

func (k *keyRing) open(enc []byte, aad string) ([]byte, error) {
	ns := k.enc.NonceSize()
	if len(enc) < ns {
		return nil, errors.New("short ciphertext")
	}
	return k.enc.Open(nil, enc[:ns], enc[ns:], []byte(aad))
}

// ensure creates the pool's first key if it has no live one. Under an advisory lock per pool,
// so instances starting together agree on one key (review-g #3).
func (k *keyRing) ensure(ctx context.Context, poolID string) error {
	return k.locked(ctx, poolID, func(tx pgx.Tx) error {
		var n int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM idp_signing_keys WHERE pool_id=$1 AND (retire_at IS NULL OR retire_at > now())`, poolID).Scan(&n); err != nil {
			return err
		}
		if n > 0 {
			return nil
		}
		return k.insert(ctx, tx, poolID, time.Now())
	})
}

// rotate publishes a new key for the pool that starts signing after publishAhead and retires
// its current ones retireAfter later. For a compromised key, retire it instead.
func (k *keyRing) rotate(ctx context.Context, poolID string, publishAhead, retireAfter time.Duration) error {
	return k.locked(ctx, poolID, func(tx pgx.Tx) error {
		signFrom := time.Now().Add(publishAhead)
		if _, err := tx.Exec(ctx, `UPDATE idp_signing_keys SET retire_at=$2 WHERE pool_id=$1 AND retire_at IS NULL`, poolID, signFrom.Add(retireAfter)); err != nil {
			return err
		}
		return k.insert(ctx, tx, poolID, signFrom)
	})
}

func (k *keyRing) locked(ctx context.Context, poolID string, f func(pgx.Tx) error) error {
	return pgx.BeginFunc(ctx, k.db, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1, hashtext($2))`, keyLockID, poolID); err != nil {
			return err
		}
		return f(tx)
	})
}

// insert writes a new key for the pool through q: a locked tx (ensure, rotate) or the
// merchant-create transaction (a new pool has no keys to race with).
func (k *keyRing) insert(ctx context.Context, q db.Querier, poolID string, signFrom time.Time) error {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return err
	}
	id := db.NewID("key")
	_, err = q.Exec(ctx, `INSERT INTO idp_signing_keys(id, pool_id, alg, private_enc, sign_from) VALUES ($1,$2,'ES256',$3,$4)`,
		id, poolID, k.seal(der, id), signFrom)
	return err
}

// live returns the pool's keys that verify now (published, not retired), reloading when stale.
func (k *keyRing) live(ctx context.Context, poolID string, force bool) ([]sigKey, error) {
	k.mu.Lock()
	pk, ok := k.pools[poolID]
	if !ok {
		pk = &poolKeys{}
		k.pools[poolID] = pk
	}
	if !force && time.Since(pk.loadedAt) < keyRefresh {
		keys := pk.keys
		k.mu.Unlock()
		return keys, nil
	}
	k.mu.Unlock()
	keys, err := k.load(ctx, poolID)
	if err != nil {
		return nil, err
	}
	k.mu.Lock()
	pk.keys, pk.loadedAt = keys, time.Now()
	k.mu.Unlock()
	return keys, nil
}

func (k *keyRing) load(ctx context.Context, poolID string) ([]sigKey, error) {
	rows, err := k.db.Query(ctx, `SELECT id, private_enc, sign_from, retire_at FROM idp_signing_keys
		WHERE pool_id=$1 AND (retire_at IS NULL OR retire_at > now()) ORDER BY sign_from`, poolID)
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
		der, err := k.open(enc, sk.id)
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
	return keys, rows.Err()
}

// signing: the pool's newest key whose sign_from has passed. With no live key at all (every key
// retired by hand), create one rather than fail every login of the pool until a restart.
func (k *keyRing) signing(ctx context.Context, poolID string) (sigKey, error) {
	keys, err := k.live(ctx, poolID, false)
	if err != nil {
		return sigKey{}, err
	}
	if len(keys) == 0 {
		if err := k.ensure(ctx, poolID); err != nil {
			return sigKey{}, err
		}
		if keys, err = k.live(ctx, poolID, true); err != nil {
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

// verify checks a JWS against the pool's live keys only (a token signed by another pool's key
// fails here even before the issuer check); an unknown kid forces a reload (at most every
// missBackoff per pool).
func (k *keyRing) verify(ctx context.Context, poolID string, jws *jose.JSONWebSignature) ([]byte, error) {
	if poolID == "" {
		return nil, errors.New("no pool")
	}
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
	keys, err := k.live(ctx, poolID, false)
	if err != nil {
		return nil, err
	}
	pub := find(keys)
	if pub == nil {
		k.mu.Lock()
		pk := k.pools[poolID]
		retry := time.Since(pk.missAt) > missBackoff
		if retry {
			pk.missAt = time.Now()
		}
		k.mu.Unlock()
		if retry {
			if keys, err = k.live(ctx, poolID, true); err != nil {
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

// poolKeySet is an oidc.KeySet for one pool (the app's verifier: pool from the token's issuer).
type poolKeySet struct {
	ring *keyRing
	pool string
}

func (p poolKeySet) VerifySignature(ctx context.Context, jws *jose.JSONWebSignature) ([]byte, error) {
	return p.ring.verify(ctx, p.pool, jws)
}

// ctxKeySet is an oidc.KeySet for the provider's own verifiers (userinfo, id_token_hint): the
// pool is the one the request's path named (poolFrom).
type ctxKeySet struct{ ring *keyRing }

func (c ctxKeySet) VerifySignature(ctx context.Context, jws *jose.JSONWebSignature) ([]byte, error) {
	p := poolFrom(ctx)
	if p == nil {
		return nil, errors.New("no pool")
	}
	return c.ring.verify(ctx, p.ID, jws)
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
