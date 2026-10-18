-- Stack h2: the OIDC issuer runs inside the app (zitadel/oidc pkg/op) and keeps its state in the
-- app's database, as in stack h, with pools as rows (SPEC §16). Every issuer table carries pool_id:
-- each pool is its own issuer (PUBLIC_URL/oidc/<pool id>), with its own users, clients, auth
-- requests, refresh tokens and signing keys. Tables are prefixed idp_; the app's tables are separate.

-- Pools. workforce, platform and shop exist from the first start; one tenant pool per merchant is
-- created in the merchant-create transaction. merchant_id is opaque to the issuer (the directory key).
CREATE TABLE idp_pools (
  id                  text PRIMARY KEY,      -- issuer path segment: workforce | platform | shop | pl_<random>
  kind                text NOT NULL CHECK (kind IN ('workforce','platform','shop','tenant')),
  merchant_id         text UNIQUE,           -- tenant pools only
  status              text NOT NULL DEFAULT 'active' CHECK (status IN ('active','suspended')),
  upstream_client_id  text,                  -- tenant pools: this pool's client at the shop pool (Sign in with Shop)
  upstream_secret_enc bytea,                 -- its secret, AES-256-GCM (nonce || ciphertext), pool id in the AAD
  created_at          timestamptz NOT NULL DEFAULT now(),
  CHECK ((kind = 'tenant') = (merchant_id IS NOT NULL))
);
INSERT INTO idp_pools(id, kind) VALUES ('workforce','workforce'), ('platform','platform'), ('shop','shop');

-- Users. user_group keeps a tenant pool's staff and customers apart ('staff' | 'customers');
-- the platform-level pools have one group ('default'). Password users have an email and a hash;
-- users federated from an upstream pool (Sign in with Shop) have upstream_pool/upstream_sub and no
-- password. The token `sub` is id; the app sees "<pool>:<id>" (identity port subject).
CREATE TABLE idp_users (
  id            text PRIMARY KEY,
  pool_id       text NOT NULL REFERENCES idp_pools(id),
  user_group    text NOT NULL,
  email         text,
  password_hash text,                        -- PHC string, argon2id
  upstream_pool text,
  upstream_sub  text,
  disabled_at   timestamptz,
  created_at    timestamptz NOT NULL DEFAULT now(),
  UNIQUE (pool_id, user_group, email),
  UNIQUE (pool_id, upstream_pool, upstream_sub),
  CHECK ((password_hash IS NOT NULL AND email IS NOT NULL) OR upstream_sub IS NOT NULL)
);

-- Clients stored as rows: machine clients (apps, agents: client_credentials, in the platform pool)
-- and federation clients (a tenant pool's confidential client at the shop pool, code + PKCE, one
-- redirect URI). First-party login clients are virtual (config), the same in every pool of a kind.
CREATE TABLE idp_clients (
  id           text PRIMARY KEY,
  pool_id      text NOT NULL REFERENCES idp_pools(id),
  kind         text NOT NULL CHECK (kind IN ('machine','federation')),
  name         text NOT NULL,
  merchant_id  text,
  secret_hash  bytea NOT NULL,               -- sha256 of a 256-bit random secret
  redirect_uri text,                         -- federation clients
  created_at   timestamptz NOT NULL DEFAULT now(),
  deleted_at   timestamptz
);
CREATE INDEX ON idp_clients(pool_id);

-- Authorization requests from /authorize until the code is redeemed (or they expire). Every lookup
-- is by (id or code) AND pool_id: a code from one pool is unknown at another pool's token endpoint.
CREATE TABLE idp_auth_requests (
  id         text PRIMARY KEY,
  pool_id    text NOT NULL REFERENCES idp_pools(id),
  request    jsonb NOT NULL,
  user_id    text,
  auth_time  timestamptz,
  done       boolean NOT NULL DEFAULT false,
  code       text UNIQUE,
  code_used  boolean NOT NULL DEFAULT false,
  expires_at timestamptz NOT NULL
);
CREATE INDEX ON idp_auth_requests(expires_at);

-- Refresh tokens (login clients only), hashed, rotated on use, per pool.
CREATE TABLE idp_refresh_tokens (
  id         text PRIMARY KEY,               -- sha256(token), hex
  pool_id    text NOT NULL REFERENCES idp_pools(id),
  family     text NOT NULL,
  user_id    text NOT NULL,
  client_id  text NOT NULL,
  scopes     text[] NOT NULL,
  audience   text[] NOT NULL,
  amr        text[] NOT NULL,
  auth_time  timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  rotated_at timestamptz,
  revoked_at timestamptz
);
CREATE INDEX ON idp_refresh_tokens(family);
CREATE INDEX ON idp_refresh_tokens(user_id, client_id);

-- Signing keys, per pool: each pool's JWKS holds only its own keys.
CREATE TABLE idp_signing_keys (
  id          text PRIMARY KEY,              -- kid
  pool_id     text NOT NULL REFERENCES idp_pools(id),
  alg         text NOT NULL,
  private_enc bytea NOT NULL,                -- PKCS#8, AES-256-GCM (nonce || ciphertext), kid as AAD
  sign_from   timestamptz NOT NULL,
  retire_at   timestamptz,
  created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ON idp_signing_keys(pool_id);

-- Sign in with Shop: one row per upstream round trip, from the tenant pool's "Sign in with Shop"
-- step to the callback. Claimed once; bound to the user agent that started it (cookie).
CREATE TABLE idp_federation_states (
  id              text PRIMARY KEY,          -- sha256(state), hex
  pool_id         text NOT NULL REFERENCES idp_pools(id),
  auth_request_id text NOT NULL,
  verifier        text NOT NULL,             -- PKCE verifier for the upstream code exchange
  nonce           text NOT NULL,
  binding_hash    bytea NOT NULL,            -- sha256 of the cookie value
  used            boolean NOT NULL DEFAULT false,
  expires_at      timestamptz NOT NULL
);
CREATE INDEX ON idp_federation_states(expires_at);
