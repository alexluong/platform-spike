-- Stack h: the OIDC issuer runs inside the app (zitadel/oidc pkg/op) and keeps its state
-- in the app's database. Tables are prefixed idp_; the app's own tables are unchanged.

-- Password users. id is the token `sub` (users.idp_subject).
CREATE TABLE idp_users (
  id            text PRIMARY KEY,
  email         text NOT NULL UNIQUE,
  password_hash text NOT NULL,               -- PHC string, argon2id
  disabled_at   timestamptz,
  created_at    timestamptz NOT NULL DEFAULT now()
);

-- Machine clients (apps, agents): client_credentials only. id = client_id = token `sub`.
CREATE TABLE idp_clients (
  id          text PRIMARY KEY,
  name        text NOT NULL,
  merchant_id text,
  secret_hash bytea NOT NULL,                -- sha256 of a 256-bit random secret
  created_at  timestamptz NOT NULL DEFAULT now(),
  deleted_at  timestamptz
);

-- Authorization requests from /authorize until the code is redeemed (or they expire).
CREATE TABLE idp_auth_requests (
  id         text PRIMARY KEY,
  request    jsonb NOT NULL,                 -- the validated request (client, redirect, scopes, PKCE, ...)
  user_id    text,
  auth_time  timestamptz,
  done       boolean NOT NULL DEFAULT false, -- set by /login
  code       text UNIQUE,                    -- one code per request
  code_used  boolean NOT NULL DEFAULT false, -- claimed atomically by the token endpoint
  expires_at timestamptz NOT NULL
);
CREATE INDEX ON idp_auth_requests(expires_at);

-- Refresh tokens (first-party login client only), stored hashed, rotated on use.
-- Reusing a rotated token revokes its whole family.
CREATE TABLE idp_refresh_tokens (
  id         text PRIMARY KEY,               -- sha256(token), hex
  family     text NOT NULL,
  user_id    text NOT NULL,
  client_id  text NOT NULL,
  scopes     text[] NOT NULL,
  audience   text[] NOT NULL,
  amr        text[] NOT NULL,
  auth_time  timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,           -- absolute: rotation doesn't extend it
  rotated_at timestamptz,
  revoked_at timestamptz
);
CREATE INDEX ON idp_refresh_tokens(family);
CREATE INDEX ON idp_refresh_tokens(user_id, client_id);

-- Signing keys. A new key is published (JWKS) before it signs; an old one keeps verifying
-- until retire_at. Private keys are encrypted with the issuer secret.
CREATE TABLE idp_signing_keys (
  id          text PRIMARY KEY,              -- kid
  alg         text NOT NULL,
  private_enc bytea NOT NULL,                -- PKCS#8, AES-256-GCM (nonce || ciphertext)
  sign_from   timestamptz NOT NULL,
  retire_at   timestamptz,
  created_at  timestamptz NOT NULL DEFAULT now()
);
