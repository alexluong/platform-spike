-- Round 4 (SPEC §16): pools. Neutral app-side facts only; which IdP holds a pool is the
-- identity adapter's business (stack i keeps its directory in its own table).
--
-- Membership moves from users.merchant_id to its own table: a platform account may be a
-- member of several merchants (partners, §16.2). Stacks a/b/f/h/a2 keep "one merchant per
-- user" as a module rule (MultiMerchant off).
CREATE TABLE memberships (
  user_id     text NOT NULL REFERENCES users(id),
  merchant_id text NOT NULL REFERENCES merchants(id),
  created_at  timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (user_id, merchant_id)
);
CREATE INDEX ON memberships(merchant_id);
INSERT INTO memberships(user_id, merchant_id) SELECT id, merchant_id FROM users WHERE merchant_id IS NOT NULL;
ALTER TABLE users DROP COLUMN merchant_id;

-- Pools: '' = the platform-level pool of the user's kind (workforce for platform staff,
-- platform accounts for users, Shop for customers); 'm:<merchant>' = that merchant's tenant
-- pool (home_merchant_id). Emails are unique per pool, not globally (§16.4).
ALTER TABLE users ADD COLUMN pool text NOT NULL DEFAULT '';
ALTER TABLE users ADD COLUMN home_merchant_id text REFERENCES merchants(id);
ALTER TABLE users DROP CONSTRAINT users_email_key;
CREATE UNIQUE INDEX users_pool_email ON users(pool, kind, email) WHERE email IS NOT NULL;
ALTER TABLE users ALTER COLUMN email DROP NOT NULL;

-- A merchant's customer record linked to a Shop account (§16.5). Created by the first Shop
-- order or the first Sign in with Shop at that merchant; no email of its own (the Shop
-- account has it) and no identity until the buyer signs in with Shop there.
ALTER TABLE users ADD COLUMN shop_account_id text REFERENCES users(id);
ALTER TABLE users ALTER COLUMN idp_subject DROP NOT NULL;
CREATE UNIQUE INDEX users_shop_link ON users(home_merchant_id, shop_account_id) WHERE shop_account_id IS NOT NULL;

-- The merchant's tenant pool is ready (stacks that provision one per merchant set false at
-- create; the identity adapter reports readiness). Shown as status "provisioning".
ALTER TABLE merchants ADD COLUMN pool_ready boolean NOT NULL DEFAULT true;
