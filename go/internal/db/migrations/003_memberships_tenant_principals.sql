-- Round 4 (SPEC §16.2, §16.4, §16.5), shared by every Go stack:
-- * membership moves from users.merchant_id to a table, so a platform account can belong to
--   several merchants (partners). Stacks that keep "one merchant per user" enforce it in the
--   module (no tenant pools = MultiMerchant off), not in the schema.
-- * users.home_merchant_id: a principal that belongs to a merchant's own pool (tenant staff,
--   tenant customers, a merchant's customer record linked to a Shop account). NULL for
--   platform-level principals (staff, platform accounts, Shop accounts).
-- * users.shop_account_id: a merchant's customer record linked to a Shop account. Its
--   idp_subject is NULL until the buyer signs in with Shop at that merchant.
-- * merchants.pool_ready: false while an adapter that provisions the tenant pool after the
--   merchant's transaction (stack i) builds it; shown as status "provisioning".
-- * orders.merchant_customer_id: the merchant's customer record an order belongs to (the
--   placing principal, or for a Shop-token order the merchant's record linked to it).
CREATE TABLE memberships (
  user_id     text NOT NULL REFERENCES users(id),
  merchant_id text NOT NULL REFERENCES merchants(id),
  created_at  timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (user_id, merchant_id)
);
CREATE INDEX ON memberships(merchant_id);
INSERT INTO memberships(user_id, merchant_id) SELECT id, merchant_id FROM users WHERE merchant_id IS NOT NULL;

ALTER TABLE users RENAME COLUMN merchant_id TO home_merchant_id;
UPDATE users SET home_merchant_id = NULL;
ALTER TABLE users ADD CONSTRAINT users_home_merchant_fk FOREIGN KEY (home_merchant_id) REFERENCES merchants(id);
ALTER TABLE users ADD COLUMN shop_account_id text REFERENCES users(id);
ALTER TABLE users ALTER COLUMN idp_subject DROP NOT NULL;
ALTER TABLE users ALTER COLUMN email DROP NOT NULL;
ALTER TABLE users DROP CONSTRAINT users_email_key;
CREATE UNIQUE INDEX users_email_platform ON users(email) WHERE home_merchant_id IS NULL;
CREATE UNIQUE INDEX users_email_tenant ON users(home_merchant_id, kind, email) WHERE home_merchant_id IS NOT NULL AND email IS NOT NULL;
CREATE UNIQUE INDEX users_shop_link ON users(home_merchant_id, shop_account_id) WHERE shop_account_id IS NOT NULL;

ALTER TABLE orders ADD COLUMN merchant_customer_id text REFERENCES users(id);
CREATE INDEX ON orders(merchant_customer_id);

ALTER TABLE merchants ADD COLUMN pool_ready boolean NOT NULL DEFAULT true;
