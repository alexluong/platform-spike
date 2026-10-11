-- App DB: the source of truth (SPEC §1.4). The authz engine gets a copy via the outbox.
CREATE TABLE users (
  id            text PRIMARY KEY,
  idp_subject   text NOT NULL UNIQUE,
  email         text NOT NULL UNIQUE,
  kind          text NOT NULL CHECK (kind IN ('platform','user','customer')),
  platform_role text,
  merchant_id   text,
  created_at    timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE merchants (
  id         text PRIMARY KEY,
  name       text NOT NULL,
  status     text NOT NULL DEFAULT 'active' CHECK (status IN ('active','suspended')),
  created_at timestamptz NOT NULL DEFAULT now()
);

-- Custom roles only; system roles live in code (perm.SystemRoles).
CREATE TABLE roles (
  id                 text PRIMARY KEY,
  merchant_id        text NOT NULL REFERENCES merchants(id),
  name               text NOT NULL,
  permissions        text[] NOT NULL,
  refund_limit_cents bigint,
  created_at         timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ON roles(merchant_id);

CREATE TABLE stores (
  id          text PRIMARY KEY,
  merchant_id text NOT NULL REFERENCES merchants(id),
  name        text NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ON stores(merchant_id);

CREATE TABLE role_assignments (
  id          text PRIMARY KEY,
  merchant_id text NOT NULL REFERENCES merchants(id),
  user_id     text NOT NULL REFERENCES users(id),
  role_id     text NOT NULL,   -- system role id or roles.id
  scope_type  text NOT NULL CHECK (scope_type IN ('merchant','store')),
  scope_id    text NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ON role_assignments(merchant_id);
CREATE INDEX ON role_assignments(user_id);
CREATE INDEX ON role_assignments(role_id);

CREATE TABLE products (
  id          text PRIMARY KEY,
  merchant_id text NOT NULL,
  store_id    text NOT NULL REFERENCES stores(id),
  title       text NOT NULL,
  price_cents bigint NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ON products(store_id);

CREATE TABLE orders (
  id             text PRIMARY KEY,
  merchant_id    text NOT NULL,
  store_id       text NOT NULL REFERENCES stores(id),
  customer_id    text NOT NULL REFERENCES users(id),
  items          jsonb NOT NULL,
  total_cents    bigint NOT NULL,
  status         text NOT NULL,
  refunded_cents bigint NOT NULL DEFAULT 0,
  created_at     timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ON orders(store_id);
CREATE INDEX ON orders(customer_id);

CREATE TABLE payments (
  id           text PRIMARY KEY,
  merchant_id  text NOT NULL,
  order_id     text NOT NULL REFERENCES orders(id),
  status       text NOT NULL,
  amount_cents bigint NOT NULL,
  created_at   timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ON payments(order_id);

CREATE TABLE shipments (
  id          text PRIMARY KEY,
  merchant_id text NOT NULL,
  order_id    text NOT NULL REFERENCES orders(id),
  carrier     text NOT NULL,
  status      text NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ON shipments(order_id);

CREATE TABLE apps (
  id          text PRIMARY KEY,
  name        text NOT NULL,
  scopes      text[] NOT NULL,
  client_id   text NOT NULL,
  idp_subject text NOT NULL UNIQUE,
  created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE app_installs (
  id          text PRIMARY KEY,
  merchant_id text NOT NULL,
  store_id    text NOT NULL REFERENCES stores(id),
  app_id      text NOT NULL REFERENCES apps(id),
  scopes      text[] NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ON app_installs(store_id);

CREATE TABLE agents (
  id            text PRIMARY KEY,
  merchant_id   text NOT NULL REFERENCES merchants(id),
  owner_user_id text NOT NULL REFERENCES users(id),
  name          text NOT NULL,
  client_id     text NOT NULL,
  idp_subject   text NOT NULL UNIQUE,
  created_at    timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE agent_grants (
  id              text PRIMARY KEY,
  merchant_id     text NOT NULL,
  store_id        text NOT NULL REFERENCES stores(id),
  agent_id        text NOT NULL REFERENCES agents(id),
  grantor_user_id text NOT NULL REFERENCES users(id),
  permissions     text[] NOT NULL,
  expires_at      timestamptz NOT NULL,
  revoked_at      timestamptz,
  created_at      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ON agent_grants(agent_id);

CREATE TABLE break_glass (
  id          text PRIMARY KEY,
  merchant_id text NOT NULL REFERENCES merchants(id),
  staff_id    text NOT NULL REFERENCES users(id),
  reason      text NOT NULL,
  expires_at  timestamptz NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE audit (
  id          bigserial PRIMARY KEY,
  actor       text NOT NULL,
  action      text NOT NULL,
  merchant_id text,
  at          timestamptz NOT NULL
);
CREATE INDEX ON audit(merchant_id, id DESC);

-- Outbox: engine-neutral events, committed with the change (SPEC §1.4).
CREATE TABLE outbox (
  id           bigserial PRIMARY KEY,
  event        jsonb NOT NULL,
  created_at   timestamptz NOT NULL DEFAULT now(),
  processed_at timestamptz,
  attempts     int NOT NULL DEFAULT 0,
  last_error   text
);
CREATE INDEX outbox_pending ON outbox(id) WHERE processed_at IS NULL;
