-- Stack i (IDP=zitadel-instances): the pool directory. Owned by the Zitadel adapter (the
-- control plane's routing directory in the platform design): pool → instance domain (what the
-- gateway puts in x-zitadel-instance-host), public host and issuer, provisioning progress.
CREATE TABLE IF NOT EXISTS zitadel_pools (
  pool            text PRIMARY KEY,          -- workforce | platform | m:<merchant id>
  merchant_id     text UNIQUE,
  label           text NOT NULL UNIQUE,      -- first DNS label of the public host
  instance_domain text NOT NULL UNIQUE,      -- internal only, never in DNS
  public_host     text NOT NULL UNIQUE,      -- <label>.<ID_DOMAIN>:<port>; a trusted domain of the instance
  issuer          text NOT NULL UNIQUE,      -- http://<public host>
  instance_id     text,
  orgs            jsonb NOT NULL DEFAULT '{}',
  project_id      text,                      -- login project (tokens' audience)
  client_id       text,                      -- login app (PKCE)
  shop_idp_id     text,                      -- merchant pools: the "Shop" generic OIDC IdP on org customers
  status          text NOT NULL DEFAULT 'provisioning' CHECK (status IN ('provisioning','active')),
  blocked         boolean NOT NULL DEFAULT false,  -- desired: the merchant is suspended
  created_at      timestamptz NOT NULL DEFAULT now(),
  ready_at        timestamptz
);
