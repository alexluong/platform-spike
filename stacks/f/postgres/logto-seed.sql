-- Stack f: the app's Management API client, seeded straight into Logto's database.
-- Logto OSS has no env/CLI way to create the first machine-to-machine app (the docs
-- say: create it in the admin console). This inserts one M2M app with a known secret
-- and gives it the pre-seeded "Logto Management API access" role (scope `all` on
-- https://default.logto.app/api). Idempotent. Runs after Logto has seeded its schema.
-- psql variables: client_id, client_secret.
\set ON_ERROR_STOP on
-- Upgrade safety: this runs on every `up`. Once the client exists, touch nothing, so a
-- later Logto release that renames or drops a column used below (e.g. the legacy
-- applications.secret) can't break the start of an existing stack. Only a fresh install
-- depends on the column list; if it fails there, it fails loudly (ON_ERROR_STOP) and the
-- app's bootstrap never starts.
SELECT EXISTS (SELECT 1 FROM applications WHERE tenant_id = 'default' AND id = :'client_id') AS seeded \gset
\if :seeded
  \echo 'logto-seed: client exists, nothing to do'
  \quit
\endif
BEGIN;
INSERT INTO applications (tenant_id, id, name, secret, description, type, oidc_client_metadata)
VALUES ('default', :'client_id', 'platform-spike-admin', :'client_secret',
        'Management API client for the platform-spike app (seeded by stacks/f)', 'MachineToMachine',
        '{"redirectUris": [], "postLogoutRedirectUris": []}')
ON CONFLICT (id) DO NOTHING;
INSERT INTO application_secrets (tenant_id, application_id, name, value)
VALUES ('default', :'client_id', 'default', :'client_secret')
ON CONFLICT DO NOTHING;
INSERT INTO applications_roles (tenant_id, id, application_id, role_id)
SELECT 'default', left(:'client_id' || 'role', 21), :'client_id', id
FROM roles WHERE tenant_id = 'default' AND name = 'Logto Management API access'
ON CONFLICT DO NOTHING;
COMMIT;
SELECT count(*) AS management_role_assigned FROM applications_roles WHERE application_id = :'client_id';
