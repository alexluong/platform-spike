-- Stack f: the app's Management API client, seeded straight into Logto's database.
-- Logto OSS has no env/CLI way to create the first machine-to-machine app (the docs
-- say: create it in the admin console). This inserts one M2M app with a known secret
-- and gives it the pre-seeded "Logto Management API access" role (scope `all` on
-- https://default.logto.app/api). Idempotent. Runs after Logto has seeded its schema.
-- psql variables: client_id, client_secret.
\set ON_ERROR_STOP on
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
