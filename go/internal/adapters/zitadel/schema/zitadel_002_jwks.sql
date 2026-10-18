-- Last good JWKS per pool: tokens of a blocked (suspended) instance stay verifiable after an
-- app restart or on another app instance.
ALTER TABLE zitadel_pools ADD COLUMN IF NOT EXISTS jwks jsonb;
