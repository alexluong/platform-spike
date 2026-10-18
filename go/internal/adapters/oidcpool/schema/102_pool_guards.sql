-- review-h2: cross-pool rows made unrepresentable. Every lookup already filters by pool_id; these
-- composite keys make the database refuse a row that ties one pool's protocol object to another
-- pool's user or request, whatever a query forgets. A login that marks pool A's auth request done
-- for pool B's user, a refresh token of pool A for pool B's user, or a federation state of pool A
-- for pool B's auth request is now a foreign-key error instead of a token.
ALTER TABLE idp_users ADD CONSTRAINT idp_users_id_pool UNIQUE (id, pool_id);
ALTER TABLE idp_auth_requests ADD CONSTRAINT idp_auth_requests_id_pool UNIQUE (id, pool_id);

-- user_id is NULL until the login step (MATCH SIMPLE: no check while NULL).
ALTER TABLE idp_auth_requests ADD CONSTRAINT idp_auth_requests_user_pool
  FOREIGN KEY (user_id, pool_id) REFERENCES idp_users(id, pool_id);
ALTER TABLE idp_refresh_tokens ADD CONSTRAINT idp_refresh_tokens_user_pool
  FOREIGN KEY (user_id, pool_id) REFERENCES idp_users(id, pool_id);
-- The sweep deletes expired auth requests; their federation states go with them.
DELETE FROM idp_federation_states s WHERE NOT EXISTS
  (SELECT 1 FROM idp_auth_requests a WHERE a.id = s.auth_request_id AND a.pool_id = s.pool_id);
ALTER TABLE idp_federation_states ADD CONSTRAINT idp_federation_states_request_pool
  FOREIGN KEY (auth_request_id, pool_id) REFERENCES idp_auth_requests(id, pool_id) ON DELETE CASCADE;
-- A federated identity names a real upstream pool.
ALTER TABLE idp_users ADD CONSTRAINT idp_users_upstream_pool
  FOREIGN KEY (upstream_pool) REFERENCES idp_pools(id);
