-- Outbox consumers (SPEC §15.1): each event is written once per consumer that takes it,
-- in the same transaction; each consumer (the authz engine; the IdP's identity sync on
-- stack a2) drains its own rows in id order with its own retry state. Stacks a and b have
-- one consumer. partition_key (the merchant) lets a consumer order per merchant instead of
-- globally (the identity sync does: IdP writes are slow, a global queue serialized them).
ALTER TABLE outbox ADD COLUMN consumer text NOT NULL DEFAULT 'authz';
ALTER TABLE outbox ADD COLUMN partition_key text NOT NULL DEFAULT '';
DROP INDEX outbox_pending;
CREATE INDEX outbox_pending ON outbox(consumer, partition_key, id) WHERE processed_at IS NULL;

-- Invitations (SPEC §15.2): app-side; the invitee joins the merchant on accept.
CREATE TABLE invitations (
  id          text PRIMARY KEY,
  merchant_id text NOT NULL REFERENCES merchants(id),
  email       text NOT NULL,            -- lower-cased
  status      text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','accepted','cancelled')),
  invited_by  text NOT NULL REFERENCES users(id),
  accepted_by text REFERENCES users(id),
  created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ON invitations(merchant_id);
