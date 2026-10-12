-- Links from app tables to Better Auth's organization tables (created by Better Auth's own
-- migrations, which run first at app start). Hand-written: drizzle-kit doesn't manage those tables.
-- SPEC §2/§15.1: one merchant per user, enforced where the IdP stores membership.
CREATE UNIQUE INDEX IF NOT EXISTS "member_one_merchant_per_user" ON "member" ("userId");
--> statement-breakpoint
ALTER TABLE "stores" ADD CONSTRAINT "stores_merchant_fk" FOREIGN KEY ("merchant_id") REFERENCES "organization"("id");
--> statement-breakpoint
ALTER TABLE "roles" ADD CONSTRAINT "roles_merchant_fk" FOREIGN KEY ("merchant_id") REFERENCES "organization"("id");
--> statement-breakpoint
ALTER TABLE "role_assignments" ADD CONSTRAINT "role_assignments_merchant_fk" FOREIGN KEY ("merchant_id") REFERENCES "organization"("id");
