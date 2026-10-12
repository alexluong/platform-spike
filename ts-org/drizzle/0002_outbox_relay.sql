CREATE TABLE "authz_consistency" (
	"id" integer PRIMARY KEY NOT NULL,
	"token" text NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "outbox" ADD COLUMN "processed_at" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "outbox" ADD COLUMN "attempts" integer DEFAULT 0 NOT NULL;--> statement-breakpoint
ALTER TABLE "outbox" ADD COLUMN "last_error" text;--> statement-breakpoint
CREATE INDEX "outbox_pending" ON "outbox" USING btree ("id") WHERE processed_at IS NULL;