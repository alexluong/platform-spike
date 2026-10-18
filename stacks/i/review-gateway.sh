#!/bin/sh
# Review probes for stack i's gateway (results/review-i.md): run on cs-ws (no DNS needed).
#   ssh cs-ws sh -s < stacks/i/review-gateway.sh
P=http://localhost:8096
H="Host: platform.cs.internal:8096"
echo "## paths (expect 404 at the gateway; 200 for keys)"
for p in /oauth/v2/keys "/oauth/v2/../../admin/v1/orgs/me" "/oauth/v2/%2e%2e/%2e%2e/admin/v1/orgs/me" "/oauth/v2/..%2f..%2fadmin/v1/orgs/me" \
  "/oidc/v1/../../v2/users" "/oauth/v2/../../system/v1/instances/_search" "/idps/callback/../../management/v1/orgs/me" "/oauth/v2//keys" \
  /admin/v1/healthz /debug/ready /v2/users /ui/console/; do
  printf "%-60s %s\n" "$p" "$(curl -s --path-as-is -o /dev/null -w '%{http_code} %{redirect_url}' -H "$H" "$P$p")"
done
echo "## pool-selecting headers (expect issuer http://platform.cs.internal:8096 or 404)"
D=/.well-known/openid-configuration
c() { n=$1; shift; printf "%-28s %s\n" "$n" "$(curl -s "$@" "$P$D" | sed -n 's/.*"issuer":"\([^"]*\)".*/\1/p;' | head -1)"; }
c base -H "$H"
c x-zitadel-instance-host -H "$H" -H "x-zitadel-instance-host: workforce.zitadel.internal" -H "x-zitadel-public-host: workforce.cs.internal:8096"
c upper-case -H "$H" -H "X-ZITADEL-INSTANCE-HOST: workforce.zitadel.internal"
c x-forwarded-host -H "$H" -H "X-Forwarded-Host: workforce.zitadel.internal"
c forwarded -H "$H" -H "Forwarded: host=workforce.zitadel.internal"
c x-zitadel-forwarded -H "$H" -H "x-zitadel-forwarded: host=workforce.zitadel.internal"
c host-upper -H "Host: PLATFORM.CS.INTERNAL:8096"
c host-trailing-dot -H "Host: platform.cs.internal.:8096"
c host-no-port -H "Host: platform.cs.internal"
c zitadel-instance-domain -H "Host: workforce.zitadel.internal:8080"
c http1.0-no-host --http1.0 -H "Host:"
