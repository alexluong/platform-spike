#!/usr/bin/env bash
# Start (or re-create with new env) the ps-zbench Zitadel. Generates the System API key pair
# once into .keys/ (gitignored). Extra env (ZBENCH_HANDLEACTIVEINSTANCES, ...) passes through.
#   DOCKER_HOST=ssh://cs-ws bench/zitadel-instances/up.sh
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p .keys
if [ ! -f .keys/system.pem ]; then
  openssl genrsa -out .keys/system.pem 2048 2>/dev/null
  openssl rsa -in .keys/system.pem -pubout -out .keys/system.pub 2>/dev/null
fi
export ZBENCH_SYSTEM_KEY="$(base64 < .keys/system.pub | tr -d '\n')"
docker compose -p ps-zbench -f compose.yaml up -d --wait "$@"
