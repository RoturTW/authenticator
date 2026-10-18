#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

# rotur_manager.sh runs ./authenticator, so build to that name.
osl compile main.osl -o authenticator

if [ -x "../../rotur_manager.sh" ]; then
  ../../rotur_manager.sh restart authenticator
else
  echo "Built ./authenticator. rotur_manager.sh was not found, so the service was not restarted."
fi
