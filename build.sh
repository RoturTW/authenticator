#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

# Compile the OSL backend and produce ./main.
osl compile main.osl

# Restart the authenticator service when the local manager is available.
if [ -x "../../rotur_manager.sh" ]; then
  ../../rotur_manager.sh restart authenticator
else
  echo "Built authenticator. rotur_manager.sh was not found; service was not restarted."
fi
