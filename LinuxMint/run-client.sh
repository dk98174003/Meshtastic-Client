#!/usr/bin/env bash
set -euo pipefail

# Run from the *current directory* (.) so the project can be moved.
PROJECT_DIR="."
cd "$PROJECT_DIR"

# Load env vars from .envrc (if present)
if [[ -f ".envrc" ]]; then
  set -a
  # shellcheck disable=SC1091
  source ".envrc"
  set +a
fi

exec python3 meshtastic_client.py
