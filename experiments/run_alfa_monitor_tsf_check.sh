#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON="$ROOT_DIR/.venv/bin/python"
RESULT_JSON="/tmp/wiguard_alfa_monitor_tsf_check.json"

if [[ ! -x "$PYTHON" ]]; then
  echo "Missing virtualenv Python at $PYTHON" >&2
  echo "Create it with: python3 -m venv .venv && .venv/bin/python -m pip install -r requirements.txt" >&2
  exit 1
fi

sudo rm -f "$RESULT_JSON"
sudo "$PYTHON" "$ROOT_DIR/experiments/alfa_rtl8812au_monitor_tsf_check.py" "$@" | sudo tee "$RESULT_JSON"
echo "Saved result to $RESULT_JSON"
