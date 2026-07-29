#!/usr/bin/env sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

if command -v python3 >/dev/null 2>&1; then
    exec python3 "$SCRIPT_DIR/src/recons101x.py" "$@"
fi

exec python "$SCRIPT_DIR/src/recons101x.py" "$@"
