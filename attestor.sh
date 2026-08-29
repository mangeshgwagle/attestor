#!/bin/sh
set -eu

ATTESTOR_LAUNCH_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
if [ ! -f "$ATTESTOR_LAUNCH_DIR/attestor_cli.py" ]; then
    echo "attestor: unified CLI entry point is unavailable" >&2
    exit 4
fi

ATTESTOR_PYTHON=$(command -v python3 2>/dev/null || command -v python 2>/dev/null || true)
case "$ATTESTOR_PYTHON" in
    /*) exec "$ATTESTOR_PYTHON" -I -B -X utf8 "$ATTESTOR_LAUNCH_DIR/attestor_cli.py" "$@" ;;
    *) echo "attestor: Python 3 is unavailable" >&2; exit 4 ;;
esac
