#!/usr/bin/env sh
set -eu
cd -- "$(dirname -- "$0")"
exec python3 -I -B -X utf8 detector/owner_control42.py "$@"
