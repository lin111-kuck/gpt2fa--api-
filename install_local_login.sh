#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
set -euo pipefail
LOGIN_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
cd "$LOGIN_DIR"
command -v python3 >/dev/null || { echo 'Install Python 3.11+ and its venv package.' >&2; exit 1; }
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else "Python 3.11+ is required")'
command -v node >/dev/null || { echo 'Install Node.js, then rerun this script.' >&2; exit 1; }
node --version
if [[ ! -x .venv/bin/python ]]; then
    python3 -m venv .venv
fi
.venv/bin/python -m pip install -r requirements-local.txt
.venv/bin/python -c 'from zoneinfo import ZoneInfo; from wreq import Emulation, Platform; assert Emulation.Chrome152; assert Platform.Windows; print("Dependencies ready; timezone:", ZoneInfo("America/Los_Angeles"))'
echo 'Ready. Run .venv/bin/python -B batch_login.py --help or relogin_service.py --help.'
