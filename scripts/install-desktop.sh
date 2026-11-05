#!/usr/bin/env bash
# Install a `bbt` command and an application-menu entry for BBT.
# Run as the desktop user (no root): bash scripts/install-desktop.sh
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

PYTHON=""
for candidate in "$REPO/.venv-sys/bin/python" "$REPO/.venv/bin/python" "$REPO/venv/bin/python"; do
    if [ -x "$candidate" ]; then
        PYTHON="$candidate"
        break
    fi
done
if [ -z "$PYTHON" ]; then
    PYTHON="$(command -v python3 || true)"
fi
if [ -z "$PYTHON" ]; then
    echo "python3 was not found; install Python 3 first." >&2
    exit 1
fi
if ! "$PYTHON" -c 'import bbt' >/dev/null 2>&1; then
    echo "warning: 'import bbt' failed with $PYTHON." >&2
    echo "         Run 'pip install -e .' in $REPO first." >&2
fi

BIN_DIR="${XDG_BIN_HOME:-$HOME/.local/bin}"
DATA_DIR="${XDG_DATA_HOME:-$HOME/.local/share}"
APP_DIR="$DATA_DIR/applications"
mkdir -p "$BIN_DIR" "$APP_DIR"

cat >"$BIN_DIR/bbt" <<EOF
#!/usr/bin/env bash
exec $(printf '%q' "$PYTHON") -m bbt "\$@"
EOF
chmod 755 "$BIN_DIR/bbt"

# The menu entry opens a terminal: prints help, then leaves an interactive
# shell with `bbt` on PATH so the window does not vanish after the help text.
cat >"$BIN_DIR/bbt-desktop" <<EOF
#!/usr/bin/env bash
cd $(printf '%q' "$REPO") || exit 1
export PATH=$(printf '%q' "$BIN_DIR"):"\$PATH"
$(printf '%q' "$BIN_DIR/bbt") --help
printf '\nRun: bbt -t https://TARGET -m auto --authorized --scope-file scope.txt\n\n'
exec "\${SHELL:-/bin/bash}" -i
EOF
chmod 755 "$BIN_DIR/bbt-desktop"

DESKTOP="$APP_DIR/bbt.desktop"
cat >"$DESKTOP" <<EOF
[Desktop Entry]
Type=Application
Version=1.0
Name=BBT - Bug Bounty Toolkit
GenericName=Bug Bounty Scanner
Comment=Authorized bug bounty reconnaissance, scanning and reporting
Exec="$BIN_DIR/bbt-desktop"
Icon=utilities-terminal
Terminal=true
Categories=System;Security;
Keywords=bbt;bug bounty;bounty;recon;scan;security;pentest;osint;
StartupNotify=true
EOF
chmod 644 "$DESKTOP"

update-desktop-database "$APP_DIR" >/dev/null 2>&1 || true
if command -v desktop-file-validate >/dev/null 2>&1; then
    desktop-file-validate "$DESKTOP" || true
fi

echo "Installed:"
echo "  command: $BIN_DIR/bbt"
echo "  menu:    $DESKTOP"
echo "Search the application menu for \"BBT\" or \"bug bounty\"."
