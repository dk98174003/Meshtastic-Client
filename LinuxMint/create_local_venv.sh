#!/usr/bin/env bash
set -euo pipefail

# create_local_venv.sh
# Dev helper: create a *local* venv for running meshtastic_client.py directly
# from the project folder (e.g. in VS Code).
#
# Key goals:
# - Make the project directory the current directory.
# - Keep it movable: no hard-coded absolute paths required.
# - Ensure Tkinter is installed at *system level* (it is not a pip package).

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEFAULT_PROJECT_DIR="$SCRIPT_DIR"

# Tip:
# If you run this script *from inside* the project folder, you can set:
#   MESHTASTIC_CLIENT_DIR="." ./create_local_venv.sh
# But the safest movable default is the folder where this script lives.

# You can override the project location when you move the folder:
#   MESHTASTIC_CLIENT_DIR=/path/to/Meshtastic_client ./create_local_venv.sh
# Or (only if you launch it from inside the repo):
#   MESHTASTIC_CLIENT_DIR="." ./create_local_venv.sh
PROJECT_DIR="${MESHTASTIC_CLIENT_DIR:-$DEFAULT_PROJECT_DIR}"

# Normalize to an absolute path (handles "." etc.)
PROJECT_DIR="$(realpath -m "$PROJECT_DIR")"

# Basic sanity checks
if [[ ! -d "$PROJECT_DIR" ]]; then
  echo "ERROR: Project dir not found: $PROJECT_DIR" >&2
  exit 1
fi

# If the script is inside the repo, this helps catch mis-pointing.
if [[ ! -f "$PROJECT_DIR/meshtastic_client.py" ]]; then
  echo "WARNING: meshtastic_client.py not found in: $PROJECT_DIR" >&2
  echo "         If you moved the repo, set MESHTASTIC_CLIENT_DIR to the new path." >&2
fi

VENV_DIR="$PROJECT_DIR/.venv"

echo "Project dir : $PROJECT_DIR"
echo "Local venv  : $VENV_DIR"

# Make PROJECT_DIR the current directory
cd "$PROJECT_DIR"

# --- Tkinter (system level) -------------------------------------------------
# Tkinter is provided by distro packages (Debian/Ubuntu/Mint: python3-tk).
# It cannot be installed reliably with pip inside a venv.

if ! python3 -c 'import tkinter' >/dev/null 2>&1; then
  echo
  echo "Tkinter is missing for system python3." >&2
  echo "Install it system-wide (Linux Mint / Ubuntu / Debian):" >&2
  echo "  sudo apt update" >&2
  echo "  sudo apt install -y python3-tk" >&2
  echo
  echo "After installing, re-run this script." >&2
  exit 2
fi

# --- venv -------------------------------------------------------------------
if [[ -d "$VENV_DIR" ]]; then
  echo "Local venv already exists at: $VENV_DIR"
  echo "If you want a fresh one, delete it first:"
  echo "  rm -rf \"$VENV_DIR\""
  exit 0
fi

echo "Creating virtualenv..."
python3 -m venv "$VENV_DIR"

echo "Upgrading pip inside venv..."
"$VENV_DIR/bin/pip" install --upgrade pip

echo "Installing dev dependencies into local venv..."
"$VENV_DIR/bin/pip" install \
  meshtastic \
  pyserial \
  pypubsub \
  protobuf \
  bleak

echo "Writing requirements.txt (for reference)..."
cat > "$PROJECT_DIR/requirements.txt" <<'REQ'
meshtastic
pyserial
pypubsub
protobuf
bleak
REQ

echo
echo "===================================================="
echo " Local dev venv ready."
echo " Path: $VENV_DIR"
echo
echo " In VS Code, select this interpreter:"
echo "   $VENV_DIR/bin/python"
echo
echo " To run locally from terminal:"
echo "   source \"$VENV_DIR/bin/activate\""
echo "   python meshtastic_client.py"
echo "===================================================="
