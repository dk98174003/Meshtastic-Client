#!/usr/bin/env bash
set -euo pipefail

# rebuilddeb.sh
# Build a .deb from the *current directory* (PROJECT_DIR=".")
# and declare Tkinter as a system requirement (python3-tk).
#
# Usage:
#   cd /path/to/Meshtastic_client
#   ./rebuilddeb.sh

APP_NAME="meshtastic-client"
APP_VERSION="$(date +"1.0.%Y%m%d%H%M")"
PROJECT_DIR="."   # <-- always build from current directory
ICON_NAME="meshtastic.png"

APP_INSTALL_DIR="/opt/${APP_NAME}"

# --- helpers ---------------------------------------------------------------

die() { echo "ERROR: $*" >&2; exit 1; }

ensure_dir() {
  local d="${1:-}"
  [[ -n "$d" ]] || die "ensure_dir() got an empty path (this caused: mkdir: cannot create directory '' ...)"
  mkdir -p "$d"
}

# --- normalize paths --------------------------------------------------------

cd "$PROJECT_DIR" || die "Cannot cd to PROJECT_DIR=$PROJECT_DIR"
PROJECT_DIR="$(pwd -P)"

BUILD_DIR="$PROJECT_DIR/build"
LOG_DIR="$PROJECT_DIR/build_logs"
LOG_FILE="$LOG_DIR/rebuild_$(date +"%Y%m%d_%H%M%S").log"

ensure_dir "$LOG_DIR"

# Send all stdout/stderr to both terminal and log
exec > >(tee -a "$LOG_FILE") 2>&1

echo "=== Building ${APP_NAME} version ${APP_VERSION} ==="
echo "Project dir : ${PROJECT_DIR}"
echo "Build dir   : ${BUILD_DIR}"
echo "Log file    : ${LOG_FILE}"

# --- system requirement: Tkinter -------------------------------------------

# Tkinter must exist system-wide (Debian/Ubuntu/Mint package: python3-tk).
# It cannot be installed with pip inside a venv reliably.
if ! python3 -c 'import tkinter' >/dev/null 2>&1; then
  echo "ERROR: Tkinter is missing for system python3." >&2
  echo "Install it:" >&2
  echo "  sudo apt update && sudo apt install -y python3-tk" >&2
  exit 2
fi

# --- clean old build output -------------------------------------------------

echo "[1/6] Cleaning old build dir..."
rm -rf "$BUILD_DIR"
ensure_dir "$BUILD_DIR"

# --- create file layout -----------------------------------------------------

echo "[2/6] Creating directory structure in build tree..."
ensure_dir "$BUILD_DIR$APP_INSTALL_DIR"
ensure_dir "$BUILD_DIR/usr/local/bin"
ensure_dir "$BUILD_DIR/usr/share/applications"
ensure_dir "$BUILD_DIR/usr/share/icons/hicolor/256x256/apps"

# --- copy app code ----------------------------------------------------------

echo "[3/6] Copying application code..."
# Copy only what we need; ignore missing optional files.
for f in meshtastic_client.py README.md requirements.txt; do
  [[ -f "$PROJECT_DIR/$f" ]] && cp -a "$PROJECT_DIR/$f" "$BUILD_DIR$APP_INSTALL_DIR/"
done

if [[ -f "$PROJECT_DIR/$ICON_NAME" ]]; then
  cp -a "$PROJECT_DIR/$ICON_NAME" "$BUILD_DIR/usr/share/icons/hicolor/256x256/apps/${APP_NAME}.png"
else
  echo "WARNING: Icon $ICON_NAME not found in project dir."
fi

# --- create launcher --------------------------------------------------------

echo "[4/6] Generating launcher script /usr/local/bin/$APP_NAME..."
LAUNCHER="$BUILD_DIR/usr/local/bin/$APP_NAME"

cat > "$LAUNCHER" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

APP_NAME="meshtastic-client"
APP_DIR="/opt/${APP_NAME}"
DATA_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/${APP_NAME}"
VENV_DIR="${DATA_DIR}/venv"
PY_BIN="$(command -v python3 || true)"

if [[ -z "$PY_BIN" ]]; then
  echo "[${APP_NAME}] ERROR: python3 not found." >&2
  exit 1
fi

# Tkinter must be available at system level
if ! "$PY_BIN" -c 'import tkinter' >/dev/null 2>&1; then
  echo "[${APP_NAME}] ERROR: Tkinter is missing (install python3-tk)." >&2
  echo "  sudo apt update && sudo apt install -y python3-tk" >&2
  exit 2
fi

mkdir -p "$DATA_DIR"

if [[ ! -d "$VENV_DIR" ]]; then
  echo "[${APP_NAME}] Creating per-user venv at: $VENV_DIR"
  "$PY_BIN" -m venv "$VENV_DIR"

  PIP_BIN="$VENV_DIR/bin/pip"
  echo "[${APP_NAME}] Upgrading pip..."
  "$PIP_BIN" install --upgrade pip

  echo "[${APP_NAME}] Installing Python dependencies..."
  "$PIP_BIN" install \
    meshtastic \
    pyserial \
    pypubsub \
    protobuf \
    bleak

  echo "[${APP_NAME}] Virtualenv ready."
fi

exec "$VENV_DIR/bin/python" "${APP_DIR}/meshtastic_client.py" "$@"
EOF

chmod +x "$LAUNCHER"

# --- desktop file -----------------------------------------------------------

echo "[5/6] Creating .desktop file..."
DESKTOP_FILE="$BUILD_DIR/usr/share/applications/${APP_NAME}.desktop"

cat > "$DESKTOP_FILE" <<EOF
[Desktop Entry]
Type=Application
Name=Meshtastic Client
Comment=Meshtastic Desktop Client
Exec=/usr/local/bin/${APP_NAME}
Icon=${APP_NAME}
Terminal=false
Categories=Utility;
EOF

# --- build deb --------------------------------------------------------------

echo "[6/6] Building .deb using fpm..."
command -v fpm >/dev/null 2>&1 || die "fpm not found. Install it first (e.g. gem install --user-install fpm, or your preferred method)."

fpm -s dir -t deb -n "$APP_NAME" -v "$APP_VERSION" \
  --description "Meshtastic Desktop Client" \
  -d python3 \
  -d python3-venv \
  -d python3-pip \
  -d python3-tk \
  -C "$BUILD_DIR" \
  .

echo "======================================================"
echo " Build finished!"
echo " Created package (in current dir): ${APP_NAME}_${APP_VERSION}_amd64.deb"
echo " Log file: $LOG_FILE"
echo "======================================================"
