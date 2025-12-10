#!/bin/bash
set -e

### CONFIG ############################################################

APP_NAME="meshtastic-client"
APP_VERSION=$(date +"1.0.%Y%m%d%H%M")
PROJECT_DIR="/home/knud/Desktop/Meshtastic/Meshtastic_client"
BUILD_DIR="$PROJECT_DIR/build"
ICON_NAME="meshtastic.png"

APP_INSTALL_DIR="/opt/${APP_NAME}"

# Logging
LOG_DIR="$PROJECT_DIR/build_logs"
mkdir -p "$LOG_DIR"
LOG_FILE="$LOG_DIR/rebuild_$(date +\"%Y%m%d_%H%M%S\").log"

# Send all stdout/stderr to both terminal and log
exec > >(tee -a "$LOG_FILE") 2>&1

echo "Logging to: $LOG_FILE"

######################################################################

echo "=== Building $APP_NAME version $APP_VERSION ==="
cd "$PROJECT_DIR" || exit 1

### CLEAN OLD BUILD OUTPUT ###########################################

echo "[1/5] Cleaning old build dir..."
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"

### CREATE FILE LAYOUT ################################################
# We do **NOT** bundle a pre-built venv in the .deb anymore.
# Instead we install the app code + a small launcher that creates
# a per-user venv on first run under ~/.local/share/${APP_NAME}/venv.

echo "[2/5] Creating directory structure in build tree..."

# App code location on target system (read-only, root-owned)
mkdir -p "$BUILD_DIR${APP_INSTALL_DIR}"

# Launcher + desktop file + icon
mkdir -p "$BUILD_DIR/usr/local/bin"
mkdir -p "$BUILD_DIR/usr/share/applications"
mkdir -p "$BUILD_DIR/usr/share/icons/hicolor/48x48/apps"

### COPY APPLICATION CODE ############################################

echo "[3/5] Copying application code..."

cp "$PROJECT_DIR/meshtastic_client.py" "$BUILD_DIR${APP_INSTALL_DIR}/meshtastic_client.py"

if [ -f "$PROJECT_DIR/$ICON_NAME" ]; then
  cp "$PROJECT_DIR/$ICON_NAME" "$BUILD_DIR/usr/share/icons/hicolor/48x48/apps/${APP_NAME}.png"
else
  echo "  (Warning: $ICON_NAME not found, skipping icon copy)"
fi

### CREATE LAUNCHER SCRIPT ###########################################

echo "[4/5] Generating launcher script /usr/local/bin/${APP_NAME}..."

LAUNCHER="$BUILD_DIR/usr/local/bin/${APP_NAME}"

cat > "$LAUNCHER" << 'EOF'
#!/bin/bash
set -e

APP_NAME="meshtastic-client"
APP_DIR="/opt/${APP_NAME}"

# Per-user venv location (no root needed)
USER_DATA_ROOT="${XDG_DATA_HOME:-$HOME/.local/share}"
USER_APP_DIR="${USER_DATA_ROOT}/${APP_NAME}"
VENV_DIR="${USER_APP_DIR}/venv"

PY_BIN="${VENV_DIR}/bin/python"
PIP_BIN="${VENV_DIR}/bin/pip"

# Create venv + install deps on first start
if [ ! -x "$PY_BIN" ]; then
  mkdir -p "$USER_APP_DIR"
  echo "[${APP_NAME}] Creating virtualenv in $VENV_DIR ..."
  python3 -m venv "$VENV_DIR"

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

exec "$PY_BIN" "${APP_DIR}/meshtastic_client.py" "$@"
EOF

chmod +x "$LAUNCHER"

### CREATE .DESKTOP FILE #############################################

echo "[5/5] Creating .desktop file..."

DESKTOP_FILE="$BUILD_DIR/usr/share/applications/${APP_NAME}.desktop"

cat > "$DESKTOP_FILE" << EOF
[Desktop Entry]
Type=Application
Name=Meshtastic Client
Comment=Meshtastic Desktop Client GUI
Exec=${APP_NAME}
Icon=${APP_NAME}
Terminal=false
Categories=Network;Utility;
EOF

### BUILD .DEB PACKAGE ###############################################

echo "[9/9] Building .deb using fpm..."
fpm -s dir -t deb -n "$APP_NAME" -v "$APP_VERSION" \
  --description "Meshtastic Desktop Client" \
  -d python3 \
  -d python3-venv \
  -d python3-pip \
  -C "$BUILD_DIR" \
  .

echo "======================================================"
echo " Build finished!"
echo " Created package: ${APP_NAME}_${APP_VERSION}_amd64.deb"
echo " Log file: $LOG_FILE"
echo "======================================================"
