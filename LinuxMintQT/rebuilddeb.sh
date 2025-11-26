#!/bin/bash
#
# Rebuild .deb for Meshtastic client
# - Installs a private venv with PySide6 + meshtastic + pubsub
# - Installs launcher, icon and .desktop file
#
# Requirements on the build machine:
#   sudo apt install python3-venv ruby-full
#   sudo gem install --no-document fpm
#
# Run from anywhere:
#   cd /home/knud/Desktop/Meshtastic/Meshtastic_client
#   ./rebuilddeb.sh
#

set -e

### CONFIG ############################################################

APP_NAME="meshtastic-client"
APP_VERSION=$(date +"1.0.%Y%m%d%H%M")
PROJECT_DIR="/home/knud/Desktop/Meshtastic/Meshtastic_client"
BUILD_DIR="$PROJECT_DIR/build"
ICON_NAME="meshtastic.png"
MAIN_PY_QT="meshtastic_client.py"

######################################################################

echo "=== Building $APP_NAME version $APP_VERSION (v1) ==="
cd "$PROJECT_DIR" || exit 1

### CLEAN OLD BUILD + DEB ############################################

echo "[1/9] Cleaning old build + .deb files..."
rm -rf "$BUILD_DIR"
rm -f "$PROJECT_DIR"/*.deb

### CREATE FOLDER STRUCTURE ##########################################

echo "[2/9] Creating folder structure in $BUILD_DIR ..."

# Program + venv
mkdir -p "$BUILD_DIR/usr/share/$APP_NAME"

# Launcher
mkdir -p "$BUILD_DIR/usr/bin"

# Desktop file
mkdir -p "$BUILD_DIR/usr/share/applications"

# Icon (512x512; other sizes can be added later)
mkdir -p "$BUILD_DIR/usr/share/icons/hicolor/512x512/apps"

### COPY PROGRAM FILES ################################################

echo "[3/9] Copying program + icon..."

if [ ! -f "$PROJECT_DIR/$MAIN_PY_QT" ]; then
    echo "ERROR: $MAIN_PY_QT not found in $PROJECT_DIR"
    exit 1
fi

cp "$PROJECT_DIR/$MAIN_PY_QT" "$BUILD_DIR/usr/share/$APP_NAME/"

if [ -f "$PROJECT_DIR/$ICON_NAME" ]; then
    cp "$PROJECT_DIR/$ICON_NAME" \
       "$BUILD_DIR/usr/share/icons/hicolor/512x512/apps/${APP_NAME}.png"
else
    echo "WARNING: $ICON_NAME not found – package will build without icon."
fi

### CREATE VENV + INSTALL PYTHON DEPENDENCIES ########################

echo "[4/9] Creating venv and installing Python dependencies..."

VENV_PATH="$BUILD_DIR/usr/share/$APP_NAME/venv"

python3 -m venv "$VENV_PATH"

# shellcheck disable=SC1090
source "$VENV_PATH/bin/activate"

pip install --upgrade pip

# Core libs for this app
pip install meshtastic PySide6 pubsub

deactivate

### CREATE LAUNCHER SCRIPT ###########################################

echo "[5/9] Creating launcher script..."

LAUNCHER="$BUILD_DIR/usr/bin/$APP_NAME"

cat > "$LAUNCHER" <<EOF
#!/bin/bash
APP_DIR="/usr/share/$APP_NAME"
VENV="\$APP_DIR/venv"

if [ ! -x "\$VENV/bin/python" ]; then
    echo "Meshtastic client venv missing. Reinstall the package." >&2
    exit 1
fi

exec "\$VENV/bin/python" "\$APP_DIR/$MAIN_PY_QT" "\$@"
EOF

chmod +x "$LAUNCHER"

### CREATE .DESKTOP FILE #############################################

echo "[6/9] Creating .desktop file..."

DESKTOP_FILE="$BUILD_DIR/usr/share/applications/${APP_NAME}.desktop"

cat > "$DESKTOP_FILE" <<EOF
[Desktop Entry]
Name=Meshtastic Client (v1)
Comment=Meshtastic Desktop Client (PySide6)
Exec=${APP_NAME}
Icon=${APP_NAME}
Terminal=false
Type=Application
Categories=Network;Utility;
EOF

### BASIC PERMISSIONS #################################################

echo "[7/9] Fixing permissions..."

find "$BUILD_DIR" -type d -exec chmod 755 {} \;
find "$BUILD_DIR" -type f -exec chmod 644 {} \;

# Launcher + venv binaries must be executable
chmod 755 "$LAUNCHER"
find "$VENV_PATH/bin" -type f -exec chmod 755 {} \; || true

### SHOW TREE (OPTIONAL) #############################################

echo "[8/9] Resulting tree under $BUILD_DIR:"
# tree might not be installed; ignore error if missing
command -v tree >/dev/null 2>&1 && tree "$BUILD_DIR" || true

### BUILD .DEB PACKAGE ###############################################

echo "[9/9] Building .deb using fpm..."

fpm -s dir -t deb -n "$APP_NAME" -v "$APP_VERSION" \
  --description "Meshtastic Desktop Client (v1)" \
  --architecture amd64 \
  -C "$BUILD_DIR" \
  .

echo "======================================================"
echo " Build finished!"
echo " Created package: ${APP_NAME}_${APP_VERSION}_amd64.deb"
echo "======================================================"

