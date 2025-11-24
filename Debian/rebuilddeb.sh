#!/bin/bash

### CONFIG ############################################################

APP_NAME="meshtastic-client"
APP_VERSION=$(date +"1.0.%Y%m%d%H%M")
PROJECT_DIR="/home/knud/Desktop/Meshtastic/Meshtastic_client"
BUILD_DIR="$PROJECT_DIR/build"
ICON_NAME="meshtastic.png"

######################################################################

echo "=== Building $APP_NAME version $APP_VERSION ==="
cd "$PROJECT_DIR" || exit

### CLEAN OLD DEB FILES ##############################################

echo "[1/9] Removing old .deb packages..."
rm -f ${APP_NAME}_*.deb

### CLEAN BUILD FOLDER ###############################################

echo "[2/9] Cleaning build directory..."
rm -rf build
mkdir -p "$BUILD_DIR/usr/local/bin"
mkdir -p "$BUILD_DIR/usr/share/$APP_NAME"
mkdir -p "$BUILD_DIR/usr/share/applications"
mkdir -p "$BUILD_DIR/usr/share/icons/hicolor/48x48/apps"

### CREATE VENV ######################################################

echo "[3/9] Creating Python virtual environment..."
python3 -m venv venv

echo "[4/9] Installing Python dependencies..."
./venv/bin/python -m pip install --upgrade pip
./venv/bin/python -m pip install meshtastic pyserial bleak protobuf

### COPY PROGRAM FILES ##############################################

echo "[5/9] Copying program files to build folder..."
cp meshtastic_client.py "$BUILD_DIR/usr/share/$APP_NAME/"
cp meshtastic-client.desktop "$BUILD_DIR/usr/share/applications/"

if [ -f "$ICON_NAME" ]; then
    echo "[6/9] Copying icon..."
    cp "$ICON_NAME" "$BUILD_DIR/usr/share/icons/hicolor/48x48/apps/$ICON_NAME"
else
    echo "[6/9] WARNING: Icon file '$ICON_NAME' not found!"
fi

### COPY VENV ########################################################

echo "[7/9] Copying virtual environment..."
cp -r venv "$BUILD_DIR/usr/share/$APP_NAME/"

### CREATE LAUNCHER ##################################################

echo "[8/9] Creating launcher..."
cat <<EOF > "$BUILD_DIR/usr/local/bin/$APP_NAME"
#!/bin/bash
/usr/share/$APP_NAME/venv/bin/python /usr/share/$APP_NAME/meshtastic_client.py
EOF

chmod +x "$BUILD_DIR/usr/local/bin/$APP_NAME"

### BUILD .DEB PACKAGE ###############################################

echo "[9/9] Building .deb using fpm..."
fpm -s dir -t deb -n "$APP_NAME" -v "$APP_VERSION" \
  --description "Meshtastic Desktop Client" \
  -C "$BUILD_DIR" \
  .

echo "======================================================"
echo " Build finished!"
echo " Created package: ${APP_NAME}_${APP_VERSION}_amd64.deb"
echo "======================================================"

