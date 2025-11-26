#!/bin/bash
set -e

APP_DIR="/home/knud/Desktop/Meshtastic/Meshtastic_client/Flatpak"
MANIFEST="dk.it4home.MeshtasticClient.yaml"
BUILD_DIR="$APP_DIR/build-dir"

cd "$APP_DIR"

echo "=== Ensuring vendor wheels exist (requirements -> vendor/) ==="
if [ ! -d "vendor" ] || [ -z "$(ls -A vendor)" ]; then
  echo "Downloading Python wheels to vendor/ ..."
  pip download -r requirements.txt -d vendor
fi

echo "=== Installing required Flatpak runtimes (24.08) ==="
flatpak install -y flathub org.freedesktop.Platform//24.08
flatpak install -y flathub org.freedesktop.Sdk//24.08

echo "=== Building + installing Flatpak (clean) ==="
flatpak-builder --user --force-clean --install "$BUILD_DIR" "$MANIFEST"
echo "=== Creating single-file bundle (.flatpak) ==="
APP_ID="dk.it4home.MeshtasticClient"
BRANCH="master"
USER_REPO="$HOME/.local/share/flatpak/repo"
BUNDLE_NAME="MeshtasticClient.flatpak"

flatpak build-bundle "$USER_REPO" "$APP_DIR/$BUNDLE_NAME" "$APP_ID" "$BRANCH"

echo "Bundle created at: $APP_DIR/$BUNDLE_NAME"


echo "=== Running Meshtastic Client ==="
flatpak run dk.it4home.MeshtasticClient




