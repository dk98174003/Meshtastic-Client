#!/bin/bash
set -e

# create_local_venv.sh
# Dev helper: create a local venv for running meshtastic_client.py
# directly from the project folder (e.g. in VS Code).

PROJECT_DIR="/home/knud/Desktop/Meshtastic/Meshtastic_client"
VENV_DIR="${PROJECT_DIR}/.venv"

echo "Project dir : $PROJECT_DIR"
echo "Local venv  : $VENV_DIR"
cd "$PROJECT_DIR" || exit 1

if [ -d "$VENV_DIR" ]; then
  echo "Local venv already exists at $VENV_DIR"
  echo "If you want a fresh one, delete it first:"
  echo "  rm -rf "$VENV_DIR""
  exit 0
fi

echo "Creating virtualenv..."
python3 -m venv "$VENV_DIR"

echo "Upgrading pip inside venv..."
"$VENV_DIR/bin/pip" install --upgrade pip

echo "Installing dev dependencies into local venv..."
"$VENV_DIR/bin/pip" install   meshtastic   pyserial   pypubsub   protobuf   bleak

echo "Writing requirements.txt (for reference)..."
cat > "$PROJECT_DIR/requirements.txt" << EOF
meshtastic
pyserial
pypubsub
protobuf
bleak
EOF

echo
echo "===================================================="
echo " Local dev venv ready."
echo " Path: $VENV_DIR"
echo
echo " In VS Code, select this interpreter:"
echo "   $VENV_DIR/bin/python"
echo
echo " To run locally from terminal:"
echo "   source "$VENV_DIR/bin/activate""
echo "   python meshtastic_client.py"
echo "===================================================="
