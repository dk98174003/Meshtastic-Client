#!/usr/bin/env bash
# install_fpm_debian.sh
# Simple installer script for FPM on Debian-based systems.

set -e

if [ "$EUID" -ne 0 ]; then
  echo "Please run this script as root (e.g. with: sudo ./install_fpm_debian.sh)"
  exit 1
fi

echo "Updating package lists..."
apt update

echo "Installing Ruby and build tools..."
apt install -y ruby ruby-dev build-essential

echo "Installing FPM via RubyGems..."
gem install --no-document fpm

echo
echo "Done. FPM version installed:"
fpm --version || echo "FPM installed, but not found in PATH. Try opening a new terminal session."
