#!/bin/bash

# liboqs Installation Script for DNSSEC PQC Plugin
set -e

# Configuration
LIBOQS_VERSION="${1:-0.12.0}"
INSTALL_PREFIX="/usr/local"
BUILD_DIR="/tmp/liboqs-build"

echo "Installing liboqs v$LIBOQS_VERSION..."

echo "Cleaning previous installation..."
sudo rm -rf "$INSTALL_PREFIX/include/oqs"
sudo rm -f "$INSTALL_PREFIX/lib/liboqs"*
sudo rm -f "$INSTALL_PREFIX/lib/pkgconfig/liboqs.pc"
rm -rf "$BUILD_DIR"

echo "Building liboqs..."
git clone --depth=1 --branch "$LIBOQS_VERSION" \
    https://github.com/open-quantum-safe/liboqs.git "$BUILD_DIR"

cd "$BUILD_DIR"
mkdir build && cd build

cmake -DCMAKE_BUILD_TYPE=Release \
      -DBUILD_SHARED_LIBS=ON \
      -DOQS_USE_OPENSSL=ON \
      -DCMAKE_INSTALL_PREFIX="$INSTALL_PREFIX" \
      ..

make -j$(nproc)
sudo make install
sudo ldconfig

cd / && rm -rf "$BUILD_DIR"

if pkg-config --exists liboqs; then
    echo "✓ liboqs v$(pkg-config --modversion liboqs) installed successfully"
else
    echo "✗ Installation failed"
    exit 1
fi