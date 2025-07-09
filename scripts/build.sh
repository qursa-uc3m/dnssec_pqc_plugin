#!/bin/bash

# DNSSEC PQC Plugin - CoreDNS Installation Script
set -e

# Configuration
COREDNS_REPO="https://github.com/coredns/coredns.git"
COREDNS_DIR="coredns"
COREDNS_VERSION="master"
PQC_PLUGIN_REPO="github.com/qursa-uc3m/dnssec_pqc_plugin"
PQC_PLUGIN_VERSION="v0.1.1"
LIBOQS_REPO="github.com/open-quantum-safe/liboqs-go"
LIBOQS_VERSION="0.12.0"
PQC_DNS_REPO="github.com/qursa-uc3m/dns"
PQC_DNS_VERSION="master"

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -d|--dir)
            COREDNS_DIR="$2"
            shift 2
            ;;
        -v|--version)
            COREDNS_VERSION="$2"
            shift 2
            ;;
        -h|--help)
            echo "CoreDNS PQC Installation Script"
            echo "Uses qursa-uc3m/dnssec_pqc_plugin for Post-Quantum Cryptography support"
            echo ""
            echo "Usage: $0 [-d directory] [-v version]"
            echo "  -d, --dir      Directory name (default: coredns)"
            echo "  -v, --version  CoreDNS version (default: master)"
            echo "  -h, --help     Show this help"
            echo ""
            echo "Examples:"
            echo "  $0"
            echo "  $0 -d coredns-v1.12 -v v1.12.2"
            echo "  $0 --version v1.11.0"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Check if liboqs is installed first
if ! pkg-config --exists liboqs 2>/dev/null; then
    echo "Error: liboqs not found. Please run: ./scripts/install_liboqs.sh"
    exit 1
fi

# Setup liboqs-go pkg-config if needed
if ! pkg-config --exists liboqs-go 2>/dev/null; then
    echo "Setting up liboqs-go configuration..."
    git clone --depth=1 --branch $LIBOQS_VERSION https://github.com/open-quantum-safe/liboqs-go /tmp/liboqs-go
    sudo cp /tmp/liboqs-go/.config/liboqs-go.pc /usr/local/lib/pkgconfig/
    rm -rf /tmp/liboqs-go
fi

echo "Building PQC key generator..."
cd keygen
if [ ! -f "go.mod" ]; then
    go mod init keygen
fi
go get github.com/open-quantum-safe/liboqs-go/oqs
go build -o keygen main.go
cd ..

echo "Setting up CoreDNS in $COREDNS_DIR..."
rm -rf "$COREDNS_DIR"
git clone "$COREDNS_REPO" "$COREDNS_DIR"
cd "$COREDNS_DIR"

if [ "$COREDNS_VERSION" != "master" ]; then
    echo "Checking out version $COREDNS_VERSION..."
    git checkout "$COREDNS_VERSION"
fi

# Modify plugin.cfg
echo "Adding PQC plugin..."
cp plugin.cfg plugin.cfg.backup
sed -i "/^dnssec:dnssec$/a dnssec_pqc:$PQC_PLUGIN_REPO" plugin.cfg

echo "Adding PQC dependencies..."
echo "Cleaning modcache..."
go clean -modcache
echo "Fetching: $PQC_PLUGIN_REPO@$PQC_PLUGIN_VERSION"
GOPROXY=direct go get "$PQC_PLUGIN_REPO@$PQC_PLUGIN_VERSION"

echo "Setting up PQC DNS replacement..."
cp go.mod go.mod.backup
echo "" >> go.mod
echo "replace github.com/miekg/dns => $PQC_DNS_REPO $PQC_DNS_VERSION" >> go.mod

echo "Cleaning up and resolving dependencies..."
go mod tidy

echo "Generating plugin files..."
go generate

echo "Cleaning up and resolving dependencies again..."
go mod tidy

echo "Building CoreDNS with PQC support..."
go build -o coredns-pqc .

echo "Done! Binaries:"
echo "  Key generator: keygen/keygen"
echo "  CoreDNS: ./$COREDNS_DIR/coredns-pqc"