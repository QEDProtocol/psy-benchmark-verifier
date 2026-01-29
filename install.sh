#!/bin/sh
set -e

REPO="QEDProtocol/psy-benchmark-verifier"
INSTALL_DIR="$HOME/.psy"
VERSION=""
PSY_DATA_URL="https://psy-benchmark-round1-data.psy-protocol.xyz"

if [ -t 1 ] && command -v tput >/dev/null 2>&1; then
    RED=$(tput setaf 1 2>/dev/null || echo "")
    GREEN=$(tput setaf 2 2>/dev/null || echo "")
    YELLOW=$(tput setaf 3 2>/dev/null || echo "")
    BLUE=$(tput setaf 4 2>/dev/null || echo "")
    RESET=$(tput sgr0 2>/dev/null || echo "")
else
    RED="" GREEN="" YELLOW="" BLUE="" RESET=""
fi

info()    { printf "%s[INFO]%s %s\n" "$BLUE" "$RESET" "$1"; }
success() { printf "%s[OK]%s %s\n" "$GREEN" "$RESET" "$1"; }
warn()    { printf "%s[WARN]%s %s\n" "$YELLOW" "$RESET" "$1"; }
error()   { printf "%s[ERROR]%s %s\n" "$RED" "$RESET" "$1" >&2; exit 1; }

detect_os() {
    case "$(uname -s)" in
        Linux*)  echo "linux" ;;
        Darwin*) echo "darwin" ;;
        MINGW*|MSYS*|CYGWIN*) echo "windows" ;;
        FreeBSD*) echo "freebsd" ;;
        *)       error "Unsupported OS: $(uname -s)" ;;
    esac
}

detect_arch() {
    case "$(uname -m)" in
        x86_64|amd64)  echo "amd64" ;;
        aarch64|arm64) echo "arm64" ;;
        armv7l|armv6l) echo "arm" ;;
        i386|i686)     echo "386" ;;
        *)             error "Unsupported arch: $(uname -m)" ;;
    esac
}

detect_downloader() {
    if command -v curl >/dev/null 2>&1; then
        echo "curl"
    elif command -v wget >/dev/null 2>&1; then
        echo "wget"
    else
        error "curl or wget required"
    fi
}

download() {
    url="$1"
    output="$2"
    downloader=$(detect_downloader)
    
    info "Downloading: $url"
    case "$downloader" in
        curl) curl -fsSL -o "$output" "$url" ;;
        wget) wget -q -O "$output" "$url" ;;
    esac
}

get_json_value() {
    key="$1"
    sed 's/,/\n/g' | grep "\"$key\"" | head -1 | sed "s/.*\"$key\"[[:space:]]*:[[:space:]]*\"\([^\"]*\)\".*/\1/"
}

get_latest_version() {
    api_url="https://api.github.com/repos/$REPO/releases/latest"
    downloader=$(detect_downloader)
    
    info "Fetching latest version..." >&2
    case "$downloader" in
        curl) response=$(curl -fsSL "$api_url") ;;
        wget) response=$(wget -qO- "$api_url") ;;
    esac
    
    version=$(echo "$response" | get_json_value "tag_name")
    [ -z "$version" ] && error "Failed to get latest version"
    echo "$version"
}

list_assets() {
    info "Available binaries:"
    echo "  psy_prover_cli_macos_arm64"
    echo "  psy_prover_cli_ubuntu22.04_amd64"
    echo "  psy_prover_cli_windows_x64"
}

try_download_asset() {
    os="$1"
    arch="$2"
    ver="$3"
    tmp_dir="$4"

    # Map os/arch to asset name suffixes
    case "$os" in
        darwin)
            case "$arch" in
                arm64) asset_suffix="macos_arm64" ;;
                *) error "Unsupported arch for macOS: $arch" ;;
            esac
            ;;
        linux)
            case "$arch" in
                amd64) asset_suffix="ubuntu22.04_amd64" ;;
                *) error "Unsupported arch for Linux: $arch" ;;
            esac
            ;;
        windows)
            case "$arch" in
                amd64) asset_suffix="windows_x64" ;;
                *) error "Unsupported arch for Windows: $arch" ;;
            esac
            ;;
        *) error "Unsupported OS: $os" ;;
    esac

    asset_name="psy_prover_cli_${asset_suffix}"
    url="https://github.com/$REPO/releases/download/$ver/$asset_name"
    output="$tmp_dir/$asset_name"

    printf "  Downloading: %s ... " "$asset_name" >&2
    if curl -fsSL --connect-timeout 30 --max-time 600 -o "$output" "$url" 2>/dev/null; then
        echo "OK" >&2
        chmod +x "$output"
        echo "$output"
        return 0
    else
        echo "not found" >&2
        return 1
    fi
}

extract() {
    # No longer needed - downloading binary directly
    :
}

find_binary() {
    # No longer needed - downloading binary directly
    :
}

show_help() {
    cat << 'EOF'
Usage: PROOF_ID=xxx install.sh [options]

Options:
  -v, --version VER    Install specific version (default: latest)
  -d, --dir DIR        Install directory (default: ~/.psy)
  -l, --list           List available binaries
  -h, --help           Show this help

Supported platforms:
  - macOS ARM64 (apple silicon)
  - Ubuntu 22.04 AMD64
  - Windows x64

Examples:
  PROOF_ID=888 curl -fsSL https://.../install.sh | sh
  PROOF_ID=888 ./install.sh
  PROOF_ID=888 ./install.sh -v v1.0.0
EOF
}

main() {
    info "Installing psy_prover_cli from $REPO"

    OS=$(detect_os)
    ARCH=$(detect_arch)
    info "Platform: $OS/$ARCH"

    [ -z "$VERSION" ] && VERSION=$(get_latest_version)
    info "Version: $VERSION"

    [ ! -d "$INSTALL_DIR" ] && { info "Creating: $INSTALL_DIR"; mkdir -p "$INSTALL_DIR"; }

    FINAL_PATH="$INSTALL_DIR/psy_prover_cli"

    # Check if already installed with same version
    if [ -f "$FINAL_PATH" ]; then
        info "Binary already installed: $FINAL_PATH"
        success "Done!"
        return 0
    fi

    TMP_DIR=$(mktemp -d)
    trap 'rm -rf "$TMP_DIR"' EXIT

    DOWNLOAD_PATH=$(try_download_asset "$OS" "$ARCH" "$VERSION" "$TMP_DIR")

    if [ -z "$DOWNLOAD_PATH" ]; then
        warn "Auto-detection failed. Available assets:"
        list_assets
        echo ""
        error "No matching binary found for $OS/$ARCH"
    fi

    rm -f "$FINAL_PATH"
    cp "$DOWNLOAD_PATH" "$FINAL_PATH"
    chmod +x "$FINAL_PATH"

    # macOS Gatekeeper: remove quarantine attribute if present
    if command -v xattr >/dev/null 2>&1; then
        xattr -dr com.apple.quarantine "$FINAL_PATH" 2>/dev/null || true
    fi

    success "Installed: $FINAL_PATH"

    success "Done!"
}

PROOF_ID="${PROOF_ID:-}"

while [ $# -gt 0 ]; do
    case "$1" in
        -v|--version) VERSION="$2"; shift 2 ;;
        -d|--dir)     INSTALL_DIR="$2"; shift 2 ;;
        -l|--list)    info "Fetching assets for $REPO..."; list_assets; exit 0 ;;
        -h|--help)    show_help; exit 0 ;;
        *)            break ;;
    esac
done

main

[ -z "$PROOF_ID" ] && error "PROOF_ID environment variable is required"

info "Running: $INSTALL_DIR/psy_prover_cli fetch-job -b \"$PSY_DATA_URL\" -p \"$PROOF_ID\""

exec "$INSTALL_DIR/psy_prover_cli" fetch-job -b "$PSY_DATA_URL" -p "$PROOF_ID"