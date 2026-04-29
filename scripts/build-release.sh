#!/bin/zsh
set -euo pipefail

# Contour Release Build Script
# Builds, signs, notarizes, and packages the contour binary for macOS
#
# Prerequisites:
#   - Developer ID Application + Installer certificates in keychain
#   - 1Password CLI (op) for --op mode
#   - Xcode command line tools (codesign, pkgbuild, xcrun)
#
# Usage:
#   ./scripts/build-release.sh --op
#   ./scripts/build-release.sh --op --skip-pkg
#   ./scripts/build-release.sh --op --skip-build --install

SCRIPT_DIR="${0:A:h}"
PROJECT_ROOT="${SCRIPT_DIR:h}"
DIST_DIR="$PROJECT_ROOT/dist"
ENV_FILE="$SCRIPT_DIR/.env"
BINARY="contour"
PKG_IDENTIFIER="io.macadmins.contour.pkg"

# 1Password default references
OP_APPLE_ID="${OP_APPLE_ID:-op://dev-credentials/NOTARIZATION_APPLE_ID/credential}"
OP_PASSWORD="${OP_PASSWORD:-op://dev-credentials/NOTARIZATION_PASSWORD/credential}"
OP_TEAM_ID="${OP_TEAM_ID:-op://dev-credentials/NOTARIZATION_TEAM_ID/credential}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Options
SKIP_PKG=false
SKIP_NOTARIZE=false
SKIP_BUILD=false
INSTALL_LOCAL=false
USE_1PASSWORD=false

log_info()  { echo -e "${GREEN}[INFO]${NC} $1" >&2; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $1" >&2; }
log_error() { echo -e "${RED}[ERROR]${NC} $1" >&2; }
log_step()  { echo -e "${CYAN}[====]${NC} $1" >&2; }

banner() {
    echo ""
    echo -e "${BLUE}+==========================================+${NC}"
    echo -e "${BLUE}|       Contour Release Build              |${NC}"
    echo -e "${BLUE}+==========================================+${NC}"
    echo ""
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --op)             USE_1PASSWORD=true; shift ;;
            --skip-pkg)       SKIP_PKG=true; shift ;;
            --skip-notarize)  SKIP_NOTARIZE=true; shift ;;
            --skip-build)     SKIP_BUILD=true; shift ;;
            --install)        INSTALL_LOCAL=true; shift ;;
            --help|-h)
                echo "Usage: $0 [OPTIONS]"
                echo ""
                echo "Options:"
                echo "  --op               Use 1Password CLI for notarization credentials"
                echo "  --skip-pkg         Skip PKG installer creation"
                echo "  --skip-notarize    Skip notarization (binaries still signed)"
                echo "  --skip-build       Reuse existing binaries in target/"
                echo "  --install          Install to /usr/local/bin after build"
                echo "  --help, -h         Show this help"
                echo ""
                echo "Credentials: use --op for 1Password, or set env vars / scripts/.env"
                echo "  OP_APPLE_ID, OP_PASSWORD, OP_TEAM_ID (1Password references)"
                echo "  CODESIGN_IDENTITY, NOTARIZATION_APPLE_ID, NOTARIZATION_TEAM_ID, NOTARIZATION_PASSWORD"
                exit 0
                ;;
            *) log_error "Unknown option: $1"; exit 1 ;;
        esac
    done
}

get_version() {
    grep '^version = ' "$PROJECT_ROOT/crates/$BINARY/Cargo.toml" | head -1 | sed 's/version = "\(.*\)"/\1/'
}

# Auto-detect signing identity from Keychain
select_signing_identity() {
    local identity_type="$1"
    local identities

    if [[ "$identity_type" == "Application" ]]; then
        identities=$(security find-identity -v -p codesigning 2>/dev/null \
            | grep "Developer ID $identity_type" \
            | sed 's/^[[:space:]]*[0-9]*)[[:space:]]*//' \
            | sed 's/[[:space:]]*$//')
    else
        identities=$(security find-identity -v 2>/dev/null \
            | grep "Developer ID $identity_type" \
            | sed 's/^[[:space:]]*[0-9]*)[[:space:]]*//' \
            | sed 's/[[:space:]]*$//')
    fi

    if [[ -z "$identities" ]]; then
        return 1
    fi

    local count
    count=$(echo "$identities" | wc -l | tr -d ' ')

    if [[ "$count" -eq 1 ]]; then
        local identity
        identity=$(echo "$identities" | sed 's/^[A-F0-9]* "//' | sed 's/"$//')
        echo "$identity"
        return 0
    fi

    # Multiple identities — pick the first one
    local identity
    identity=$(echo "$identities" | head -1 | sed 's/^[A-F0-9]* "//' | sed 's/"$//')
    echo "$identity"
    return 0
}

# Submit artifact to Apple notarization service
notarize_artifact() {
    local artifact="$1"
    local output

    if [[ "$USE_1PASSWORD" == "true" ]]; then
        command -v op >/dev/null 2>&1 || { log_error "1Password CLI (op) not found"; exit 1; }
        local apple_id password team_id
        apple_id=$(op read "$OP_APPLE_ID")
        password=$(op read "$OP_PASSWORD")
        team_id=$(op read "$OP_TEAM_ID")

        output=$(xcrun notarytool submit "$artifact" \
            --apple-id "$apple_id" \
            --password "$password" \
            --team-id "$team_id" \
            --timeout 15m \
            --wait 2>&1) || { echo "$output" >&2; return 1; }
    elif [[ -n "${NOTARIZATION_APPLE_ID:-}" ]]; then
        output=$(xcrun notarytool submit "$artifact" \
            --apple-id "$NOTARIZATION_APPLE_ID" \
            --password "$NOTARIZATION_PASSWORD" \
            --team-id "$NOTARIZATION_TEAM_ID" \
            --timeout 15m \
            --wait 2>&1) || { echo "$output" >&2; return 1; }
    else
        log_error "No notarization credentials (use --op or set env vars)"
        return 1
    fi

    echo "$output"
}

load_credentials() {
    log_step "Loading credentials"

    if [[ "$USE_1PASSWORD" == "true" ]]; then
        command -v op >/dev/null 2>&1 || { log_error "1Password CLI (op) not found"; exit 1; }
        log_info "Using 1Password for notarization credentials"
    else
        # Try .env file fallback
        if [[ -z "${CODESIGN_IDENTITY:-}" || -z "${NOTARIZATION_APPLE_ID:-}" ]]; then
            if [[ -f "$ENV_FILE" ]]; then
                log_info "Sourcing credentials from $ENV_FILE"
                set -a
                source "$ENV_FILE"
                set +a
            fi
        fi

        # Resolve any op:// references in env vars
        if [[ "${CODESIGN_IDENTITY:-}" == op://* ]]; then
            CODESIGN_IDENTITY=$(op read "$CODESIGN_IDENTITY")
        fi
        if [[ "${NOTARIZATION_APPLE_ID:-}" == op://* ]]; then
            NOTARIZATION_APPLE_ID=$(op read "$NOTARIZATION_APPLE_ID")
        fi
        if [[ "${NOTARIZATION_TEAM_ID:-}" == op://* ]]; then
            NOTARIZATION_TEAM_ID=$(op read "$NOTARIZATION_TEAM_ID")
        fi
        if [[ "${NOTARIZATION_PASSWORD:-}" == op://* ]]; then
            NOTARIZATION_PASSWORD=$(op read "$NOTARIZATION_PASSWORD")
        fi
    fi

    # Auto-detect signing identity if not set
    if [[ -z "${CODESIGN_IDENTITY:-}" ]]; then
        CODESIGN_IDENTITY=$(select_signing_identity "Application") || true
    fi

    if [[ -z "${CODESIGN_IDENTITY:-}" ]]; then
        log_error "No Developer ID Application certificate found"
        security find-identity -v -p codesigning
        exit 1
    fi

    if [[ -z "${INSTALLER_IDENTITY:-}" ]]; then
        INSTALLER_IDENTITY=$(select_signing_identity "Installer") || true
    fi

    if [[ "$SKIP_PKG" != true && -z "${INSTALLER_IDENTITY:-}" ]]; then
        log_error "No Developer ID Installer certificate found"
        security find-identity -v
        exit 1
    fi

    log_info "Signing (app):  $CODESIGN_IDENTITY"
    if [[ -n "${INSTALLER_IDENTITY:-}" ]]; then
        log_info "Signing (pkg):  $INSTALLER_IDENTITY"
    fi
}

check_prerequisites() {
    log_step "Checking prerequisites"

    command -v codesign >/dev/null 2>&1 || { log_error "codesign not found"; exit 1; }
    command -v xcrun    >/dev/null 2>&1 || { log_error "xcrun not found"; exit 1; }
    command -v pkgbuild >/dev/null 2>&1 || { log_error "pkgbuild not found"; exit 1; }

    log_info "Prerequisites OK"
}

build_binary() {
    if [[ "$SKIP_BUILD" == true ]]; then
        log_warn "Skipping build (--skip-build)"
        if [[ ! -f "$PROJECT_ROOT/target/aarch64-apple-darwin/release/$BINARY" ]]; then
            log_error "No existing binary found at target/aarch64-apple-darwin/release/$BINARY"
            exit 1
        fi
        return
    fi

    log_step "Building $BINARY for aarch64-apple-darwin"
    cd "$PROJECT_ROOT"
    cargo build --release --target aarch64-apple-darwin -p "$BINARY"
    log_info "Build complete"
}

strip_binary() {
    log_step "Stripping debug symbols"

    cp "$PROJECT_ROOT/target/aarch64-apple-darwin/release/$BINARY" "$DIST_DIR/$BINARY"

    local before_size=$(ls -lh "$DIST_DIR/$BINARY" | awk '{print $5}')
    strip "$DIST_DIR/$BINARY"
    local after_size=$(ls -lh "$DIST_DIR/$BINARY" | awk '{print $5}')

    log_info "$BINARY: $before_size -> $after_size (stripped)"
}

sign_binary() {
    log_step "Signing binary (hardened runtime)"

    codesign --force --options runtime --timestamp \
        --sign "$CODESIGN_IDENTITY" "$DIST_DIR/$BINARY"

    codesign -vvv --deep --strict "$DIST_DIR/$BINARY"
    log_info "$BINARY signed and verified"
}

create_zip() {
    log_step "Creating ZIP archive"

    local version=$(get_version)
    local zip_name="${BINARY}-${version}-macos-arm64.zip"

    cd "$DIST_DIR"
    ditto -c -k --keepParent "$BINARY" "$zip_name"
    log_info "Created: $zip_name"
}

notarize_zip() {
    log_step "Notarizing binary (zip → notarytool)"

    local version=$(get_version)
    local zip_file="${BINARY}-${version}-macos-arm64.zip"

    cd "$DIST_DIR"
    log_info "Submitting $zip_file..."

    local output
    if output=$(notarize_artifact "$zip_file"); then
        echo "$output"
        if echo "$output" | grep -q "status: Accepted"; then
            log_info "Binary notarized (registered with Apple)"
        else
            log_warn "Notarization response unexpected — check output above"
        fi
    else
        log_error "Binary notarization failed"
        exit 1
    fi

    log_warn "Note: Notarization tickets cannot be stapled to bare executables"
    log_info "Users need an internet connection on first run to verify"
}

build_pkg() {
    log_step "Building PKG installer with pkgbuild"

    cd "$PROJECT_ROOT"

    # Stage payload tree in a fresh temp dir so the source tree stays clean.
    local pkg_stage
    pkg_stage=$(mktemp -d)
    trap 'rm -rf "$pkg_stage"' EXIT

    mkdir -p "$pkg_stage/payload/usr/local/bin"
    cp "$DIST_DIR/$BINARY" "$pkg_stage/payload/usr/local/bin/"
    chmod 755 "$pkg_stage/payload/usr/local/bin/$BINARY"

    # Verify payload binary is signed before packaging
    log_info "Verifying payload binary..."
    codesign --verify --strict "$pkg_stage/payload/usr/local/bin/$BINARY" \
        || { log_error "Payload binary is not properly signed"; exit 1; }

    local version
    version=$(get_version)
    local pkg_path="$DIST_DIR/${BINARY}-${version}.pkg"

    pkgbuild \
        --root "$pkg_stage/payload" \
        --identifier "$PKG_IDENTIFIER" \
        --version "$version" \
        --install-location / \
        --sign "$INSTALLER_IDENTITY" \
        --timestamp \
        "$pkg_path"

    log_info "PKG built: $(basename "$pkg_path")"
}

notarize_pkg() {
    log_step "Notarizing PKG installer"

    local pkg_file
    pkg_file=$(ls "$DIST_DIR"/*.pkg 2>/dev/null | head -1)
    if [[ -z "$pkg_file" ]]; then
        log_error "No .pkg file found in $DIST_DIR"
        exit 1
    fi

    log_info "Submitting $(basename "$pkg_file")..."

    local output
    if output=$(notarize_artifact "$pkg_file"); then
        echo "$output"
        if echo "$output" | grep -q "status: Accepted"; then
            log_info "PKG notarized — stapling ticket..."
            xcrun stapler staple "$pkg_file"
            log_info "PKG notarized and stapled"
        else
            log_warn "PKG notarization response unexpected — check output above"
        fi
    else
        log_error "PKG notarization failed"
        exit 1
    fi
}

create_checksums() {
    log_step "Creating checksums"

    cd "$DIST_DIR"
    rm -f checksums.txt

    shasum -a 256 *.zip  >> checksums.txt 2>/dev/null || true
    shasum -a 256 *.pkg  >> checksums.txt 2>/dev/null || true
    shasum -a 256 "$BINARY" >> checksums.txt 2>/dev/null || true

    log_info "Checksums:"
    cat checksums.txt
}

verify_artifacts() {
    log_step "Verification"

    echo ""
    echo "=== Binary Signature ==="
    codesign -dvv "$DIST_DIR/$BINARY" 2>&1 | grep -E "(Identifier|Authority|Timestamp|Flags)" || true

    if [[ "$SKIP_PKG" != true ]]; then
        echo ""
        echo "=== Package Signature ==="
        for pkg in "$DIST_DIR"/*.pkg; do
            if [[ -f "$pkg" ]]; then
                echo "$(basename "$pkg"):"
                pkgutil --check-signature "$pkg" 2>&1 | head -10
                if spctl --assess --type install "$pkg" 2>/dev/null; then
                    echo "  Gatekeeper: PASS"
                else
                    echo "  Gatekeeper: FAIL (not notarized/stapled)"
                fi
            fi
        done
    fi
}

install_local() {
    log_step "Installing to /usr/local/bin"

    sudo cp "$DIST_DIR/$BINARY" "/usr/local/bin/$BINARY"
    sudo chmod +x "/usr/local/bin/$BINARY"
    log_info "Installed $BINARY to /usr/local/bin/"

    "/usr/local/bin/$BINARY" --version 2>/dev/null || true
}

show_summary() {
    log_step "Build Summary"
    echo ""
    log_info "Version: $(get_version)"
    log_info "Distribution: $DIST_DIR"
    echo ""
    ls -lh "$DIST_DIR"

    if [[ "$INSTALL_LOCAL" != true ]]; then
        echo ""
        log_info "To install locally:"
        log_info "  sudo cp $DIST_DIR/$BINARY /usr/local/bin/"
        log_info "Or re-run with --install"
    fi
}

main() {
    parse_args "$@"
    banner

    log_info "Binary: $BINARY"

    load_credentials
    check_prerequisites

    # Clean dist/
    rm -rf "$DIST_DIR"
    mkdir -p "$DIST_DIR"

    # Build
    build_binary
    strip_binary
    sign_binary
    create_zip

    # Notarize
    if [[ "$SKIP_NOTARIZE" == true ]]; then
        log_warn "Skipping notarization (--skip-notarize)"
    else
        notarize_zip
    fi

    # PKG
    if [[ "$SKIP_PKG" == true ]]; then
        log_warn "Skipping PKG creation (--skip-pkg)"
    else
        build_pkg
        if [[ "$SKIP_NOTARIZE" != true ]]; then
            notarize_pkg
        fi
    fi

    # Checksums and verification
    create_checksums
    verify_artifacts

    # Install
    if [[ "$INSTALL_LOCAL" == true ]]; then
        install_local
    fi

    show_summary
    echo ""
    log_info "Build complete!"
}

main "$@"
