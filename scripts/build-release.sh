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

# Captured at top level: inside a zsh function `$0` is the function's name,
# not the script's, so --help printed "Usage: parse_args".
SCRIPT_PATH="${0:A}"
SCRIPT_DIR="${0:A:h}"
PROJECT_ROOT="${SCRIPT_DIR:h}"
DIST_DIR="$PROJECT_ROOT/dist"
ENV_FILE="$SCRIPT_DIR/.env"
# Release targets. Each ships as its own signed binary, its own zip and its
# own pkg — contour-mcp is a separate product with a separate dependency tree
# (read-only, no MDM-artifact writers linked), so it gets a separate installer
# rather than riding along inside contour's.
#
# BINARY and PKG_IDENTIFIER are reassigned per target inside main()'s loop;
# every function below reads them as globals, which is why the loop can reuse
# them unchanged.
ALL_BINARIES=(contour contour-mcp)
# Every target this script can produce, whatever `--only` narrowed
# ALL_BINARIES to. Checksums and Gatekeeper cover the current version of each
# one present in dist/, so an --only run keeps the other target's pkg listed.
KNOWN_BINARIES=(contour contour-mcp)
BINARY="contour"
PKG_IDENTIFIER="io.macadmins.contour.pkg"

# Reverse-DNS installer identifier for a target.
pkg_identifier_for() {
    case "$1" in
        contour)     echo "io.macadmins.contour.pkg" ;;
        contour-mcp) echo "io.macadmins.contour-mcp.pkg" ;;
        *)           log_error "No pkg identifier defined for '$1'"; exit 1 ;;
    esac
}

# 1Password default references
# 1Password references for --op, e.g. op://<vault>/<item>/<field>. No
# defaults: each account names its own vault. Set them in the environment
# or in scripts/.env.
OP_APPLE_ID="${OP_APPLE_ID:-}"
OP_PASSWORD="${OP_PASSWORD:-}"
OP_TEAM_ID="${OP_TEAM_ID:-}"

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
            --only)
                shift
                [[ $# -gt 0 ]] || { log_error "--only needs a binary name"; exit 1; }
                pkg_identifier_for "$1" >/dev/null   # validates the name
                ALL_BINARIES=("$1")
                shift
                ;;
            --help|-h)
                echo "Usage: ${SCRIPT_PATH:t} [OPTIONS]"
                echo ""
                echo "Builds, signs, notarizes and packages every release target:"
                echo "  ${ALL_BINARIES[*]}"
                echo "Each gets its own binary, zip and pkg in dist/."
                echo ""
                echo "Options:"
                echo "  --op               Use 1Password CLI for notarization credentials"
                echo "  --only <binary>    Build just one target (contour | contour-mcp)"
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
        if [[ -z "$OP_APPLE_ID" || -z "$OP_PASSWORD" || -z "$OP_TEAM_ID" ]] && [[ -f "$ENV_FILE" ]]; then
            log_info "Sourcing 1Password references from $ENV_FILE"
            set -a
            source "$ENV_FILE"
            set +a
        fi
        # Checked before anything is built, not at the first notarization.
        local missing=()
        [[ -n "${OP_APPLE_ID:-}" ]] || missing+=(OP_APPLE_ID)
        [[ -n "${OP_PASSWORD:-}" ]] || missing+=(OP_PASSWORD)
        [[ -n "${OP_TEAM_ID:-}" ]] || missing+=(OP_TEAM_ID)
        if (( ${#missing[@]} > 0 )); then
            log_error "--op needs 1Password references (op://<vault>/<item>/<field>) in: ${missing[*]}"
            log_error "Set them in the environment or in $ENV_FILE"
            exit 1
        fi
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

# The artifacts one target produces at the current version.
artifacts_for() {
    local version
    version=$(get_version)
    echo "$1" "$1-${version}-macos-arm64.zip" "$1-${version}.pkg"
}

# Remove this target's current-version artifacts, and nothing else.
#
# dist/ is not wiped: `--only contour-mcp` keeps the contour pkg beside it,
# and earlier releases survive a rebuild. Only what this run replaces goes.
clean_target_artifacts() {
    local f
    for f in $(artifacts_for "$BINARY"); do
        rm -f "$DIST_DIR/$f"
    done
}

# Refuse a binary that is not the version being released.
#
# --skip-build packages whatever sits in target/. After a run that failed
# before compiling a target, that can be an earlier version's binary, which
# would otherwise go out inside a pkg named for this one.
check_binary_version() {
    local version reported
    version=$(get_version)
    reported=$("$DIST_DIR/$BINARY" --version 2>/dev/null | head -1)
    if [[ "$reported" != "$BINARY $version"* ]]; then
        log_error "$BINARY reports '${reported:-nothing}', expected $version — stale target/ binary? Rebuild without --skip-build"
        exit 1
    fi
    log_info "$BINARY reports $version"
    # The datasets are compiled in; census reads them back out of the binary.
    # A zero count means a schema crate was built without its data.
    if [[ "$BINARY" == "contour" ]]; then
        if "$DIST_DIR/$BINARY" census --json 2>/dev/null | grep -Eq '"[a-z_]+": 0(,|$)'; then
            log_error "$BINARY census reports an empty dataset — a schema crate built without its data:"
            "$DIST_DIR/$BINARY" census --json 2>/dev/null | grep -E '"[a-z_]+": 0(,|$)' >&2
            exit 1
        fi
        log_info "$BINARY census: every embedded dataset present"
    fi
}

strip_binary() {
    log_step "Stripping debug symbols"

    cp "$PROJECT_ROOT/target/aarch64-apple-darwin/release/$BINARY" "$DIST_DIR/$BINARY"
    check_binary_version

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

    # Pack the binary at the top level (no parent dir). Users running
    # `unzip contour-*.zip && sudo mv contour /usr/local/bin/` should
    # find `contour` directly — not `dist/contour`.
    # https://github.com/macadmins/contour/issues — christian-glattfelder-at-ethz
    cd "$DIST_DIR"
    ditto -c -k "$BINARY" "$zip_name"
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
    # No EXIT trap — `pkg_stage` is function-local, and the OS cleans /var/folders.
    local pkg_stage
    pkg_stage=$(mktemp -d)

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

    rm -rf "$pkg_stage"
    log_info "PKG built: $(basename "$pkg_path")"
}

notarize_pkg() {
    log_step "Notarizing PKG installer"

    # Name the file for the target being processed, not the first *.pkg:
    # with two targets that would pick the wrong pkg on the second pass.
    local version
    version=$(get_version)
    local pkg_file="$DIST_DIR/${BINARY}-${version}.pkg"
    if [[ ! -f "$pkg_file" ]]; then
        log_error "Expected pkg not found: $pkg_file"
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
    # Named for the platform: the Linux workflow publishes its own manifests
    # to the same release, and two files called checksums.txt overwrite each
    # other there.
    rm -f checksums-macos-arm64.txt

    # The current version of every known target present, not a glob:
    # dist/ now keeps earlier releases, whose files are not this release.
    # Each target by name, not $BINARY — after the build loop that global
    # holds the last target only.
    local bin f
    for bin in "${KNOWN_BINARIES[@]}"; do
        BINARY="$bin"
        for f in $(artifacts_for "$bin"); do
            [[ -f "$f" ]] && shasum -a 256 "$f" >> checksums-macos-arm64.txt
        done
    done

    log_info "Checksums:"
    cat checksums-macos-arm64.txt
}

verify_artifacts() {
    log_step "Verification"

    for bin in "${ALL_BINARIES[@]}"; do
        echo ""
        echo "=== Binary Signature: $bin ==="
        codesign -dvv "$DIST_DIR/$bin" 2>&1 | grep -E "(Identifier|Authority|Timestamp|flags=)" || true
    done

    if [[ "$SKIP_PKG" != true ]]; then
        echo ""
        echo "=== Package Signature ==="
        local gatekeeper_failures=0
        local pkgs=() bin
        for bin in "${KNOWN_BINARIES[@]}"; do
            BINARY="$bin"
            pkgs+=("$DIST_DIR/${bin}-$(get_version).pkg")
        done
        for pkg in "${pkgs[@]}"; do
            if [[ -f "$pkg" ]]; then
                echo "$(basename "$pkg"):"
                pkgutil --check-signature "$pkg" 2>&1 | head -10
                if spctl --assess --type install "$pkg" 2>/dev/null; then
                    echo "  Gatekeeper: PASS"
                else
                    echo "  Gatekeeper: FAIL (not notarized/stapled)"
                    # Not `((gatekeeper_failures++))`: post-increment from 0
                    # evaluates to 0, exit status 1, and `set -e` would end
                    # the run here before the guard below decides whether
                    # the failure is tolerable (it is under --skip-notarize).
                    gatekeeper_failures=$((gatekeeper_failures + 1))
                fi
            fi
        done

        # A pkg that Gatekeeper rejects is not shippable, so refuse to exit 0
        # on one.
        if [[ "$SKIP_NOTARIZE" != true && $gatekeeper_failures -gt 0 ]]; then
            log_error "$gatekeeper_failures package(s) failed Gatekeeper — not shippable"
            exit 1
        fi
    fi
}

install_local() {
    log_step "Installing to /usr/local/bin"

    for bin in "${ALL_BINARIES[@]}"; do
        sudo cp "$DIST_DIR/$bin" "/usr/local/bin/$bin"
        sudo chmod +x "/usr/local/bin/$bin"
        log_info "Installed $bin to /usr/local/bin/"
        "/usr/local/bin/$bin" --version 2>/dev/null || true
    done
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
        for bin in "${ALL_BINARIES[@]}"; do
            log_info "  sudo cp $DIST_DIR/$bin /usr/local/bin/"
        done
        log_info "Or re-run with --install"
    fi
}

main() {
    parse_args "$@"
    banner

    log_info "Targets: ${ALL_BINARIES[*]}"

    # Credentials and prerequisites are resolved once, before any target is
    # built. Every notarization in the loop reuses them, so 1Password is
    # unlocked once per run rather than once per target.
    load_credentials
    check_prerequisites

    mkdir -p "$DIST_DIR"

    for BINARY in "${ALL_BINARIES[@]}"; do
        PKG_IDENTIFIER=$(pkg_identifier_for "$BINARY")
        log_step "── $BINARY ($PKG_IDENTIFIER) ──"
        clean_target_artifacts

        build_binary
        strip_binary
        sign_binary
        create_zip

        if [[ "$SKIP_NOTARIZE" == true ]]; then
            log_warn "Skipping notarization (--skip-notarize)"
        else
            notarize_zip
        fi

        if [[ "$SKIP_PKG" == true ]]; then
            log_warn "Skipping PKG creation (--skip-pkg)"
        else
            build_pkg
            if [[ "$SKIP_NOTARIZE" != true ]]; then
                notarize_pkg
            fi
        fi
    done

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
