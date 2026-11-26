#!/bin/sh
# Universal installer for rship (Linux / macOS)
# Usage: curl -fsSL https://hua0512.github.io/rship/install.sh | sh
# Options:
#   -v, --version <tag>       Install a specific release tag (e.g. v0.1.0; default: latest)
#   -d, --dir <path>          Target installation directory
#       --libc <auto|gnu|musl> Linux libc target (default: auto; gnu if glibc >= 2.28, else musl)
#       --no-verify           Skip SHA256SUMS.txt verification
#   -h, --help                Print help and exit

set -eu

REPO="hua0512/rship"
VERSION="${RSHIP_VERSION:-}"
INSTALL_DIR="${RSHIP_INSTALL_DIR:-}"
LIBC="${RSHIP_LIBC:-auto}"
NO_VERIFY="${RSHIP_NO_VERIFY:-0}"

say() {
  printf '%s\n' "[rship] $*"
}

err() {
  printf '%s\n' "[rship] error: $*" >&2
  exit 1
}

usage() {
  cat <<'EOF'
Install prebuilt rship binary from GitHub Releases.

USAGE:
  curl -fsSL https://hua0512.github.io/rship/install.sh | sh
  curl -fsSL https://hua0512.github.io/rship/install.sh | sh -s -- [OPTIONS]

OPTIONS:
  -v, --version <tag>        Release tag to install (e.g. v0.1.0; default: latest)
  -d, --dir <path>           Install directory (default: /usr/local/bin if root, else ~/.local/bin)
      --libc <auto|gnu|musl> Linux libc variant (default: auto; gnu if glibc >= 2.28, else musl)
      --no-verify            Skip SHA-256 verification against SHA256SUMS.txt
  -h, --help                 Show this help message

ENVIRONMENT:
  RSHIP_VERSION              Same as --version
  RSHIP_INSTALL_DIR          Same as --dir
  RSHIP_LIBC                 Same as --libc (auto, gnu, or musl)
  RSHIP_NO_VERIFY=1          Same as --no-verify
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    -v|--version)
      [ "$#" -ge 2 ] || err "missing value for $1"
      VERSION="$2"
      shift 2
      ;;
    --version=*)
      VERSION="${1#*=}"
      shift
      ;;
    -d|--dir)
      [ "$#" -ge 2 ] || err "missing value for $1"
      INSTALL_DIR="$2"
      shift 2
      ;;
    --dir=*)
      INSTALL_DIR="${1#*=}"
      shift
      ;;
    --libc)
      [ "$#" -ge 2 ] || err "missing value for $1"
      LIBC="$2"
      shift 2
      ;;
    --libc=*)
      LIBC="${1#*=}"
      shift
      ;;
    --no-verify)
      NO_VERIFY="1"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      err "unknown argument: $1 (pass --help for usage)"
      ;;
  esac
done

have_cmd() {
  command -v "$1" >/dev/null 2>&1
}

download_file() {
  _url="$1"
  _dest="$2"
  if have_cmd curl; then
    curl -fsSL "$_url" -o "$_dest"
  elif have_cmd wget; then
    wget -qO "$_dest" "$_url"
  else
    err "curl or wget is required to download release artifacts"
  fi
}

resolve_latest_version() {
  _tag=""
  if have_cmd curl; then
    _effective="$(curl -fsSLI -o /dev/null -w '%{url_effective}' "https://github.com/${REPO}/releases/latest" || true)"
    _tag="$(printf '%s' "$_effective" | sed 's|.*/||')"
    if [ "$_tag" = "latest" ]; then
      _tag=""
    fi
  fi

  if [ -z "$_tag" ]; then
    _api_tmp="$TMP_DIR/latest.json"
    download_file "https://api.github.com/repos/${REPO}/releases/latest" "$_api_tmp"
    _tag="$(sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$_api_tmp" | head -n 1)"
  fi

  [ -n "$_tag" ] || err "could not resolve latest release tag from github.com/${REPO}/releases"
  printf '%s' "$_tag"
}

sha256_file() {
  _file="$1"
  if have_cmd sha256sum; then
    sha256sum "$_file" | awk '{print $1}'
  elif have_cmd shasum; then
    shasum -a 256 "$_file" | awk '{print $1}'
  elif have_cmd openssl; then
    openssl dgst -sha256 "$_file" | awk '{print $NF}'
  else
    return 1
  fi
}

detect_linux_libc() {
  _glibc_ver=""
  if have_cmd getconf; then
    _raw="$(getconf GNU_LIBC_VERSION 2>/dev/null || true)"
    case "$_raw" in
      glibc\ *|GLIBC\ *)
        _glibc_ver="$(printf '%s' "$_raw" | awk '{print $2}')"
        ;;
    esac
  fi

  if [ -z "$_glibc_ver" ] && have_cmd ldd; then
    _ldd_out="$(ldd --version 2>&1 || true)"
    case "$_ldd_out" in
      *musl*)
        printf '%s' "musl"
        return 0
        ;;
      *GLIBC*|*"GNU libc"*|*"GNU C Library"*)
        _glibc_ver="$(printf '%s\n' "$_ldd_out" | head -n 1 | sed -n 's/.* \([0-9][0-9]*\.[0-9][0-9]*\).*/\1/p')"
        ;;
    esac
  fi

  if [ -n "$_glibc_ver" ]; then
    _maj="$(printf '%s' "$_glibc_ver" | cut -d. -f1)"
    _min="$(printf '%s' "$_glibc_ver" | cut -d. -f2)"
    case "$_maj:$_min" in
      *[!0-9:]*|:|*:|:* )
        ;;
      *)
        if [ "$_maj" -gt 2 ] || { [ "$_maj" -eq 2 ] && [ "$_min" -ge 28 ]; }; then
          printf '%s' "gnu"
          return 0
        fi
        ;;
    esac
  fi

  printf '%s' "musl"
}

OS="$(uname -s)"
ARCH="$(uname -m)"
FALLBACK_TARGET=""

case "$OS" in
  Linux)
    LIBC="$(printf '%s' "$LIBC" | tr '[:upper:]' '[:lower:]')"
    case "$LIBC" in
      auto)
        RESOLVED_LIBC="$(detect_linux_libc)"
        ;;
      gnu|musl)
        RESOLVED_LIBC="$LIBC"
        ;;
      *)
        err "invalid --libc value: $LIBC (expected: auto, gnu, or musl)"
        ;;
    esac
    case "$ARCH" in
      x86_64|amd64)
        TARGET="x86_64-unknown-linux-${RESOLVED_LIBC}"
        if [ "$LIBC" = "auto" ] && [ "$RESOLVED_LIBC" = "gnu" ]; then
          FALLBACK_TARGET="x86_64-unknown-linux-musl"
        fi
        ;;
      aarch64|arm64)
        TARGET="aarch64-unknown-linux-${RESOLVED_LIBC}"
        if [ "$LIBC" = "auto" ] && [ "$RESOLVED_LIBC" = "gnu" ]; then
          FALLBACK_TARGET="aarch64-unknown-linux-musl"
        fi
        ;;
      *)
        err "unsupported Linux architecture: $ARCH (see https://github.com/${REPO}/releases)"
        ;;
    esac
    ;;
  Darwin)
    case "$ARCH" in
      arm64|aarch64)
        TARGET="aarch64-apple-darwin"
        ;;
      x86_64|amd64)
        TARGET="x86_64-apple-darwin"
        ;;
      *)
        err "unsupported macOS architecture: $ARCH"
        ;;
    esac
    ;;
  *)
    err "unsupported operating system: $OS (on Windows, use install.ps1)"
    ;;
esac

have_cmd tar || err "tar is required to extract release archives"

TMP_DIR="$(mktemp -d 2>/dev/null || mktemp -d -t rship-install)"
cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT INT TERM

if [ -z "$VERSION" ]; then
  say "Resolving latest release..."
  VERSION="$(resolve_latest_version)"
else
  VERSION="v${VERSION#v}"
fi

if [ -z "$INSTALL_DIR" ]; then
  if [ "$(id -u)" -eq 0 ]; then
    INSTALL_DIR="/usr/local/bin"
  else
    INSTALL_DIR="${HOME}/.local/bin"
  fi
fi

STEM="rship-${VERSION}-${TARGET}"
ARCHIVE="${STEM}.tar.gz"
BASE_URL="https://github.com/${REPO}/releases/download/${VERSION}"

say "Downloading ${ARCHIVE}..."
if [ -n "$FALLBACK_TARGET" ]; then
  if ! download_file "${BASE_URL}/${ARCHIVE}" "${TMP_DIR}/${ARCHIVE}" 2>/dev/null; then
    TARGET="$FALLBACK_TARGET"
    STEM="rship-${VERSION}-${TARGET}"
    ARCHIVE="${STEM}.tar.gz"
    say "gnu archive unavailable for ${VERSION}; falling back to ${ARCHIVE}..."
    download_file "${BASE_URL}/${ARCHIVE}" "${TMP_DIR}/${ARCHIVE}"
  fi
else
  download_file "${BASE_URL}/${ARCHIVE}" "${TMP_DIR}/${ARCHIVE}"
fi

if [ "$NO_VERIFY" != "1" ]; then
  say "Verifying SHA-256 checksum..."
  download_file "${BASE_URL}/SHA256SUMS.txt" "${TMP_DIR}/SHA256SUMS.txt"
  EXPECTED_SHA="$(awk -v f="$ARCHIVE" '$2 == f || $2 == ("*" f) { print $1; exit }' "${TMP_DIR}/SHA256SUMS.txt")"
  [ -n "$EXPECTED_SHA" ] || err "checksum entry for ${ARCHIVE} not found in SHA256SUMS.txt"
  ACTUAL_SHA="$(sha256_file "${TMP_DIR}/${ARCHIVE}")" || err "sha256sum, shasum, or openssl is required for verification (or pass --no-verify)"
  [ "$ACTUAL_SHA" = "$EXPECTED_SHA" ] || err "checksum mismatch for ${ARCHIVE} (expected ${EXPECTED_SHA}, got ${ACTUAL_SHA})"
fi

tar -xzf "${TMP_DIR}/${ARCHIVE}" -C "${TMP_DIR}"

SRC_BIN="${TMP_DIR}/${STEM}/rship"
if [ ! -f "$SRC_BIN" ]; then
  SRC_BIN="$(find "$TMP_DIR" -type f -name rship | head -n 1 || true)"
fi
[ -n "$SRC_BIN" ] && [ -f "$SRC_BIN" ] || err "rship binary not found inside ${ARCHIVE}"

mkdir -p "$INSTALL_DIR"
STAGED_BIN="${INSTALL_DIR}/.rship.tmp.$$"
cp "$SRC_BIN" "$STAGED_BIN"
chmod 755 "$STAGED_BIN"
mv -f "$STAGED_BIN" "${INSTALL_DIR}/rship"

INSTALLED_VER="$("${INSTALL_DIR}/rship" --version 2>/dev/null || printf '%s' "$VERSION")"
say "Installed ${INSTALLED_VER} to ${INSTALL_DIR}/rship"

case ":${PATH}:" in
  *:"${INSTALL_DIR}":*) ;;
  *)
    say "Note: ${INSTALL_DIR} is not on your PATH. Add it cleanly to your shell profile:"
    say "  export PATH=\"${INSTALL_DIR}:\$PATH\""
    ;;
esac
