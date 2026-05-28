#!/bin/sh
# install.sh - download, verify, and install the roe binary.
#
# Usage:
#   ./install.sh                 # install the default version
#   VERSION=1.2.3 ./install.sh   # install a specific version
#
# The script downloads a prebuilt release asset and its .sha256 checksum from
# the GitHub releases page, verifies the SHA-256, and installs the `roe`
# binary to /usr/local/bin when writable (or when run as root) and otherwise
# to ~/.local/bin. Re-running the script is safe and overwrites any previous
# install of the same name.

set -eu

VERSION="${VERSION:-1.0.0}"
REPO="manop55555/roe"
BASE_URL="https://github.com/${REPO}/releases/download/v${VERSION}"

log() {
    printf '%s\n' "$*"
}

die() {
    printf 'error: %s\n' "$*" >&2
    exit 1
}

# Detect the operating system and normalize it to the release naming scheme.
detect_os() {
    os="$(uname -s)"
    case "${os}" in
        Linux) echo "linux" ;;
        Darwin) echo "darwin" ;;
        *) die "unsupported operating system: ${os}" ;;
    esac
}

# Detect the CPU architecture and normalize it to the release naming scheme.
detect_arch() {
    arch="$(uname -m)"
    case "${arch}" in
        x86_64 | amd64) echo "x86_64" ;;
        aarch64 | arm64) echo "aarch64" ;;
        armv7l | armv7 | armhf | arm) echo "arm" ;;
        riscv64) echo "riscv64" ;;
        *) die "unsupported architecture: ${arch}" ;;
    esac
}

# Download URL "$1" to local path "$2" using curl or wget.
download() {
    url="$1"
    dest="$2"
    if command -v curl >/dev/null 2>&1; then
        curl --fail --location --silent --show-error --output "${dest}" "${url}"
    elif command -v wget >/dev/null 2>&1; then
        wget --quiet --output-document="${dest}" "${url}"
    else
        die "neither curl nor wget is available"
    fi
}

# Verify that the file "$1" matches the checksum file "$2".
verify_checksum() {
    file="$1"
    sumfile="$2"
    dir="$(dirname "${file}")"
    base="$(basename "${file}")"

    # The .sha256 file contains "<hash>  <name>"; check it in the file's own
    # directory so the embedded file name resolves.
    if command -v sha256sum >/dev/null 2>&1; then
        (cd "${dir}" && sha256sum -c "$(basename "${sumfile}")") >/dev/null
    elif command -v shasum >/dev/null 2>&1; then
        (cd "${dir}" && shasum -a 256 -c "$(basename "${sumfile}")") >/dev/null
    else
        die "neither sha256sum nor shasum is available for verification"
    fi
    log "Checksum verified for ${base}"
}

# Choose an installation directory that is writable by the current user.
install_dir() {
    if [ "$(id -u)" = "0" ] || [ -w /usr/local/bin ]; then
        echo "/usr/local/bin"
    else
        echo "${HOME}/.local/bin"
    fi
}

main() {
    os="$(detect_os)"
    arch="$(detect_arch)"
    asset="roe-${VERSION}-${os}-${arch}.tar.gz"
    asset_url="${BASE_URL}/${asset}"
    sum_url="${asset_url}.sha256"

    log "Installing roe ${VERSION} for ${os}/${arch}"

    tmpdir="$(mktemp -d)"
    trap 'rm -rf "${tmpdir}"' EXIT INT TERM

    log "Downloading ${asset_url}"
    download "${asset_url}" "${tmpdir}/${asset}"

    log "Downloading ${sum_url}"
    download "${sum_url}" "${tmpdir}/${asset}.sha256"

    verify_checksum "${tmpdir}/${asset}" "${tmpdir}/${asset}.sha256"

    log "Extracting ${asset}"
    tar -xzf "${tmpdir}/${asset}" -C "${tmpdir}"

    binary="$(find "${tmpdir}" -type f -name roe -perm -u+x 2>/dev/null | head -n 1)"
    if [ -z "${binary}" ]; then
        binary="$(find "${tmpdir}" -type f -name roe 2>/dev/null | head -n 1)"
    fi
    [ -n "${binary}" ] || die "could not find the roe binary inside ${asset}"

    dest_dir="$(install_dir)"
    mkdir -p "${dest_dir}"

    if command -v install >/dev/null 2>&1; then
        install -m 0755 "${binary}" "${dest_dir}/roe"
    else
        cp "${binary}" "${dest_dir}/roe"
        chmod 0755 "${dest_dir}/roe"
    fi

    log "Installed roe to ${dest_dir}/roe"

    case ":${PATH}:" in
        *":${dest_dir}:"*) ;;
        *) log "Note: ${dest_dir} is not on your PATH; add it to use 'roe' directly." ;;
    esac

    log "Done. Run 'roe --version' to verify."
}

main "$@"
