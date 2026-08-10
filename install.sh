#!/bin/sh
set -eu

# smol installer — builds from this checkout and installs the binary.
#
#   git clone <repo> && cd smolnet
#   sudo ./install.sh <host>:<port>
#
# <host>:<port> is the control server's raw tcp/udp port (the mesh reflector and
# grpc endpoint). The https api is derived from the same host as
# https://<host>/api, because the http proxy in front of it cannot carry grpc.
#
# Once there are published builds this is replaced by a download+verify script.

BINARY_NAME="smol"
INSTALL_DIR="${SMOL_INSTALL_DIR:-/usr/local/bin}"
BINARY_PATH="${INSTALL_DIR}/${BINARY_NAME}"
ENDPOINT_DIR="/etc/smol"
ENDPOINT_PATH="${ENDPOINT_DIR}/config.toml"

SOURCE_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

# --- Control server endpoint ---

ENDPOINT="${1:-}"

if [ -z "${ENDPOINT}" ]; then
    if [ -f "${ENDPOINT_PATH}" ]; then
        echo "  - keeping the endpoint already in ${ENDPOINT_PATH}"
    else
        echo "usage: sudo ./install.sh <host>:<port>"
        echo ""
        echo "  <host>  the control server's hostname"
        echo "  <port>  its raw tcp/udp port (mesh reflector + grpc)"
        echo ""
        echo "example: sudo ./install.sh smolmesh-sync.boxd-metal.sh:54189"
        exit 1
    fi
else
    CONTROL_HOST=${ENDPOINT%%:*}
    CONTROL_PORT=${ENDPOINT##*:}

    if [ "${CONTROL_HOST}" = "${ENDPOINT}" ] || [ -z "${CONTROL_PORT}" ]; then
        echo "error: expected <host>:<port>, got '${ENDPOINT}'"
        exit 1
    fi

    case "${CONTROL_PORT}" in
        ''|*[!0-9]*) echo "error: '${CONTROL_PORT}' is not a port number"; exit 1 ;;
    esac

    CONTROL_API="https://${CONTROL_HOST}/api"
    CONTROL_MESH="${CONTROL_HOST}:${CONTROL_PORT}"
fi

OS=$(uname -s)
ARCH=$(uname -m)

case "${OS}" in
    Darwin|Linux) ;;
    *) echo "error: unsupported OS: ${OS}"; exit 1 ;;
esac

echo ""
echo "  smol installer (${OS} ${ARCH}, from source)"
echo ""

# --- Must be root to write the install dir and register the service ---

if [ "$(id -u)" -ne 0 ]; then
    echo "  x this installer needs root: sudo ./install.sh"
    exit 1
fi

# --- Build as the invoking user, not as root ---
#
# Building under sudo would write root-owned artifacts into ./target and use
# root's cargo, which usually is not installed. Drop back to the user who
# invoked sudo so their toolchain and cache are used.

BUILD_USER="${SUDO_USER:-}"

if [ -n "${BUILD_USER}" ] && [ "${BUILD_USER}" != "root" ]; then
    echo "  - building as ${BUILD_USER}"
    su - "${BUILD_USER}" -c "cd '${SOURCE_DIR}' && cargo build --release --bin ${BINARY_NAME}" \
        || { echo "  x build failed"; exit 1; }
else
    command -v cargo >/dev/null 2>&1 || {
        echo "  x cargo not found; install rust from https://rustup.rs"
        exit 1
    }
    cargo build --release --bin "${BINARY_NAME}" --manifest-path "${SOURCE_DIR}/Cargo.toml" \
        || { echo "  x build failed"; exit 1; }
fi

BUILT="${SOURCE_DIR}/target/release/${BINARY_NAME}"

if [ ! -x "${BUILT}" ]; then
    echo "  x expected a binary at ${BUILT}"
    exit 1
fi

echo "  - built"

# --- Stop a running daemon before replacing the binary it runs ---

if [ -x "${BINARY_PATH}" ]; then
    "${BINARY_PATH}" stop >/dev/null 2>&1 || true
fi

mkdir -p "${INSTALL_DIR}"
install -m 0755 "${BUILT}" "${BINARY_PATH}"

if [ "${OS}" = "Darwin" ]; then
    xattr -d com.apple.quarantine "${BINARY_PATH}" 2>/dev/null || true
fi

echo "  - installed to ${BINARY_PATH}"

# --- Record the endpoint for every user on this machine ---

if [ -n "${ENDPOINT}" ]; then
    mkdir -p "${ENDPOINT_DIR}"
    umask 022
    if [ -f "${ENDPOINT_PATH}" ]; then
        # keep whatever credentials are already there, replace only the endpoint
        sed -i.bak '/^control =/d; /^mesh =/d; /^# written by smol/d' "${ENDPOINT_PATH}" 2>/dev/null || true
        rm -f "${ENDPOINT_PATH}.bak"
        printf 'control = "%s"\nmesh = "%s"\n' "${CONTROL_API}" "${CONTROL_MESH}" \
            | cat - "${ENDPOINT_PATH}" > "${ENDPOINT_PATH}.next"
        mv "${ENDPOINT_PATH}.next" "${ENDPOINT_PATH}"
    else
        printf '# written by smol\ncontrol = "%s"\nmesh = "%s"\n' \
            "${CONTROL_API}" "${CONTROL_MESH}" > "${ENDPOINT_PATH}"
    fi
    chmod 0644 "${ENDPOINT_PATH}"

    echo "  - api  ${CONTROL_API}"
    echo "  - mesh ${CONTROL_MESH}"
fi

# --- Restart a daemon that was already configured ---

if "${BINARY_PATH}" status 2>/dev/null | grep -qv "not installed"; then
    "${BINARY_PATH}" start >/dev/null 2>&1 \
        && echo "  - daemon restarted on the new binary" || true
fi

echo ""
echo "  Ready! Next:"
echo ""
echo "    smol login"

if [ "${OS}" = "Darwin" ]; then
    echo "    sudo smol start   # installs a LaunchDaemon at /Library/LaunchDaemons"
else
    echo "    sudo smol start   # installs a systemd unit at /etc/systemd/system"
fi

echo ""
echo "  Run 'smol login' as yourself, not with sudo: it writes to ~/.config/smol."
echo "  The daemon needs root to create the tunnel interface."
echo ""
