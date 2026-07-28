#!/bin/bash
#
# ChatE2EE -- one-shot installer for the cPouta VM.
#
# Run it from the directory holding the files it installs:
#
#     scp -r server/ ubuntu@86.50.22.138:/tmp/chate2ee-deploy/
#     ssh ubuntu@86.50.22.138
#     cd /tmp/chate2ee-deploy
#     sudo bash deploy/install_cpouta.sh
#
# WHAT IT DOES, AND WHAT IT DELIBERATELY DOES NOT
# -----------------------------------------------
# It does: create the service user, lay out /opt/wsserver, build a private
# virtual environment, install server.py and prekey_store.py, install the
# systemd unit and the certbot deploy hook, back up any existing database, and
# run the TLS preflight.
#
# It does NOT obtain the certificate. That is one interactive command
# (`certbot certonly --standalone -d <host>`) which prompts for an email and
# an agreement, and wrapping an interactive prompt inside a script only makes
# it harder to see what you agreed to. It also does not open the cPouta
# security group, which is a cloud-console action this VM cannot perform on
# its own behalf.
#
# It is SAFE TO RE-RUN. Every step is guarded: an existing user is not
# recreated, an existing database is backed up rather than replaced, and the
# service is stopped before files move and started again afterwards.

set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=chate2ee-common.sh
. "${HERE}/chate2ee-common.sh"

SERVICE="wsserver"
USER_NAME="wsserver"
PREFIX="/opt/wsserver"
PORT="${CHATE2EE_PORT:-8765}"
DOMAIN=""; PUBLIC_IP=""; EXPLICIT_DOMAIN=""

while [ $# -gt 0 ]; do
    case "$1" in
        --domain) EXPLICIT_DOMAIN="${2:-}"; shift 2 ;;
        --port)   PORT="${2:-}"; shift 2 ;;
        -h|--help) sed -n '2,32p' "$0"; exit 0 ;;
        *) die "unknown argument: $1" ;;
    esac
done

[ "$(id -u)" -eq 0 ] || die "run this with sudo"

# The script must be run from the directory that contains the payload, because
# copying the wrong server.py onto a production relay is not a mistake worth
# leaving available. Checking up front turns it into a clear error instead of a
# half-finished install.
# WHERE ARE THE FILES?
#
# Two layouts both reach this script, and it should not care which:
#   (a) canonical -- scripts in server/deploy/, code in server/ (the repo)
#   (b) flattened -- scripts and code together in server/ (what you get if the
#       deploy files were copied to the server/ root, or scp flattened them)
#
# So the two directories are discovered rather than assumed: DEPLOY_DIR is
# wherever this script actually lives, and CODE_DIR is wherever server.py
# actually is -- beside it, or one level up. Getting this wrong is how a deploy
# copies the wrong server.py onto a production relay, so both are verified and
# printed before anything is installed.
DEPLOY_DIR="${HERE}"
if [ -f "${DEPLOY_DIR}/server.py" ]; then
    CODE_DIR="${DEPLOY_DIR}"
elif [ -f "${DEPLOY_DIR}/../server.py" ]; then
    CODE_DIR="$(cd "${DEPLOY_DIR}/.." && pwd)"
else
    die "cannot find server.py next to this script or one level up.
       This script is at: ${DEPLOY_DIR}
       Run it from the copied server/ tree (canonical: server/deploy/, or the
       flattened layout with the scripts beside server.py)."
fi

for f in "${CODE_DIR}/server.py" "${CODE_DIR}/prekey_store.py" \
         "${DEPLOY_DIR}/wsserver.service" \
         "${DEPLOY_DIR}/chate2ee-cert-deploy.sh" \
         "${DEPLOY_DIR}/chate2ee-common.sh"; do
    [ -f "$f" ] || die "missing required file: $f"
done
ok "code from:    ${CODE_DIR}"
ok "scripts from: ${DEPLOY_DIR}"

step "1/10 Which hostname is this relay serving?"
# The deploy hook is generated per-host, so this has to be settled before
# anything else. On a rebuilt VM it is a NEW floating IP and therefore a new
# name -- nothing from the previous instance carries over.
resolve_domain "${EXPLICIT_DOMAIN}"

step "2/10 Checking the interpreter and SQLite"
PY=$(command -v python3) || die "python3 not found"
PYVER=$("$PY" -c 'import sys; print("%d.%d" % sys.version_info[:2])')
"$PY" - <<'PYEOF' || die "python3 is too old; the code uses 'str | None' unions (3.10+)"
import sys
raise SystemExit(0 if sys.version_info >= (3, 10) else 1)
PYEOF
ok "python3 ${PYVER} at ${PY}"
if command -v sqlite3 >/dev/null 2>&1; then
    SQLV=$(sqlite3 --version | awk '{print $1}')
    ok "sqlite3 ${SQLV}"
    # The prekey pool's atomic claim uses DELETE ... RETURNING, added in 3.35.
    "$PY" - "$SQLV" <<'PYEOF' || warn "sqlite3 < 3.35: the prekey store falls back to a non-atomic claim"
import sys
v = tuple(int(x) for x in sys.argv[1].split(".")[:3])
raise SystemExit(0 if v >= (3, 35, 0) else 1)
PYEOF
else
    warn "sqlite3 CLI not installed (the server uses Python's module, so this is only for your own inspection)"
fi

step "3/10 Service user"
if id "${USER_NAME}" >/dev/null 2>&1; then
    ok "user ${USER_NAME} already exists"
else
    useradd --system --home "${PREFIX}" --shell /usr/sbin/nologin "${USER_NAME}"
    ok "created system user ${USER_NAME}"
fi

step "4/10 Stopping the service if it is running"
if systemctl is-active --quiet "${SERVICE}" 2>/dev/null; then
    systemctl stop "${SERVICE}"
    ok "stopped ${SERVICE}"
else
    ok "${SERVICE} was not running"
fi

step "5/10 Directory layout"
install -d -m 0755 -o "${USER_NAME}" -g "${USER_NAME}" "${PREFIX}"
install -d -m 0750 -o "${USER_NAME}" -g "${USER_NAME}" "${PREFIX}/tls"
ok "${PREFIX} and ${PREFIX}/tls"

step "6/10 Backing up the existing database"
# WAL mode means a database is only complete together with its sidecars, so
# all three are copied. Restoring the .db alone would restore it to a state its
# own journal disagrees with.
if [ -f "${PREFIX}/chat.db" ]; then
    STAMP=$(date +%Y%m%d-%H%M%S)
    for ext in "" "-wal" "-shm"; do
        [ -f "${PREFIX}/chat.db${ext}" ] && \
            cp -p "${PREFIX}/chat.db${ext}" "${PREFIX}/chat.db${ext}.bak-${STAMP}"
    done
    ok "backed up chat.db (+ WAL sidecars) as .bak-${STAMP}"
    echo "       restore with: systemctl stop ${SERVICE} && cp ${PREFIX}/chat.db.bak-${STAMP} ${PREFIX}/chat.db"
else
    ok "no existing database (first install)"
fi

step "7/10 Virtual environment"
# A private venv keeps the relay's one dependency off the system Python, so an
# unrelated apt upgrade cannot move it underneath the service.
if [ ! -x "${PREFIX}/.venv/bin/python" ]; then
    sudo -u "${USER_NAME}" "$PY" -m venv "${PREFIX}/.venv"
    ok "created ${PREFIX}/.venv"
else
    ok "${PREFIX}/.venv already present"
fi
sudo -u "${USER_NAME}" "${PREFIX}/.venv/bin/pip" install --quiet --upgrade pip
# websockets is the relay's ONLY runtime dependency. cryptography and pynacl
# belong to crypto_core.py / file_crypto.py, which are the Python reference
# implementations for the test suite and are not imported by server.py.
sudo -u "${USER_NAME}" "${PREFIX}/.venv/bin/pip" install --quiet 'websockets>=13,<17'
WSV=$(sudo -u "${USER_NAME}" "${PREFIX}/.venv/bin/python" -c 'import websockets; print(websockets.__version__)')
ok "websockets ${WSV}"

step "8/10 Application code"
if [ -f "${PREFIX}/server.py" ]; then
    cp -p "${PREFIX}/server.py" "${PREFIX}/server.py.bak-$(date +%Y%m%d-%H%M%S)"
    ok "kept a copy of the previous server.py"
fi
install -m 0644 -o "${USER_NAME}" -g "${USER_NAME}" "${CODE_DIR}/server.py"        "${PREFIX}/server.py"
install -m 0644 -o "${USER_NAME}" -g "${USER_NAME}" "${CODE_DIR}/prekey_store.py"  "${PREFIX}/prekey_store.py"
ok "installed server.py and prekey_store.py"

step "9/10 systemd unit and certbot deploy hook"
# Written before the hook is installed, because the hook refuses to run without
# it. Keeping the hostname here rather than inside the hook means a rebuilt VM
# needs no script edits -- just re-run this installer with the new address.
cat > /etc/default/chate2ee <<CONFEOF
# ChatE2EE deployment configuration.
# Written by install_cpouta.sh on $(date -u '+%Y-%m-%d %H:%M:%S UTC').
# Read by /etc/letsencrypt/renewal-hooks/deploy/chate2ee.sh.
CHATE2EE_DOMAIN=${DOMAIN}
CHATE2EE_SERVICE=${SERVICE}
CHATE2EE_USER=${USER_NAME}
CHATE2EE_TLS_DIR=${PREFIX}/tls
CONFEOF
chmod 0644 /etc/default/chate2ee
ok "wrote /etc/default/chate2ee (domain ${DOMAIN})"

install -d -m 0755 /etc/systemd/system
install -m 0644 -o root -g root "${DEPLOY_DIR}/wsserver.service" \
        /etc/systemd/system/wsserver.service
install -d -m 0755 /etc/letsencrypt/renewal-hooks/deploy
install -m 0755 -o root -g root "${DEPLOY_DIR}/chate2ee-cert-deploy.sh" \
        /etc/letsencrypt/renewal-hooks/deploy/chate2ee.sh
ok "unit and deploy hook copied into place"

# Keep a copy of the deploy scripts next to the application, so a future
# rebuild does not depend on finding the original checkout.
install -d -m 0755 -o "${USER_NAME}" -g "${USER_NAME}" "${PREFIX}/deploy"
for f in chate2ee-common.sh install_cpouta.sh bootstrap_cpouta.sh chate2ee-cert-deploy.sh wsserver.service; do
    [ -f "${DEPLOY_DIR}/${f}" ] && \
        install -m 0644 -o "${USER_NAME}" -g "${USER_NAME}" \
                "${DEPLOY_DIR}/${f}" "${PREFIX}/deploy/${f}"
done
ok "deployment scripts archived in ${PREFIX}/deploy"

# Guarded rather than bare. A container or chroot has no running systemd, and
# `set -e` would otherwise abort here having already copied the unit -- leaving
# a half-finished install whose last message is an unrelated D-Bus error. The
# cPouta VM does run systemd, so this branch is for the person who tries the
# script somewhere else first, which is a reasonable thing to do.
HAVE_SYSTEMD=0
if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
    HAVE_SYSTEMD=1
fi

if [ "${HAVE_SYSTEMD}" -eq 1 ]; then
    systemctl daemon-reload
    ok "systemd reloaded"
else
    warn "systemd is not running here, so the unit was copied but not loaded"
    warn "on the VM this step runs automatically; elsewhere it is a no-op"
fi

if command -v systemd-analyze >/dev/null 2>&1; then
    if systemd-analyze verify /etc/systemd/system/wsserver.service 2>/dev/null; then
        ok "systemd-analyze verify passed"
    else
        warn "systemd-analyze verify reported something -- read it before enabling"
    fi
fi

# Populate ${PREFIX}/tls now if the certificate already exists, so the preflight
# below has something to check.
if [ -d "/etc/letsencrypt/live/${DOMAIN}" ]; then
    /etc/letsencrypt/renewal-hooks/deploy/chate2ee.sh || \
        warn "the deploy hook reported a problem"
else
    warn "no certificate at /etc/letsencrypt/live/${DOMAIN} yet -- see step 9"
fi

step "10/10 TLS preflight, as the service user"
# This is the check that separates "works when I run it as root" from "works
# under systemd". It answers one question: can THIS user read and load THESE
# files? No port is bound and no database is touched.
if sudo -u "${USER_NAME}" \
     CHATE2EE_TLS_CERT="${PREFIX}/tls/fullchain.pem" \
     CHATE2EE_TLS_KEY="${PREFIX}/tls/privkey.pem" \
     "${PREFIX}/.venv/bin/python" "${PREFIX}/server.py" --check-tls; then
    echo
    ok "TLS is ready"
    echo
    echo "${BOLD}Start it:${OFF}"
    echo "  sudo systemctl enable --now ${SERVICE}"
    echo "  journalctl -u ${SERVICE} -f"
    echo
    echo "You want to see 'Listening on wss://0.0.0.0:${PORT}'."
    echo "'Running WITHOUT TLS' means the certificate did not load."
    echo
    echo "${BOLD}Point the client at:${OFF}  wss://${DOMAIN}:${PORT}"
else
    echo
    warn "TLS is not ready yet. Obtain the certificate, then re-run this script:"
    echo
    echo "  # Port 80 must be open in the cPouta security group for this."
    echo "  sudo bash \"${DEPLOY_DIR}/bootstrap_cpouta.sh\" --domain ${DOMAIN} --email you@tuni.fi"
    echo "  sudo bash \"${DEPLOY_DIR}/install_cpouta.sh\" --domain ${DOMAIN}"
    echo
    echo "The relay would still start without it, in plain ws:// mode."
    echo "Do not leave it that way."
fi
