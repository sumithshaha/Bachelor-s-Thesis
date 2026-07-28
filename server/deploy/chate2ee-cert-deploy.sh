#!/bin/bash
#
# ChatE2EE -- certbot deploy hook.
#
# Install as:
#   sudo install -m 0755 -o root -g root \
#        chate2ee-cert-deploy.sh /etc/letsencrypt/renewal-hooks/deploy/chate2ee.sh
#
# Everything in /etc/letsencrypt/renewal-hooks/deploy/ is executed by certbot
# after a SUCCESSFUL issuance or renewal, and only then -- a failed renewal
# runs nothing, so this script never sees a half-written certificate.
#
# It exists to solve two problems that would otherwise both be silent.
#
# PROBLEM 1 -- PERMISSIONS.
# /etc/letsencrypt/live and /etc/letsencrypt/archive are mode 0700 root:root.
# The relay runs as an unprivileged user and simply cannot read privkey.pem
# from there. The alternatives were to run the relay as root (which throws
# away the reason for having a service user at all) or to loosen those
# directories with setfacl (which works, but lives only in the filesystem --
# invisible to the repository, and gone if the directories are ever
# recreated). Copying with explicit ownership keeps the policy in a file you
# can read, review and reinstall.
#
# PROBLEM 2 -- THE RENEWED CERTIFICATE NEVER REACHING THE PROCESS.
# server.py builds its SSLContext once, in make_ssl_context(), before serve():
#
#     ctx.load_cert_chain(certfile, keyfile)
#
# That context then lives for the life of the process. There is no SNI
# callback and no file watch. So when certbot renews at day 60 and writes new
# files, the running relay carries on presenting the OLD certificate from
# memory, and keeps doing so until something restarts it -- eventually serving
# an expired certificate while `certbot certificates` reports everything as
# valid. The restart at the end of this script is what closes that gap.
#
# Test the whole path without waiting 60 days:
#   sudo certbot renew --dry-run
# and watch `journalctl -u wsserver -f` for the restart.

set -euo pipefail

# The hostname is NOT baked in. It is written by install_cpouta.sh into the
# config below, because a rebuilt VM gets a new floating IP and therefore a new
# sslip.io name -- and a hook still pointing at a previous instance's hostname
# would silently copy nothing, leaving the relay on a certificate that quietly
# expires. Reading it from a file makes rebuilding a matter of re-running the
# installer rather than remembering to edit a script.
CONFIG="/etc/default/chate2ee"
DOMAIN=""
# shellcheck source=/dev/null
[ -r "${CONFIG}" ] && . "${CONFIG}"

SERVICE="${CHATE2EE_SERVICE:-wsserver}"
DEST="${CHATE2EE_TLS_DIR:-/opt/wsserver/tls}"
OWNER="${CHATE2EE_USER:-wsserver}"
DOMAIN="${CHATE2EE_DOMAIN:-${DOMAIN}}"

if [ -z "${DOMAIN}" ]; then
    echo "[chate2ee-cert-deploy] ERROR: no domain configured." >&2
    echo "  Expected CHATE2EE_DOMAIN in ${CONFIG}." >&2
    echo "  Re-run: sudo bash deploy/install_cpouta.sh --domain <hostname>" >&2
    exit 1
fi

SRC="/etc/letsencrypt/live/${DOMAIN}"

log() { echo "[chate2ee-cert-deploy] $*"; }

# certbot sets RENEWED_LINEAGE to the live directory of the certificate it
# just renewed. On a machine with one certificate this is always ours, but
# checking makes the hook safe to leave in place if a second one is ever added
# -- otherwise a renewal for some other domain would copy the wrong files.
if [ -n "${RENEWED_LINEAGE:-}" ] && [ "${RENEWED_LINEAGE}" != "${SRC}" ]; then
    log "renewal was for ${RENEWED_LINEAGE}, not ${SRC} -- nothing to do"
    exit 0
fi

if [ ! -r "${SRC}/fullchain.pem" ] || [ ! -r "${SRC}/privkey.pem" ]; then
    log "ERROR: cannot read the certificate at ${SRC}" >&2
    log "       (this hook must run as root)" >&2
    exit 1
fi

install -d -m 0750 -o "${OWNER}" -g "${OWNER}" "${DEST}"

# Write to a temporary name and then move into place. mv within one filesystem
# is atomic, so the relay can never be restarted against a half-copied key --
# which, given the restart at the end of this script, is a real ordering worth
# getting right rather than a theoretical one.
install -m 0644 -o "${OWNER}" -g "${OWNER}" "${SRC}/fullchain.pem" "${DEST}/.fullchain.pem.new"
install -m 0640 -o "${OWNER}" -g "${OWNER}" "${SRC}/privkey.pem"   "${DEST}/.privkey.pem.new"
mv -f "${DEST}/.fullchain.pem.new" "${DEST}/fullchain.pem"
mv -f "${DEST}/.privkey.pem.new"   "${DEST}/privkey.pem"

log "installed certificate for ${DOMAIN} into ${DEST}"
log "  not valid after: $(openssl x509 -in "${DEST}/fullchain.pem" -noout -enddate | cut -d= -f2)"

# Restart, not reload: the relay has no reload path, for the reason above.
if systemctl is-enabled --quiet "${SERVICE}" 2>/dev/null; then
    log "restarting ${SERVICE} so the new certificate is actually served"
    systemctl restart "${SERVICE}"
    sleep 2
    if systemctl is-active --quiet "${SERVICE}"; then
        log "${SERVICE} is running"
    else
        log "ERROR: ${SERVICE} did not come back up -- check journalctl -u ${SERVICE}" >&2
        exit 1
    fi
else
    log "${SERVICE} is not enabled; skipping restart"
fi

log "done"
