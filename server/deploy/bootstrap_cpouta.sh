#!/bin/bash
#
# ChatE2EE -- stage 1 of 2: prepare a BARE cPouta VM and obtain a certificate.
#
#   sudo bash deploy/bootstrap_cpouta.sh              # detect the address
#   sudo bash deploy/bootstrap_cpouta.sh --domain X   # state it yourself
#   sudo -E bash deploy/bootstrap_cpouta.sh --email you@tuni.fi
#
# Then stage 2:
#
#   sudo bash deploy/install_cpouta.sh
#
# WHY TWO SCRIPTS
# ---------------
# This one touches the machine's shared state -- apt, certbot, the Let's
# Encrypt account -- and normally runs exactly once in a VM's life. The other
# installs the application and is meant to be re-run on every deployment. Made
# into one script, the risky once-only parts would be re-executed every time
# you shipped a code change, which is how a routine deploy turns into an
# outage.
#
# WHAT IT CANNOT DO
# -----------------
# It cannot open the cPouta security group. That is a cloud-level firewall in
# front of the instance, configured in the Pouta web console, and the VM has no
# authority over it. A missing rule there looks EXACTLY like a service that is
# down, so this script checks reachability and tells you plainly which it is.

set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=chate2ee-common.sh
. "${HERE}/chate2ee-common.sh"

DOMAIN=""; PUBLIC_IP=""; EMAIL=""; EXPLICIT_DOMAIN=""; STAGING_ONLY=0
while [ $# -gt 0 ]; do
    case "$1" in
        --domain) EXPLICIT_DOMAIN="${2:-}"; shift 2 ;;
        --email)  EMAIL="${2:-}"; shift 2 ;;
        --dry-run-only) STAGING_ONLY=1; shift ;;
        -h|--help) sed -n '2,30p' "$0"; exit 0 ;;
        *) die "unknown argument: $1" ;;
    esac
done

[ "$(id -u)" -eq 0 ] || die "run this with sudo"

step "1/6  Which hostname are we certifying?"
resolve_domain "${EXPLICIT_DOMAIN}"

step "2/6  Base packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
# python3-venv is separate from python3 on Ubuntu and its absence only shows up
# later, as a confusing failure inside `python3 -m venv`.
apt-get install -y -qq python3 python3-venv python3-pip sqlite3 curl dnsutils >/dev/null
ok "python3 $(python3 -c 'import sys; print("%d.%d.%d" % sys.version_info[:3])')"
ok "sqlite3 $(sqlite3 --version | awk '{print $1}')"

step "3/6  certbot"
if command -v certbot >/dev/null 2>&1; then
    ok "certbot already installed: $(certbot --version 2>&1 | head -1)"
elif command -v snap >/dev/null 2>&1; then
    snap install --classic certbot >/dev/null
    ln -sf /snap/bin/certbot /usr/bin/certbot
    ok "certbot installed via snap: $(certbot --version 2>&1 | head -1)"
else
    apt-get install -y -qq certbot >/dev/null
    ok "certbot installed from the distribution archive: $(certbot --version 2>&1 | head -1)"
fi

step "4/6  DNS"
# sslip.io needs no registration -- a-b-c-d.sslip.io resolves to a.b.c.d -- so
# this should be instant. If it is not, nothing after it can work.
if ! check_dns "${DOMAIN}" "${PUBLIC_IP}"; then
    warn "the HTTP-01 challenge validates by connecting to whatever this name"
    warn "resolves to, so it will fail until this is right."
    if [ "${CHATE2EE_ASSUME_YES:-0}" != "1" ]; then
        printf "  continue anyway? [y/N] "
        read -r reply < /dev/tty || reply=""
        case "$reply" in [yY]*) : ;; *) die "stopped" ;; esac
    fi
fi

step "5/6  Port 80"
# WHAT THIS DOES *NOT* DO, AND WHY
#
# The obvious check is to bind port 80 here and have something on the internet
# connect back to it. I wrote that first and then discarded it: from inside the
# VM, the sslip.io name resolves to the FLOATING ip, so the probe connects out
# and expects to arrive back at itself. That is NAT hairpinning, and OpenStack
# floating-IP setups frequently do not support it. The probe would report "port
# 80 unreachable" on a perfectly correctly configured VM and block the
# deployment for no reason.
#
# The authoritative test already exists and costs nothing: `certbot --dry-run`
# validates against the real Let's Encrypt staging servers, exercising DNS,
# inbound port 80 and the whole challenge flow, without consuming any rate
# limit. Step 6 runs it before the real issuance. So the only thing worth
# checking locally is the one thing the dry run cannot tell you apart from
# other failures: whether something else has already taken the port.
if command -v ss >/dev/null 2>&1 && ss -ltn 2>/dev/null | grep -q ':80 '; then
    warn "something is already listening on port 80:"
    ss -ltnp 2>/dev/null | grep ':80 ' | sed 's/^/      /'
    warn "certbot --standalone needs that port free. Stop the other service,"
    warn "or use 'certbot certonly --webroot -w <docroot>' instead."
else
    ok "port 80 is free for certbot --standalone"
fi
ok "the relay uses ${PORT_HINT:-8765}, so certbot does not disturb it"

echo
echo "  If the dry run in the next step fails, it is almost always one of:"
echo "    - TCP 80 not open in the cPouta security group (ingress, 0.0.0.0/0)"
echo "    - the floating IP not associated with this instance"
echo "    - the hostname not matching the floating IP"
echo
echo "  Open the rules in the Pouta console under"
echo "  Network -> Security Groups -> your group -> Manage Rules:"
echo "    Ingress  TCP  80    0.0.0.0/0    certbot HTTP-01, now AND at renewal"
echo "    Ingress  TCP  8765  0.0.0.0/0    the relay"
echo "    Ingress  TCP  22    your IP      SSH"

step "6/6  Certificate"
CERT_DIR="/etc/letsencrypt/live/${DOMAIN}"
if [ -d "${CERT_DIR}" ]; then
    ok "a certificate already exists for ${DOMAIN}"
    certbot certificates 2>/dev/null | sed 's/^/    /' || true
else
    EMAIL_ARGS=(--register-unsafely-without-email)
    if [ -n "${EMAIL}" ]; then
        EMAIL_ARGS=(-m "${EMAIL}" --no-eff-email)
    else
        warn "no --email given; registering without one means no expiry warnings by mail"
    fi

    echo "  rehearsing against the staging CA first (no rate-limit cost)..."
    if certbot certonly --standalone --dry-run -d "${DOMAIN}" \
            --agree-tos "${EMAIL_ARGS[@]}" --non-interactive; then
        ok "dry run succeeded"
    else
        die "the dry run failed. Nothing was issued, so no rate limit was consumed.
       Fix the cause above and re-run -- almost always DNS or port 80."
    fi

    if [ "${STAGING_ONLY}" -eq 1 ]; then
        ok "--dry-run-only was given; stopping before the real issuance"
        exit 0
    fi

    certbot certonly --standalone -d "${DOMAIN}" \
        --agree-tos "${EMAIL_ARGS[@]}" --non-interactive
    ok "certificate issued"
fi

openssl x509 -in "${CERT_DIR}/fullchain.pem" -noout -subject -issuer -dates \
    -ext subjectAltName 2>/dev/null | sed 's/^/    /'

echo
ok "bootstrap complete for ${DOMAIN}"
echo
echo "${BOLD}Next:${OFF}"
echo "  sudo bash deploy/install_cpouta.sh --domain ${DOMAIN}"
echo
echo "Point the client at:  wss://${DOMAIN}:8765"
