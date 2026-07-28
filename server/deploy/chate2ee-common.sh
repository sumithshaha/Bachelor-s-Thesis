#!/bin/bash
#
# ChatE2EE -- shared helpers for the deployment scripts.
# Sourced, not executed:  . "$(dirname "$0")/chate2ee-common.sh"

BOLD=$'\033[1m'; RED=$'\033[31m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'; OFF=$'\033[0m'
step() { echo; echo "${BOLD}==> $*${OFF}"; }
ok()   { echo "  ${GREEN}ok${OFF}   $*"; }
warn() { echo "  ${YELLOW}warn${OFF} $*"; }
die()  { echo "  ${RED}FAIL${OFF} $*" >&2; exit 1; }

# ---------------------------------------------------------------------------
# Working out which hostname this VM should get a certificate for.
#
# WHY THIS CANNOT JUST READ THE NETWORK INTERFACE
#
# On cPouta a floating IP is NAT'd onto the instance. The VM's own interface
# carries a private 192.168.x.x address and has no idea what its public
# address is -- `ip addr` and `hostname -I` both report the private one. Ask
# certbot for a certificate for a private address and Let's Encrypt will
# refuse, correctly, because it cannot reach it to validate.
#
# So the public address has to come from outside: either the operator states
# it, or an external echo service reports what address the request appeared to
# come from. The echo route is convenient but it is third-party input, so it is
# always shown for confirmation rather than used silently.
# ---------------------------------------------------------------------------

sslip_name() {
    # 86.50.22.138 -> 86-50-22-138.sslip.io
    echo "${1//./-}.sslip.io"
}

valid_ipv4() {
    local ip="$1" o
    [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || return 1
    IFS='.' read -ra o <<< "$ip"
    for n in "${o[@]}"; do
        [ "$n" -le 255 ] 2>/dev/null || return 1
    done
    return 0
}

is_private_ipv4() {
    # RFC 1918 plus loopback and link-local. If detection returns one of these
    # it has found the NAT interface rather than the floating IP, and using it
    # would produce a certificate request Let's Encrypt cannot validate.
    case "$1" in
        10.*|127.*|169.254.*|192.168.*) return 0 ;;
        172.1[6-9].*|172.2[0-9].*|172.3[01].*) return 0 ;;
        *) return 1 ;;
    esac
}

detect_public_ip() {
    # Several independent services, because any one of them can be down or
    # blocked, and a deployment script that fails because one third party is
    # having a bad day is not much of a deployment script.
    local svc ip
    for svc in "https://api.ipify.org" \
               "https://ifconfig.me/ip" \
               "https://icanhazip.com" \
               "https://ipinfo.io/ip"; do
        ip=$(curl -fsS --max-time 6 "$svc" 2>/dev/null | tr -d '[:space:]')
        if valid_ipv4 "$ip" && ! is_private_ipv4 "$ip"; then
            echo "$ip"
            return 0
        fi
    done
    return 1
}

# resolve_domain [explicit-domain-or-empty]
# Sets the globals DOMAIN and PUBLIC_IP.
resolve_domain() {
    local explicit="${1:-}"

    if [ -n "$explicit" ]; then
        DOMAIN="$explicit"
        PUBLIC_IP=""
        ok "using the hostname you supplied: ${DOMAIN}"
        return 0
    fi

    if [ -n "${CHATE2EE_DOMAIN:-}" ]; then
        DOMAIN="${CHATE2EE_DOMAIN}"
        PUBLIC_IP=""
        ok "using CHATE2EE_DOMAIN: ${DOMAIN}"
        return 0
    fi

    echo "  detecting this VM's public address..."
    if ! PUBLIC_IP=$(detect_public_ip); then
        die "could not determine the public address.
       Pass it explicitly:  --domain \$(echo 1.2.3.4 | tr . -).sslip.io
       or:                  CHATE2EE_DOMAIN=my.host.example sudo -E bash \$0
       The floating IP is the one shown in the Pouta console, not the
       192.168.x.x address this VM sees on its own interface."
    fi

    DOMAIN="$(sslip_name "$PUBLIC_IP")"
    ok "public address appears to be ${PUBLIC_IP}"
    ok "hostname will be ${DOMAIN}"

    # Confirm, because this value came from a third party and it is what the
    # certificate will be issued for. Getting it wrong wastes a Let's Encrypt
    # issuance and produces a certificate no client will accept.
    if [ "${CHATE2EE_ASSUME_YES:-0}" != "1" ]; then
        printf "  is %s the floating IP from the Pouta console? [y/N] " "$PUBLIC_IP"
        read -r reply < /dev/tty || reply=""
        case "$reply" in
            [yY]*) : ;;
            *) die "stopped. Re-run with --domain <hostname> once you have checked." ;;
        esac
    fi
    return 0
}

# Confirms that DNS actually resolves the chosen name to the expected address.
# sslip.io needs no registration, but it is still DNS, and a name that does not
# resolve is the single most common reason an HTTP-01 challenge fails.
check_dns() {
    local name="$1" expect="${2:-}"
    local got
    if ! command -v dig >/dev/null 2>&1 && ! command -v getent >/dev/null 2>&1; then
        warn "no dig or getent available; skipping the DNS check"
        return 0
    fi
    if command -v dig >/dev/null 2>&1; then
        got=$(dig +short "$name" 2>/dev/null | head -1)
    else
        got=$(getent hosts "$name" 2>/dev/null | awk '{print $1}' | head -1)
    fi
    if [ -z "$got" ]; then
        warn "${name} does not resolve yet"
        return 1
    fi
    if [ -n "$expect" ] && [ "$got" != "$expect" ]; then
        warn "${name} resolves to ${got}, but the floating IP is ${expect}"
        return 1
    fi
    ok "${name} resolves to ${got}"
    return 0
}
