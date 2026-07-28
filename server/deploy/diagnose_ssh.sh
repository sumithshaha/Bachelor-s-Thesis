#!/bin/bash
#
# ChatE2EE -- diagnose an SSH/scp key problem BEFORE it wastes your time.
#
#   bash deploy/diagnose_ssh.sh <keyfile> <user@host>
#   bash deploy/diagnose_ssh.sh ~/thesis.key ubuntu@86.50.230.46
#
# WHY THIS EXISTS
#
# The symptom you hit -- scp fails with "Permission denied (publickey)" while
# `sudo ssh -i key` works -- has a specific, non-obvious cause, and `sudo`
# actively hides it. This script reproduces the checks OpenSSH itself makes,
# as your normal user, and tells you which one is failing. It makes no network
# change and needs no root.
#
# Run WITHOUT sudo. The whole point is to test what your normal user can do,
# because that is what scp will be.

set -uo pipefail

BOLD=$'\033[1m'; RED=$'\033[31m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'; OFF=$'\033[0m'
ok()   { echo "  ${GREEN}ok${OFF}   $*"; }
bad()  { echo "  ${RED}FAIL${OFF} $*"; }
warn() { echo "  ${YELLOW}warn${OFF} $*"; }

[ $# -eq 2 ] || { echo "usage: bash $0 <keyfile> <user@host>"; exit 2; }
KEY="$1"; TARGET="$2"
FAILED=0

if [ "$(id -u)" -eq 0 ]; then
    warn "you are running this as root (via sudo?)."
    warn "scp will run as your NORMAL user, so run this WITHOUT sudo to get a"
    warn "true picture. root bypasses exactly the checks that are failing."
    echo
fi

echo "${BOLD}1. Does the key file exist and where?${OFF}"
if [ ! -e "$KEY" ]; then
    bad "no such file: $KEY"
    echo "     (the ssh that worked used '-i thesis.key' from your home dir;"
    echo "      give the same path here, e.g. ~/thesis.key)"
    exit 1
fi
KEY_ABS="$(cd "$(dirname "$KEY")" && pwd)/$(basename "$KEY")"
ok "found: ${KEY_ABS}"

# The /mnt/c trap: a key on the Windows drive under WSL cannot be chmod'd, so
# OpenSSH will always consider it too open. This is worth catching explicitly
# because the fix (move it to ~) is different from the usual fix (chmod).
case "$KEY_ABS" in
    /mnt/[a-z]/*)
        warn "this key is on a Windows drive (${KEY_ABS%%/*}/mnt/...)."
        warn "WSL usually cannot set Unix permissions there, so OpenSSH will"
        warn "treat it as 'too open' no matter what chmod you run. Move it into"
        warn "the WSL filesystem, which fixes the permission problem for good:"
        echo "         mkdir -p ~/.ssh && cp '${KEY_ABS}' ~/.ssh/thesis.key"
        echo "         chmod 600 ~/.ssh/thesis.key"
        echo "         # then use ~/.ssh/thesis.key from here on"
        ;;
esac

echo
echo "${BOLD}2. Permissions -- the usual cause of your exact error${OFF}"
MODE=$(stat -c '%a' "$KEY" 2>/dev/null || stat -f '%Lp' "$KEY" 2>/dev/null)
OWNER=$(stat -c '%U' "$KEY" 2>/dev/null || stat -f '%Su' "$KEY" 2>/dev/null)
echo "     mode ${MODE}, owner ${OWNER}"
if [ "$OWNER" != "$(id -un)" ] && [ "$OWNER" != "unknown" ]; then
    bad "the key is owned by ${OWNER}, not you ($(id -un))."
    echo "     OpenSSH refuses a key it does not own, even at mode 600, with"
    echo "     'Load key ...: Permission denied'. This often happens after a"
    echo "     'sudo ssh' created or touched files as root. Fix:"
    echo "         sudo chown $(id -un) '${KEY}'"
    FAILED=1
fi
# OpenSSH refuses anything group- or world-accessible.
if [ -n "$MODE" ] && [ "$MODE" != "600" ] && [ "$MODE" != "400" ]; then
    if [ "$((0$MODE & 077))" -ne 0 ]; then
        bad "mode ${MODE} is too open: readable by group or others."
        echo "     THIS is what makes scp fall back to 'Permission denied"
        echo "     (publickey)'. OpenSSH prints 'Permissions ${MODE} for ... are"
        echo "     too open. This private key will be ignored.' Fix:"
        echo "         chmod 600 '${KEY}'"
        FAILED=1
    else
        ok "mode ${MODE} is acceptable (not group/other accessible)"
    fi
else
    ok "mode ${MODE} is correct"
fi

echo
echo "${BOLD}3. Can OpenSSH actually load this key?${OFF}"
# ssh-keygen -y applies the SAME permission and ownership policy as ssh, with
# no network. If this succeeds, the key itself is usable.
if LOADOUT=$(ssh-keygen -y -f "$KEY" 2>&1); then
    ok "the key loads: ${LOADOUT:0:38}..."
else
    bad "OpenSSH will not load this key:"
    echo "$LOADOUT" | sed 's/^/       /'
    FAILED=1
fi

echo
echo "${BOLD}4. Does the key authenticate to ${TARGET}?${OFF}"
# BatchMode=yes -> never fall back to a password prompt, so this either
# authenticates with the key or fails cleanly. No sudo.
if ssh -i "$KEY" -o BatchMode=yes -o ConnectTimeout=8 \
       -o StrictHostKeyChecking=accept-new "$TARGET" true 2>/tmp/diag_ssh.$$; then
    ok "authenticated with the key -- scp will work with the same -i"
else
    rc=$?
    bad "ssh with this key failed (exit ${rc}):"
    sed 's/^/       /' /tmp/diag_ssh.$$ | head -6
    FAILED=1
fi
rm -f /tmp/diag_ssh.$$

echo
if [ "$FAILED" -eq 0 ]; then
    echo "${GREEN}${BOLD}All checks passed.${OFF} Copy the code with the SAME key, no sudo."
    echo "Create the target directory first — modern scp will NOT create it and"
    echo "otherwise fails with 'path canonicalization failed':"
    echo
    echo "  ssh -i ${KEY} ${TARGET} 'mkdir -p /tmp/chate2ee-deploy'"
    echo "  scp -i ${KEY} -r server/ ${TARGET}:/tmp/chate2ee-deploy/"
    echo
    echo "Then on the VM:"
    echo "  cd /tmp/chate2ee-deploy/server"
    echo "  sudo bash bootstrap_cpouta.sh --email you@tuni.fi"
    echo "  sudo bash install_cpouta.sh"
else
    echo "${RED}${BOLD}Fix the FAIL line(s) above, then re-run this script.${OFF}"
    echo "Do NOT reach for 'sudo' to make it work -- it hides these faults"
    echo "rather than fixing them, and 'sudo scp' would copy files as the wrong"
    echo "user and leave root-owned files on the VM."
fi
exit "$FAILED"
