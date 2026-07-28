#!/bin/bash
#
# ChatE2EE -- set the VM's clock and timezone correctly.
#
#   sudo bash deploy/fix_clock.sh                 # default: Europe/Helsinki
#   sudo bash deploy/fix_clock.sh --tz UTC        # keep the machine on UTC
#   sudo bash deploy/fix_clock.sh --tz Europe/Helsinki
#
# WHY A CLOCK LOOKS "WRONG" -- TWO INDEPENDENT THINGS
#
# What a timestamp reads is decided by two separate settings, and confusing
# them is what makes a clock seem "four hours behind":
#
#   1. The system CLOCK -- the actual UTC instant. This is correct only if time
#      synchronisation (NTP) is running. A VM whose clock has drifted, or that
#      booted with a bad clock, shows the wrong instant everywhere.
#   2. The TIMEZONE -- the offset applied when that instant is DISPLAYED. A
#      cloud image almost always ships as UTC. Finland in summer is EEST
#      (UTC+3), so a UTC machine displays local Finnish events three hours
#      earlier than your wall clock -- which reads as "behind".
#
# This script fixes both: it turns on NTP so the instant is correct, and sets
# the timezone so the DISPLAY matches your wall clock. It then verifies the
# result rather than assuming it took.
#
# It changes only system time settings. It does not touch the relay, which
# picks up the corrected time automatically at its next log line.

set -euo pipefail

BOLD=$'\033[1m'; RED=$'\033[31m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'; OFF=$'\033[0m'
ok()   { echo "  ${GREEN}ok${OFF}   $*"; }
warn() { echo "  ${YELLOW}warn${OFF} $*"; }
die()  { echo "  ${RED}FAIL${OFF} $*" >&2; exit 1; }

TZ_WANT="Europe/Helsinki"
while [ $# -gt 0 ]; do
    case "$1" in
        --tz) TZ_WANT="${2:-}"; shift 2 ;;
        -h|--help) sed -n '2,30p' "$0"; exit 0 ;;
        *) die "unknown argument: $1" ;;
    esac
done

[ "$(id -u)" -eq 0 ] || die "run this with sudo"
command -v timedatectl >/dev/null 2>&1 || die "timedatectl not found (not a systemd system?)"

echo "${BOLD}Before:${OFF}"
timedatectl | sed 's/^/  /'
echo

# 1. Timezone. Validate the name against the tz database before setting it, so
#    a typo fails loudly instead of silently leaving the old zone.
echo "${BOLD}1. Timezone -> ${TZ_WANT}${OFF}"
if [ ! -f "/usr/share/zoneinfo/${TZ_WANT}" ]; then
    die "unknown timezone '${TZ_WANT}'. List valid names with: timedatectl list-timezones"
fi
timedatectl set-timezone "${TZ_WANT}"
ok "timezone set to ${TZ_WANT}"

# 2. NTP. This is what makes the UTC instant correct and keeps it correct.
echo "${BOLD}2. Network time synchronisation${OFF}"
# On minimal images the sync service may not be installed. Add it if missing,
# because set-ntp true is a no-op with no service behind it.
if ! systemctl list-unit-files 2>/dev/null | grep -qE 'systemd-timesyncd|chrony|ntp'; then
    warn "no time-sync service found; installing systemd-timesyncd"
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq && apt-get install -y -qq systemd-timesyncd >/dev/null 2>&1 \
        || warn "could not install systemd-timesyncd; check connectivity"
fi
timedatectl set-ntp true || warn "set-ntp true was not accepted; check the sync service"
ok "NTP enabled"

# Give the sync a moment, then verify rather than trust.
echo "${BOLD}3. Verifying${OFF}"
sleep 3
SYNC=$(timedatectl show -p NTPSynchronized --value 2>/dev/null || echo "unknown")
if [ "${SYNC}" = "yes" ]; then
    ok "system clock is synchronised"
else
    warn "clock not reported synchronised yet (NTPSynchronized=${SYNC})."
    warn "It can take a minute after enabling. Re-check with: timedatectl"
    warn "If it never syncs, UDP 123 outbound may be blocked -- but note the"
    warn "cPouta security group governs INBOUND only, so egress NTP is usually"
    warn "fine; the likelier cause is a missing/again-disabled sync service."
fi

echo
echo "${BOLD}After:${OFF}"
timedatectl | sed 's/^/  /'
echo
echo "Local time now:  $(date '+%Y-%m-%d %H:%M:%S %Z')"
echo "UTC   time now:  $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
echo
echo "New journal lines will use ${TZ_WANT}. To read the journal in UTC at any"
echo "time regardless of this setting:  journalctl -u wsserver --utc"
echo
echo "Restart the relay so its own log lines pick up the new zone immediately:"
echo "  sudo systemctl restart wsserver"
