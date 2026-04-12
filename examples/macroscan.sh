#!/usr/bin/env bash
# macroscan.sh — Comprehensive network scanning orchestrator for runZeroHound
#
# Installs and runs multiple scanning tools concurrently against a target
# network, writing all output to a timestamped directory. Results can be
# imported into runZeroHound with:
#
#   runZeroHound convert <output-dir>/*
#
# Usage:
#   sudo ./macroscan.sh <CIDR> [CIDR ...]
#
# Examples:
#   sudo ./macroscan.sh 192.168.1.0/24
#   sudo ./macroscan.sh 10.0.0.0/24 172.16.0.0/16
#
# Requirements:
#   - Debian/Ubuntu system with apt
#   - Root privileges (required for raw-socket scanning)
#   - Internet access (for package and binary downloads)

set -euo pipefail

# ─── Color helpers ────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

info()  { echo -e "${BLUE}[*]${NC} $*"; }
ok()    { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
fail()  { echo -e "${RED}[-]${NC} $*"; }

# ─── Pre-flight checks ───────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    fail "This script must be run as root (raw sockets, packet capture, etc.)."
    echo "  Try: sudo $0 $*"
    exit 1
fi

if [[ $# -lt 1 ]]; then
    fail "Usage: $0 <CIDR> [CIDR ...]"
    echo "  Example: sudo $0 192.168.1.0/24"
    exit 1
fi

TARGETS=("$@")
# Collapse all CIDRs into a comma-separated string for tools that want it
TARGET_CSV=$(IFS=,; echo "${TARGETS[*]}")
# Use the first CIDR as the primary target for single-target tools
PRIMARY_TARGET="${TARGETS[0]}"

# ─── Output directory ─────────────────────────────────────────────────────────
DATE_TAG=$(date +%Y%m%d-%H%M%S)
OUTDIR="./macroscan-${DATE_TAG}"
mkdir -p "${OUTDIR}"
info "Output directory: ${OUTDIR}"

# Temp directory for downloaded binaries
TOOLDIR="${OUTDIR}/.tools"
mkdir -p "${TOOLDIR}"

# ─── Architecture detection ──────────────────────────────────────────────────
ARCH=$(uname -m)
case "${ARCH}" in
    x86_64)  GOARCH="amd64" ;;
    aarch64) GOARCH="arm64" ;;
    *)       GOARCH="amd64"; warn "Unknown arch ${ARCH}, defaulting to amd64" ;;
esac

# ─── Logging ──────────────────────────────────────────────────────────────────
LOGFILE="${OUTDIR}/macroscan.log"
exec > >(tee -a "${LOGFILE}") 2>&1
info "Logging to ${LOGFILE}"
info "Targets: ${TARGETS[*]}"
info "Date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"

# ═══════════════════════════════════════════════════════════════════════════════
#  PHASE 1 — Install tools
# ═══════════════════════════════════════════════════════════════════════════════
info "Phase 1: Checking and installing tools..."

# Helper: check if a command exists
have() { command -v "$1" &>/dev/null; }

# ── 1a. apt packages ─────────────────────────────────────────────────────────
APT_PACKAGES=(
    nmap                # Port scanning, service detection, NSE scripts
    snmp                # net-snmp: snmpwalk, snmpget, etc.
    snmp-mibs-downloader # MIB files for readable SNMP output
    masscan             # High-speed port scanner
    zmap                # Internet-scale single-port scanner
    tshark              # Packet capture and analysis (CLI Wireshark)
    arp-scan            # Layer-2 ARP discovery
    nbtscan             # Fast NetBIOS name scanner
    onesixtyone         # Fast SNMP community string brute-forcer
    nikto               # Web server vulnerability scanner
    curl                # HTTP client (for downloading binaries)
    wget                # HTTP client (fallback)
    jq                  # JSON processing
    xmlstarlet          # XML processing
    net-tools           # ifconfig, netstat, etc.
    iputils-ping        # ping
)

NEED_INSTALL=()
for pkg in "${APT_PACKAGES[@]}"; do
    if ! dpkg -s "${pkg}" &>/dev/null; then
        NEED_INSTALL+=("${pkg}")
    fi
done

if [[ ${#NEED_INSTALL[@]} -gt 0 ]]; then
    info "Installing ${#NEED_INSTALL[@]} apt package(s): ${NEED_INSTALL[*]}"
    apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "${NEED_INSTALL[@]}"
    ok "apt packages installed."
else
    ok "All apt packages already installed."
fi

# Enable non-free MIBs so snmpwalk output is human-readable
if [[ -f /etc/snmp/snmp.conf ]]; then
    sed -i 's/^mibs :$/# mibs :/' /etc/snmp/snmp.conf 2>/dev/null || true
fi

# ── 1b. Download nerva ───────────────────────────────────────────────────────
NERVA_BIN="${TOOLDIR}/nerva"
if [[ ! -x "${NERVA_BIN}" ]]; then
    info "Downloading nerva (network scanner by Praetorian)..."
    NERVA_URL="https://github.com/praetorian-inc/nerva/releases/latest/download/nerva-linux-${GOARCH}.tar.gz"
    if curl -fsSL "${NERVA_URL}" -o "${TOOLDIR}/nerva.tar.gz"; then
        tar -xzf "${TOOLDIR}/nerva.tar.gz" -C "${TOOLDIR}" 2>/dev/null || true
        # The binary might be at the top level or inside a directory
        find "${TOOLDIR}" -name "nerva" -type f -exec mv {} "${NERVA_BIN}" \; 2>/dev/null || true
        chmod +x "${NERVA_BIN}" 2>/dev/null || true
        rm -f "${TOOLDIR}/nerva.tar.gz"
        if [[ -x "${NERVA_BIN}" ]]; then
            ok "nerva installed."
        else
            warn "nerva download succeeded but binary not found; skipping."
        fi
    else
        warn "Failed to download nerva; skipping."
    fi
else
    ok "nerva already present."
fi

# ── 1c. Download brutus ──────────────────────────────────────────────────────
BRUTUS_BIN="${TOOLDIR}/brutus"
if [[ ! -x "${BRUTUS_BIN}" ]]; then
    info "Downloading brutus (credential scanner by Praetorian)..."
    BRUTUS_URL="https://github.com/praetorian-inc/brutus/releases/download/v1.3.0/brutus-linux-amd64.tar.gz"
    if curl -fsSL "${BRUTUS_URL}" -o "${TOOLDIR}/brutus.tar.gz"; then
        tar -xzf "${TOOLDIR}/brutus.tar.gz" -C "${TOOLDIR}" 2>/dev/null || true
        find "${TOOLDIR}" -name "brutus" -type f -exec mv {} "${BRUTUS_BIN}" \; 2>/dev/null || true
        chmod +x "${BRUTUS_BIN}" 2>/dev/null || true
        rm -f "${TOOLDIR}/brutus.tar.gz"
        if [[ -x "${BRUTUS_BIN}" ]]; then
            ok "brutus installed."
        else
            warn "brutus download succeeded but binary not found; skipping."
        fi
    else
        warn "Failed to download brutus; skipping."
    fi
else
    ok "brutus already present."
fi

# ── 1d. Build runZeroHound (in-repo tool) ────────────────────────────────────
RZHOUND_BIN="${TOOLDIR}/runZeroHound"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

if [[ -f "${REPO_ROOT}/go.mod" ]]; then
    if have go; then
        info "Building runZeroHound from source..."
        (cd "${REPO_ROOT}" && go build -o "${RZHOUND_BIN}" .) 2>&1 || warn "Failed to build runZeroHound; skipping."
        if [[ -x "${RZHOUND_BIN}" ]]; then
            ok "runZeroHound built."
        fi
    else
        warn "Go not installed; skipping runZeroHound build. Install with: apt-get install golang"
    fi
else
    warn "Not running from within runZeroHound repo; skipping build."
fi

# ═══════════════════════════════════════════════════════════════════════════════
#  PHASE 2 — Run all tools concurrently
# ═══════════════════════════════════════════════════════════════════════════════
info "Phase 2: Running scans concurrently..."
info "═══════════════════════════════════════════════════════════"

# Track background PIDs for the wait at the end
declare -A PIDS

# Helper: launch a background scan and track its PID
run_scan() {
    local name="$1"
    shift
    info "Starting: ${name}"
    "$@" &
    PIDS["${name}"]=$!
}

# ── 2a. Nmap — Full discovery scan (the gold standard for runZeroHound) ──────
#
# This follows the recommended command from docs/nmap-commands.md.
# Produces XML output that runZeroHound's convert command ingests directly.
for cidr in "${TARGETS[@]}"; do
    CIDR_SAFE=$(echo "${cidr}" | tr '/' '_')
    run_scan "nmap-${CIDR_SAFE}" \
        nmap -sS -sU \
            -p T:1-65535,U:53,67,123,161,162,500,623,1900,4500,5353 \
            -sV -O \
            --script ssh-hostkey,ssl-cert,smb2-security-mode,smb-os-discovery,snmp-info,snmp-sysdescr,snmp-interfaces,nbstat,banner \
            --script-args snmp.version=all \
            --traceroute --reason \
            --min-rate 1000 \
            -oX "${OUTDIR}/nmap-${CIDR_SAFE}.xml" \
            -oN "${OUTDIR}/nmap-${CIDR_SAFE}.txt" \
            "${cidr}"
done

# ── 2b. Masscan — High-speed port discovery ─────────────────────────────────
#
# Masscan is much faster than nmap for initial port discovery on large
# networks.  The XML output is importable by runZeroHound.
for cidr in "${TARGETS[@]}"; do
    CIDR_SAFE=$(echo "${cidr}" | tr '/' '_')
    run_scan "masscan-${CIDR_SAFE}" \
        masscan "${cidr}" \
            -p 1-65535 \
            --rate 10000 \
            --banners \
            -oX "${OUTDIR}/masscan-${CIDR_SAFE}.xml" \
            --output-format xml
done

# ── 2c. ZMap — Single-port, full-speed sweep ────────────────────────────────
#
# ZMap is optimized for scanning a single port across a large address space.
# We target common ports that reveal identity data.
ZMAP_PORTS=(22 80 443 445 161 3389 8080 8443)
for port in "${ZMAP_PORTS[@]}"; do
    run_scan "zmap-port-${port}" \
        bash -c "zmap -p '${port}' --bandwidth=10M -o '${OUTDIR}/zmap-port-${port}.csv' '${PRIMARY_TARGET}' 2>&1 || true"
done

# ── 2d. ARP scan — Layer-2 MAC address discovery ────────────────────────────
#
# Only works on the local subnet. Discovers MAC addresses and vendors.
for cidr in "${TARGETS[@]}"; do
    CIDR_SAFE=$(echo "${cidr}" | tr '/' '_')
    run_scan "arp-scan-${CIDR_SAFE}" \
        bash -c "arp-scan --ignoredups '${cidr}' > '${OUTDIR}/arp-scan-${CIDR_SAFE}.txt' 2>&1 || true"
done

# ── 2e. nbtscan — Fast NetBIOS name resolution ──────────────────────────────
for cidr in "${TARGETS[@]}"; do
    CIDR_SAFE=$(echo "${cidr}" | tr '/' '_')
    run_scan "nbtscan-${CIDR_SAFE}" \
        bash -c "nbtscan -v -s '	' '${cidr}' > '${OUTDIR}/nbtscan-${CIDR_SAFE}.txt' 2>&1"
done

# ── 2f. onesixtyone — SNMP community string scanner ─────────────────────────
#
# Discovers SNMP-enabled devices and the community strings they accept.
# The output feeds into snmpwalk for deeper enumeration.
for cidr in "${TARGETS[@]}"; do
    CIDR_SAFE=$(echo "${cidr}" | tr '/' '_')
    run_scan "onesixtyone-${CIDR_SAFE}" \
        bash -c "onesixtyone -c <(echo -e 'public\nprivate\ncommunity\nmanager\nmonitor') '${cidr}' > '${OUTDIR}/onesixtyone-${CIDR_SAFE}.txt' 2>&1"
done

# ── 2g. snmpwalk — SNMP enumeration for found devices ───────────────────────
#
# We can't enumerate all IPs; we'll do a quick snmpbulkwalk on the primary
# target to demonstrate the output format.  In practice you'd feed in the
# list of SNMP-responsive hosts from onesixtyone.
run_scan "snmpwalk" \
    bash -c "
        # Try SNMPv2c bulk walk first (much faster), fall back to v1
        for host in \$(nmap -sn -n '${PRIMARY_TARGET}' -oG - 2>/dev/null | awk '/Up\$/{print \$2}' | head -20); do
            echo '# Target: \${host}' >> '${OUTDIR}/snmpwalk.txt'
            snmpbulkwalk -v2c -c public -OQn \"\${host}\" .1 >> '${OUTDIR}/snmpwalk.txt' 2>/dev/null || \
            snmpwalk -v1 -c public -OQn \"\${host}\" .1 >> '${OUTDIR}/snmpwalk.txt' 2>/dev/null || true
        done
    "

# ── 2h. tshark — Passive network capture ────────────────────────────────────
#
# Runs a 60-second packet capture to discover broadcast/multicast traffic,
# ARP, DHCP, mDNS, SSDP, LLMNR, and other passive network data.
CAPTURE_IFACE=$(ip route get 8.8.8.8 2>/dev/null | awk '{for(i=1;i<=NF;i++) if ($i=="dev") print $(i+1)}' | head -1)
if [[ -n "${CAPTURE_IFACE:-}" ]]; then
    run_scan "tshark" \
        bash -c "
            timeout 60 tshark -i '${CAPTURE_IFACE}' \
                -f 'arp or udp port 5353 or udp port 1900 or udp port 5355 or udp port 67 or udp port 137' \
                -w '${OUTDIR}/tshark-passive.pcap' \
                -a duration:60 2>/dev/null
            # Also export a human-readable summary
            tshark -r '${OUTDIR}/tshark-passive.pcap' \
                -T fields -e frame.time -e eth.src -e eth.dst -e ip.src -e ip.dst -e _ws.col.Protocol -e _ws.col.Info \
                > '${OUTDIR}/tshark-passive.txt' 2>/dev/null || true
        "
else
    warn "Could not determine default network interface; skipping tshark capture."
fi

# ── 2i. nerva — Network vulnerability scanner ────────────────────────────────
if [[ -x "${NERVA_BIN}" ]]; then
    for cidr in "${TARGETS[@]}"; do
        CIDR_SAFE=$(echo "${cidr}" | tr '/' '_')
        run_scan "nerva-${CIDR_SAFE}" \
            bash -c "'${NERVA_BIN}' scan -t '${cidr}' -o '${OUTDIR}/nerva-${CIDR_SAFE}.json' 2>&1 || true"
    done
else
    warn "nerva not available; skipping."
fi

# ── 2j. brutus — Credential scanner ─────────────────────────────────────────
if [[ -x "${BRUTUS_BIN}" ]]; then
    for cidr in "${TARGETS[@]}"; do
        CIDR_SAFE=$(echo "${cidr}" | tr '/' '_')
        run_scan "brutus-${CIDR_SAFE}" \
            bash -c "'${BRUTUS_BIN}' -t '${cidr}' -o '${OUTDIR}/brutus-${CIDR_SAFE}.json' 2>&1 || true"
    done
else
    warn "brutus not available; skipping."
fi

# ── 2k. runZeroHound nextnet — Multi-homed host / pivot discovery ────────────
if [[ -x "${RZHOUND_BIN}" ]]; then
    for cidr in "${TARGETS[@]}"; do
        CIDR_SAFE=$(echo "${cidr}" | tr '/' '_')
        run_scan "nextnet-${CIDR_SAFE}" \
            "${RZHOUND_BIN}" nextnet \
                --rate 1000 \
                --output "${OUTDIR}/nextnet-${CIDR_SAFE}.nxt" \
                "${cidr}"
    done
else
    warn "runZeroHound not built; skipping nextnet scan."
fi

# ── 2l. nikto — Web server vulnerability scan ────────────────────────────────
#
# Nikto is slow, so we only scan hosts with HTTP/HTTPS from the nmap scan.
# Since nmap is running concurrently, we start nikto after a brief delay
# and parse whatever partial results are available.
run_scan "nikto" \
    bash -c "
        sleep 30  # Give nmap a head start
        # Find hosts with HTTP from any available nmap results
        WEB_HOSTS=()
        for xml in '${OUTDIR}'/nmap-*.xml; do
            [ -f \"\${xml}\" ] || continue
            WEB_HOSTS+=(\$(xmlstarlet sel -t -m '//port[state/@state=\"open\" and (service/@name=\"http\" or service/@name=\"https\" or @portid=\"80\" or @portid=\"443\" or @portid=\"8080\" or @portid=\"8443\")]/../address[@addrtype=\"ipv4\"]' -v '@addr' -n \"\${xml}\" 2>/dev/null | sort -u | head -10))
        done
        for host in \"\${WEB_HOSTS[@]}\"; do
            [[ -z \"\${host}\" ]] && continue
            nikto -h \"\${host}\" -output '${OUTDIR}/nikto-\${host}.txt' -Format txt 2>/dev/null || true
        done
    "

# ═══════════════════════════════════════════════════════════════════════════════
#  PHASE 3 — Wait for all scans and report
# ═══════════════════════════════════════════════════════════════════════════════
info "Phase 3: Waiting for all scans to complete..."
info "═══════════════════════════════════════════════════════════"

FAILED=0
for name in "${!PIDS[@]}"; do
    pid=${PIDS[$name]}
    if wait "${pid}" 2>/dev/null; then
        ok "Completed: ${name} (PID ${pid})"
    else
        warn "Failed or partial: ${name} (PID ${pid}, exit $?)"
        ((FAILED++)) || true
    fi
done

# ═══════════════════════════════════════════════════════════════════════════════
#  PHASE 4 — Post-processing & runZeroHound import
# ═══════════════════════════════════════════════════════════════════════════════
info "Phase 4: Post-processing..."

# Generate a summary of all output files
{
    echo "# macroscan summary — ${DATE_TAG}"
    echo "# Targets: ${TARGETS[*]}"
    echo "# Date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "#"
    echo "# Output files:"
    for f in "${OUTDIR}"/*; do
        [[ -d "$f" ]] && continue
        echo "#   $(basename "$f")  $(du -h "$f" | cut -f1)"
    done
} > "${OUTDIR}/SUMMARY.txt"

# If runZeroHound is available, auto-convert everything into an OpenGraph file
if [[ -x "${RZHOUND_BIN}" ]]; then
    info "Generating runZeroHound OpenGraph from all scan data..."
    CONVERT_INPUTS=()
    # Add all nmap XML files
    for f in "${OUTDIR}"/nmap-*.xml; do [[ -f "$f" ]] && CONVERT_INPUTS+=("$f"); done
    # Add all masscan XML files
    for f in "${OUTDIR}"/masscan-*.xml; do [[ -f "$f" ]] && CONVERT_INPUTS+=("$f"); done
    # Add all nextnet .nxt files
    for f in "${OUTDIR}"/nextnet-*.nxt; do [[ -f "$f" ]] && CONVERT_INPUTS+=("$f"); done
    # Add snmpwalk output
    [[ -f "${OUTDIR}/snmpwalk.txt" ]] && CONVERT_INPUTS+=("${OUTDIR}/snmpwalk.txt")

    if [[ ${#CONVERT_INPUTS[@]} -gt 0 ]]; then
        "${RZHOUND_BIN}" convert \
            --output "${OUTDIR}/opengraph-${DATE_TAG}.json" \
            "${CONVERT_INPUTS[@]}" 2>&1 || warn "runZeroHound convert failed."
        if [[ -f "${OUTDIR}/opengraph-${DATE_TAG}.json" ]]; then
            ok "OpenGraph file: ${OUTDIR}/opengraph-${DATE_TAG}.json"
        fi
    else
        warn "No importable scan files found for runZeroHound convert."
    fi
fi

# ═══════════════════════════════════════════════════════════════════════════════
#  Done
# ═══════════════════════════════════════════════════════════════════════════════
echo ""
info "═══════════════════════════════════════════════════════════"
ok "macroscan complete!"
info "Results directory: ${OUTDIR}"
info "Total files: $(find "${OUTDIR}" -type f | wc -l)"
info "Total size: $(du -sh "${OUTDIR}" | cut -f1)"
if [[ ${FAILED} -gt 0 ]]; then
    warn "${FAILED} scan(s) reported errors — check ${LOGFILE} for details."
fi
echo ""
info "To import into BloodHound via runZeroHound:"
echo "  runZeroHound convert --output graph.json ${OUTDIR}/nmap-*.xml ${OUTDIR}/nextnet-*.nxt"
echo ""
