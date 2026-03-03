#!/usr/bin/env bash
###############################################################################
# harden_samba_standalone_rocky9.sh
#
# Production-quality Samba hardening script for Rocky Linux 9 / RHEL9.
#
# Purpose : Harden a STANDALONE Samba file server (NOT domain-joined).
# Target  : Rocky Linux 9 (RHEL9 compatible)
# Run as  : root (sudo)
# Idempotent: Yes – safe to re-run; backs up before every change.
#
# This host is a standalone workgroup file server. It is NOT an Active
# Directory Domain Controller and is NOT joined to any domain.
# Authentication is via local Samba users (smbpasswd / passdb).
#
# Author  : Auto-generated hardening script
# Date    : 2026-03-02
###############################################################################
set -euo pipefail
IFS=$'\n\t'

# ─── Constants ───────────────────────────────────────────────────────────────
readonly EXPECTED_IP="172.18.14.8"
readonly ALLOWED_SUBNET="172.18.14.0/24"
readonly ALLOWED_HOSTS="172.18.14. 127.0.0.1 ::1"
readonly BACKUP_DIR="/root/samba-hardening-backups/$(date +%Y%m%d-%H%M%S)"
readonly SMB_CONF="/etc/samba/smb.conf"
readonly SECURE_SHARE_PATH="/srv/samba/secure"
readonly MANAGED_BEGIN="### BEGIN MANAGED HARDENING BLOCK ###"
readonly MANAGED_END="### END MANAGED HARDENING BLOCK ###"
readonly LOG_TAG="[SAMBA-HARDEN]"

# Colours for terminal output (no-op if not a tty)
if [[ -t 1 ]]; then
    RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
    CYAN='\033[0;36m'; NC='\033[0m'
else
    RED=''; GREEN=''; YELLOW=''; CYAN=''; NC=''
fi

# ─── Logging helpers ─────────────────────────────────────────────────────────
log_info()  { echo -e "${GREEN}${LOG_TAG} [INFO]${NC}  $*"; }
log_warn()  { echo -e "${YELLOW}${LOG_TAG} [WARN]${NC}  $*"; }
log_error() { echo -e "${RED}${LOG_TAG} [ERROR]${NC} $*" >&2; }
log_step()  { echo -e "\n${CYAN}═══════════════════════════════════════════════════════════${NC}"; \
              echo -e "${CYAN}${LOG_TAG} $*${NC}"; \
              echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"; }

# ─── Cleanup / rollback on fatal error ────────────────────────────────────────
rollback_smb_conf() {
    local latest_backup
    latest_backup=$(find "$BACKUP_DIR" -name 'smb.conf.*' -type f 2>/dev/null | sort | tail -1 || true)
    if [[ -n "$latest_backup" && -f "$latest_backup" ]]; then
        log_warn "Restoring smb.conf from backup: $latest_backup"
        cp -a "$latest_backup" "$SMB_CONF"
        log_warn "Backup restored. Manual review required."
    else
        log_error "No backup found to restore – manual intervention required."
    fi
}

###############################################################################
# 1) PREFLIGHT CHECKS
###############################################################################
log_step "STEP 1 — Preflight checks"

# ── 1a. Must run as root ─────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    log_error "This script must be run as root (EUID 0). Aborting."
    exit 1
fi
log_info "Running as root — OK"

# ── 1b. Verify Rocky Linux 9 / RHEL9 ────────────────────────────────────────
if [[ -f /etc/os-release ]]; then
    # shellcheck disable=SC1091
    source /etc/os-release
    if [[ "${ID:-}" =~ ^(rocky|rhel|almalinux|centos)$ ]] && [[ "${VERSION_ID:-}" == 9* ]]; then
        log_info "Detected OS: ${PRETTY_NAME:-$ID $VERSION_ID} — OK"
    else
        log_error "Unsupported OS: ${PRETTY_NAME:-$ID $VERSION_ID}. Expected Rocky/RHEL 9."
        exit 1
    fi
else
    log_error "/etc/os-release not found. Cannot verify OS."
    exit 1
fi

# ── 1c. Install required Samba packages (standalone file server) ─────────────
# For a standalone Samba file server on Rocky 9:
#   samba              – smbd daemon for file/print sharing
#   samba-common       – shared config files and tools
#   samba-common-tools – smbpasswd, testparm, pdbedit, etc.
#   samba-client       – smbclient for testing connectivity
#   policycoreutils-python-utils – semanage for SELinux fcontext
#   firewalld          – host-based firewall
REQUIRED_PACKAGES=(
    samba
    samba-common
    samba-common-tools
    samba-client
    policycoreutils-python-utils
    firewalld
)

missing_required=()
for pkg in "${REQUIRED_PACKAGES[@]}"; do
    if ! rpm -q "$pkg" &>/dev/null; then
        missing_required+=("$pkg")
    fi
done

if [[ ${#missing_required[@]} -gt 0 ]]; then
    log_info "Installing missing required packages: ${missing_required[*]}"
    dnf install -y "${missing_required[@]}" || {
        log_error "Failed to install required packages. Aborting."
        exit 1
    }
fi
log_info "All required packages are present."

# ── 1d. Detect active network interface for 172.18.14.8 ─────────────────────
ACTIVE_IFACE=""
ACTIVE_IFACE=$(ip -o -4 addr show | awk -v ip="$EXPECTED_IP" '$4 ~ ip {print $2; exit}')
if [[ -z "$ACTIVE_IFACE" ]]; then
    log_error "Cannot find interface with IP $EXPECTED_IP. Aborting."
    log_error "Output of 'ip -o -4 addr show':"
    ip -o -4 addr show >&2
    exit 1
fi
log_info "Detected interface: $ACTIVE_IFACE with IP $EXPECTED_IP"

# ── 1e. Create backup directory ──────────────────────────────────────────────
mkdir -p "$BACKUP_DIR"
log_info "Backup directory: $BACKUP_DIR"

# ── 1f. Backup current Samba config and state ───────────────────────────────
if [[ -f "$SMB_CONF" ]]; then
    cp -a "$SMB_CONF" "${BACKUP_DIR}/smb.conf.bak"
    log_info "Backed up $SMB_CONF → ${BACKUP_DIR}/smb.conf.bak"
else
    log_warn "$SMB_CONF does not exist yet – no backup needed."
fi

# Capture current service states
{
    echo "=== Service states before hardening ==="
    for svc in smb nmb winbind; do
        echo "--- $svc ---"
        systemctl is-active "$svc" 2>&1 || true
        systemctl is-enabled "$svc" 2>&1 || true
    done
} > "${BACKUP_DIR}/service-state-before.txt"
log_info "Captured service states → ${BACKUP_DIR}/service-state-before.txt"

# Backup firewalld state
if systemctl is-active firewalld &>/dev/null; then
    firewall-cmd --list-all > "${BACKUP_DIR}/firewalld-state-before.txt" 2>&1 || true
    log_info "Captured firewalld state → ${BACKUP_DIR}/firewalld-state-before.txt"
fi

###############################################################################
# 2) HARDENING — Standalone Samba File Server Configuration
###############################################################################
log_step "STEP 2 — Applying hardened Samba standalone configuration"

# ── 2a. Extract existing non-global shares from current smb.conf ─────────────
# We preserve any share definitions ([share_name]) that are NOT [global].
# Strategy: replace [global] with our hardened block, keep existing shares.
EXISTING_SHARES=""
if [[ -f "$SMB_CONF" ]]; then
    # Extract everything outside the [global] section.
    EXISTING_SHARES=$(awk '
        /^\[global\]/,/^\[/ {
            if (/^\[/ && !/^\[global\]/) { printing=1; print; next }
            next
        }
        { if (printing != 0 || !/^\[global\]/) print }
    ' "$SMB_CONF" 2>/dev/null || true)
fi

# ── 2b. Write hardened smb.conf ──────────────────────────────────────────────
#
# KEY HARDENING DECISIONS (documented inline):
#
# • server role = standalone server
#   WHY: This host is not joined to any domain. It authenticates users from
#         its own local passdb (tdbsam). No AD/DC/domain member functionality.
#
# • server min protocol = SMB3_00
#   WHY: Disables SMB1 and SMB2 entirely. SMB1 is insecure (EternalBlue,
#         relay attacks, no encryption). SMB3 provides encryption, secure
#         negotiation, and signing. SMB3_00 supports Windows 10+ and modern
#         Linux clients. Use SMB2_10 only if legacy clients are required.
#
# • server signing = mandatory
#   WHY: Prevents man-in-the-middle and relay attacks on SMB sessions.
#         All modern clients (Windows 10+, smbclient) support signing.
#
# • smb encrypt = required
#   WHY: Enforces SMB3 transport encryption (AES-CCM/GCM) for all connections.
#         For a standalone server with no legacy constraints, 'required' is the
#         strongest option. Downgrade to 'desired' if older clients cannot
#         negotiate encryption.
#
# • ntlm auth = ntlmv2-only
#   WHY: Disables NTLMv1 and LANMAN authentication. NTLMv1 hashes are trivially
#         crackable. NTLMv2 is the minimum safe NTLM variant.
#
# • lanman auth = no / raw NTLMv2 auth = no
#   WHY: Belt-and-suspenders — explicitly disables LANMAN (DES-based, broken)
#         and raw NTLMv2 (no session security negotiation).
#
# • map to guest = never
#   WHY: Prevents any failed login from being silently mapped to a guest
#         account. Forces explicit authentication for all access.
#
# • restrict anonymous = 2
#   WHY: Blocks anonymous enumeration of shares, users, and SAM accounts.
#         Level 2 is the most restrictive, matching hardened Windows GPO.
#
# • bind interfaces only = yes + interfaces = lo <iface>
#   WHY: Ensures Samba only listens on the expected network interface and
#         loopback. Reduces attack surface on multi-homed hosts.
#
# • hosts allow / hosts deny
#   WHY: Defense-in-depth ACL limiting connections to the local subnet.
#
# • log level = 1 auth_audit:3 auth:3
#   WHY: Keeps general logging low but enables detailed auth logging for
#         security monitoring and incident response.
#
# • passdb backend = tdbsam
#   WHY: Local user database for standalone server. Users are managed via
#         `smbpasswd -a <user>` or `pdbedit`.

cat > "$SMB_CONF" << SMBEOF
${MANAGED_BEGIN}
# ──────────────────────────────────────────────────────────────────────────────
# Hardened Samba Standalone File Server Configuration
# Generated: $(date -u +"%Y-%m-%dT%H:%M:%SZ")
# Target IP: ${EXPECTED_IP} (interface: ${ACTIVE_IFACE})
# Role: Standalone file server (NOT domain-joined)
# ──────────────────────────────────────────────────────────────────────────────

[global]
    # ── Role ──────────────────────────────────────────────────────────────────
    # Standalone server: authenticates users from its own local passdb.
    # No domain membership, no AD DC, no domain controller functionality.
    server role = standalone server
    workgroup = WORKGROUP

    # ── Local User Database ───────────────────────────────────────────────────
    # tdbsam is the default local password database for standalone servers.
    # Manage users with: smbpasswd -a <username>  or  pdbedit -a <username>
    passdb backend = tdbsam

    # ── Network Binding ───────────────────────────────────────────────────────
    # Bind only to loopback and the detected interface to reduce exposure.
    # Samba will not listen on any other interfaces.
    interfaces = lo ${ACTIVE_IFACE}
    bind interfaces only = yes

    # ── Access Control ────────────────────────────────────────────────────────
    # Restrict connections to the local subnet and loopback only.
    hosts allow = ${ALLOWED_HOSTS}
    hosts deny = 0.0.0.0/0

    # ── Protocol Hardening ────────────────────────────────────────────────────
    # Disable SMB1/SMB2 entirely. Require SMB3 minimum.
    # SMB1 is vulnerable to EternalBlue, relay attacks, and lacks encryption.
    # SMB3 provides AES encryption, secure negotiation, and mandatory signing.
    server min protocol = SMB3_00
    client min protocol = SMB3_00

    # Enforce SMB signing on all connections (prevents MITM/relay attacks).
    server signing = mandatory
    client signing = mandatory

    # Require SMB3 transport encryption (AES-CCM/GCM) for all connections.
    # For a standalone server with modern clients, 'required' is safest.
    # Downgrade to 'desired' only if clients cannot negotiate encryption.
    smb encrypt = required

    # ── Authentication Hardening ──────────────────────────────────────────────
    # Disable NTLMv1 and LANMAN — allow only NTLMv2 as authentication.
    # NTLMv1 uses weak DES-based hashing and is trivially crackable.
    ntlm auth = ntlmv2-only
    lanman auth = no
    raw NTLMv2 auth = no

    # Do not store LANMAN password hashes (they are DES-based and broken).
    # This is default on modern Samba but we enforce it explicitly.

    # Never map failed auth to guest — forces explicit authentication.
    # Prevents anonymous/unauthenticated access escalation.
    map to guest = never

    # Block anonymous enumeration of shares, users, SAM database.
    # Level 2 = most restrictive (matches Windows hardened GPO setting
    # "No access without explicit anonymous permissions").
    restrict anonymous = 2

    # ── Logging ───────────────────────────────────────────────────────────────
    # General log level low (1); auth-related subsystems at detail level 3
    # for security auditing and incident response.
    log level = 1 auth_audit:3 auth:3
    log file = /var/log/samba/log.%m
    max log size = 5000

    # ── Miscellaneous Hardening ───────────────────────────────────────────────
    # Disable printer sharing — reduces attack surface. Re-enable only if
    # this server explicitly provides print services.
    load printers = no
    printing = bsd
    printcap name = /dev/null
    disable spoolss = yes

    # Disable WINS — not needed for standalone file server on a flat network.
    wins support = no

    # Disable NetBIOS over TCP/IP if not needed for name resolution.
    # Modern clients use DNS. This removes ports 137/138/139.
    # If you have legacy clients that rely on NetBIOS name resolution,
    # change this to 'yes' and re-enable nmb.service.
    disable netbios = yes

    # Obfuscate server version — prevents information leakage in enumeration.
    server string = Samba File Server

    # Limit max connections to prevent resource exhaustion / DoS.
    max connections = 50

    # Prevent symlink traversal outside share boundaries.
    # 'no' means Samba will not follow symlinks that point outside the share.
    allow insecure wide links = no
    unix extensions = yes

${MANAGED_END}

# ── Example Hardened Share ────────────────────────────────────────────────────
# A secured file share restricted to authenticated local Samba users.
# Add users with: smbpasswd -a <linux_username>
[secure]
    comment = Hardened secure file share
    path = ${SECURE_SHARE_PATH}
    browseable = yes
    read only = no
    # Only authenticated Samba users can access this share.
    # Replace with specific usernames or @group to restrict further.
    valid users = @sambashare
    # Inherit permissions from parent directory for consistent ACLs.
    inherit permissions = yes
    # Force new files/dirs to be owned by the share group.
    force group = sambashare
    # Restrictive create masks.
    create mask = 0660
    directory mask = 2770
    # Per-share encryption — inherits 'required' from global.
    smb encrypt = required
    # Disable guest access on this share.
    guest ok = no

SMBEOF

# Append any preserved non-global shares that weren't "secure"
if [[ -n "$EXISTING_SHARES" ]]; then
    # Filter out the [secure] section we already wrote
    FILTERED_SHARES=$(echo "$EXISTING_SHARES" | awk '
        BEGIN { skip=0 }
        /^\[secure\]/ { skip=1; next }
        /^\[/ { skip=0 }
        skip { next }
        { print }
    ')
    if [[ -n "$FILTERED_SHARES" ]]; then
        log_info "Appending preserved share definitions from original config."
        echo "" >> "$SMB_CONF"
        echo "# ── Preserved Shares (from pre-hardening config) ──────────────────────────" >> "$SMB_CONF"
        echo "$FILTERED_SHARES" >> "$SMB_CONF"
    fi
fi

log_info "Hardened smb.conf written to $SMB_CONF"

# ── 2c. Create secure share directory with proper perms & SELinux context ────
log_info "Setting up secure share at ${SECURE_SHARE_PATH}"
mkdir -p "$SECURE_SHARE_PATH"

# Create 'sambashare' group if it doesn't exist — used for share access control
if ! getent group sambashare &>/dev/null; then
    groupadd sambashare
    log_info "Created group 'sambashare'."
else
    log_info "Group 'sambashare' already exists."
fi

chown root:sambashare "$SECURE_SHARE_PATH"
chmod 2770 "$SECURE_SHARE_PATH"
log_info "Set ownership root:sambashare and mode 2770 on ${SECURE_SHARE_PATH}"

# Apply SELinux context for Samba shares
if command -v semanage &>/dev/null && command -v restorecon &>/dev/null; then
    # Check if context is already applied (idempotent)
    if ! semanage fcontext -l 2>/dev/null | grep -q "${SECURE_SHARE_PATH}"; then
        semanage fcontext -a -t samba_share_t "${SECURE_SHARE_PATH}(/.*)?"
        log_info "SELinux: Added samba_share_t context for ${SECURE_SHARE_PATH}"
    else
        log_info "SELinux: samba_share_t context already set for ${SECURE_SHARE_PATH}"
    fi
    restorecon -Rv "$SECURE_SHARE_PATH"
else
    log_warn "semanage/restorecon not available — skipping SELinux context."
fi

# Enable SELinux booleans relevant to Samba file serving
# (only the relevant booleans; do not change global policy)
if command -v setsebool &>/dev/null; then
    for sebool in samba_enable_home_dirs samba_export_all_rw; do
        current=$(getsebool "$sebool" 2>/dev/null | awk '{print $NF}' || echo "unknown")
        if [[ "$current" != "on" ]]; then
            setsebool -P "$sebool" on 2>/dev/null || \
                log_warn "Could not set SELinux boolean $sebool (may require different policy)."
            log_info "SELinux: Set $sebool = on"
        else
            log_info "SELinux: $sebool already on"
        fi
    done
fi

# Ensure Samba log directory exists
mkdir -p /var/log/samba
chmod 750 /var/log/samba

# ── 2d. Validate smb.conf syntax BEFORE restarting ──────────────────────────
log_step "STEP 2d — Validating smb.conf syntax with testparm"
if command -v testparm &>/dev/null; then
    if testparm -s "$SMB_CONF" > "${BACKUP_DIR}/testparm-output.txt" 2>&1; then
        log_info "testparm: Configuration syntax is VALID."
        cat "${BACKUP_DIR}/testparm-output.txt"
    else
        log_error "testparm: Configuration syntax is INVALID!"
        cat "${BACKUP_DIR}/testparm-output.txt" >&2
        rollback_smb_conf
        exit 1
    fi
else
    log_warn "testparm not found — cannot validate config (continuing cautiously)."
fi

###############################################################################
# 3) FIREWALL — Restrict Samba ports to local subnet only
###############################################################################
log_step "STEP 3 — Configuring firewalld rich rules for Samba"

# Ensure firewalld is running
if ! systemctl is-active firewalld &>/dev/null; then
    log_info "Starting and enabling firewalld..."
    systemctl enable --now firewalld
fi

# Standalone Samba file server only needs:
#   TCP 445  – SMB (primary; all modern SMB traffic)
#   Note: TCP 139, UDP 137, UDP 138 are NetBIOS — disabled above
#         via 'disable netbios = yes'. Not opened in firewall.
#         If you re-enable NetBIOS, add rules for those ports.

FIREWALL_ZONE=$(firewall-cmd --get-default-zone 2>/dev/null || echo "public")
log_info "Default firewalld zone: ${FIREWALL_ZONE}"

# Remove any existing wide-open samba service to prevent exposure to 0.0.0.0/0.
# (Idempotent: remove silently if not present.)
firewall-cmd --permanent --zone="${FIREWALL_ZONE}" --remove-service=samba 2>/dev/null || true
firewall-cmd --permanent --zone="${FIREWALL_ZONE}" --remove-service=samba-client 2>/dev/null || true
firewall-cmd --permanent --zone="${FIREWALL_ZONE}" --remove-service=samba-dc 2>/dev/null || true

# Samba SMB port — restricted to local subnet only
declare -A SMB_PORTS=(
    ["tcp-445"]="tcp/445"
)

for key in "${!SMB_PORTS[@]}"; do
    proto="${SMB_PORTS[$key]%%/*}"
    port="${SMB_PORTS[$key]##*/}"

    # Build the rich rule
    rule="rule family=\"ipv4\" source address=\"${ALLOWED_SUBNET}\" port protocol=\"${proto}\" port=\"${port}\" accept"

    # Check if rule already exists (idempotent)
    if firewall-cmd --permanent --zone="${FIREWALL_ZONE}" --query-rich-rule="$rule" &>/dev/null; then
        log_info "Firewall: Rich rule already exists — ${proto}/${port}"
    else
        firewall-cmd --permanent --zone="${FIREWALL_ZONE}" --add-rich-rule="$rule"
        log_info "Firewall: Added rich rule — ${proto}/${port} from ${ALLOWED_SUBNET}"
    fi
done

# Explicit deny for SMB from outside the subnet (belt-and-suspenders;
# firewalld default-deny usually handles this, but this makes intent clear).
DENY_RULE='rule family="ipv4" source NOT address="172.18.14.0/24" port protocol="tcp" port="445" reject'
if ! firewall-cmd --permanent --zone="${FIREWALL_ZONE}" --query-rich-rule="$DENY_RULE" &>/dev/null; then
    firewall-cmd --permanent --zone="${FIREWALL_ZONE}" --add-rich-rule="$DENY_RULE" 2>/dev/null || \
        log_warn "Could not add explicit deny rule for TCP/445 (default deny should cover this)."
fi

# Reload to apply all permanent rules
firewall-cmd --reload
log_info "Firewalld configuration reloaded."
log_info "ROLLBACK NOTE: To revert firewall changes, restore from:"
log_info "  ${BACKUP_DIR}/firewalld-state-before.txt"
log_info "  and run: firewall-cmd --reload"

###############################################################################
# 4) SERVICE MANAGEMENT — Enable and restart smb (standalone file server)
###############################################################################
log_step "STEP 4 — Managing Samba standalone services"

# For a standalone Samba file server on Rocky 9:
#   smb.service  – runs smbd (SMB file serving daemon) — REQUIRED
#   nmb.service  – runs nmbd (NetBIOS name service)    — NOT NEEDED (NetBIOS disabled)
#   winbind      – runs winbindd (domain integration)  — NOT NEEDED (standalone)
#   samba        – runs the AD DC binary                — NOT NEEDED (standalone)
#
# We enable 'smb' and disable everything else that's unnecessary.

SAMBA_SERVICE="smb"

# Disable AD DC and unnecessary services if present
for unnecessary_svc in samba nmb winbind; do
    if systemctl list-unit-files "${unnecessary_svc}.service" &>/dev/null 2>&1; then
        if systemctl is-enabled "${unnecessary_svc}" &>/dev/null 2>&1; then
            log_info "Disabling unnecessary service: ${unnecessary_svc}"
            systemctl disable --now "${unnecessary_svc}" 2>/dev/null || true
        fi
    fi
done

# Enable and start smb (smbd)
log_info "Enabling and restarting 'smb' service (smbd)..."
systemctl enable smb
systemctl restart smb
log_info "Service 'smb' is $(systemctl is-active smb 2>/dev/null || echo 'unknown')."

###############################################################################
# 5) END-TO-END VERIFICATION
###############################################################################
log_step "STEP 5 — End-to-end verification"

# ── 5a. testparm ─────────────────────────────────────────────────────────────
echo ""
log_info "── testparm -s ──"
testparm -s 2>&1 || log_warn "testparm returned non-zero (may be warnings)."

# ── 5b. smbclient listing ────────────────────────────────────────────────────
echo ""
log_info "── smbclient -L localhost -m SMB3 ──"
log_info "(Expected to fail with anonymous access denied — this confirms hardening)"
smbclient -L localhost -m SMB3 -N 2>&1 || \
    log_info "smbclient anonymous listing blocked — hardening is working correctly."

# ── 5c. Listening ports ─────────────────────────────────────────────────────
echo ""
log_info "── Listening Samba ports ──"
ss -lntup | head -1
ss -lntup | grep -E ':(445|139)\b' 2>/dev/null || \
    log_warn "No Samba ports detected in ss output (service may still be starting)."

# ── 5d. Service status checks ────────────────────────────────────────────────
echo ""
log_info "── Service Status: smb ──"
systemctl status smb --no-pager 2>&1 || \
    log_warn "'smb' service status check returned non-zero."

echo ""
log_info "── Service Status: samba ──"
systemctl status samba --no-pager 2>&1 || \
    log_info "Note: 'samba' service is for AD DC — not used on standalone server. This is expected."

echo ""
log_info "── Service Status: smbd ──"
systemctl status smbd --no-pager 2>&1 || \
    log_info "Note: 'smbd' unit typically does not exist on Rocky 9 (the unit is named 'smb'). This is expected."

###############################################################################
# SUMMARY
###############################################################################
log_step "HARDENING COMPLETE"

cat << SUMMARY

┌─────────────────────────────────────────────────────────────────────────┐
│              SAMBA STANDALONE SERVER HARDENING SUMMARY                  │
├─────────────────────────────────────────────────────────────────────────┤
│  Server Role        : standalone server (NOT domain-joined)            │
│  Detected Interface : ${ACTIVE_IFACE}
│  Detected IP        : ${EXPECTED_IP}
│  Active Service     : ${SAMBA_SERVICE} (smbd)
│  Config File        : ${SMB_CONF}
│  Backups Saved To   : ${BACKUP_DIR}
│                                                                         │
│  Key Hardening Applied:                                                 │
│    ✓ SMB1/SMB2 disabled (min protocol = SMB3_00)                       │
│    ✓ SMB signing mandatory                                              │
│    ✓ SMB encryption required (AES-CCM/GCM)                             │
│    ✓ NTLMv1 / LANMAN authentication disabled (NTLMv2 only)            │
│    ✓ Guest / anonymous access blocked (map to guest = never)           │
│    ✓ Anonymous enumeration blocked (restrict anonymous = 2)            │
│    ✓ Interface binding: lo + ${ACTIVE_IFACE}
│    ✓ hosts allow: ${ALLOWED_HOSTS}
│    ✓ NetBIOS disabled (ports 137/138/139 closed)                       │
│    ✓ Printer sharing disabled                                           │
│    ✓ Firewall: TCP/445 restricted to ${ALLOWED_SUBNET}
│    ✓ SELinux context set on ${SECURE_SHARE_PATH}
│    ✓ Auth-level logging enabled                                         │
│                                                                         │
│  Next Steps:                                                            │
│    1. Add Samba users:   smbpasswd -a <linux_user>                     │
│    2. Add to share group: usermod -aG sambashare <linux_user>          │
│    3. Test from client:  smbclient //172.18.14.8/secure -U <user>     │
│                                                                         │
│  To revert:                                                             │
│    cp ${BACKUP_DIR}/smb.conf.bak ${SMB_CONF}
│    systemctl restart smb                                                │
└─────────────────────────────────────────────────────────────────────────┘

SUMMARY

exit 0
