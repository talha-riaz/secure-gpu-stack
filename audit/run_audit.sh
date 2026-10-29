#!/usr/bin/env bash
# run_audit.sh: collect security evidence from this host for the before/after report.
#
#   sudo ./audit/run_audit.sh before              # stock instance, before install.sh
#   sudo ./audit/run_audit.sh after               # after install.sh
#   sudo ./audit/run_audit.sh after --no-trivy    # skip the slow vulnerability scan
#
# Collection only: raw command output goes to audit/results/<label>-<host>-<time>/
# and no security setting is changed (it does install the scanners it needs:
# lynis and ssh-audit from Ubuntu's repositories, and a checksum-pinned trivy).
# Pass/fail is decided later by report.py, so every number in the report can be
# traced back to a raw file. Secrets are never collected: TOTP files are listed by
# name and permissions only, and tokens in process arguments are redacted.

# shellcheck disable=SC2016  # bash -c snippets are expanded by the inner shell
set -uo pipefail   # no -e: one failing probe must not stop the rest

SGS_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=lib/common.sh
source "$SGS_ROOT/lib/common.sh"
SGS_MODULE=audit

TOTP_DIR=$SGS_STATE_DIR/totp
# A public-looking client address, so sshd Match blocks are evaluated as they
# would be for a connection from the internet (TEST-NET-3, never routed).
PROBE_ADDR=203.0.113.10

# Pinned scanners: versions at least a few weeks old, checksums from the release pages.
# Ubuntu 22.04's ssh-audit (2.5.0, 2021) misreads current OpenSSH (e.g. flags the
# Terrapin fix as "unknown"), so a pinned PyPI wheel is used; it runs in place.
SSH_AUDIT_WHEEL_URL=https://files.pythonhosted.org/packages/24/79/ce022332cf59f0eb2e1b8ff6cdab3f80502449fdf3c053f05191a5a87326/ssh_audit-3.9.0-py3-none-any.whl
SSH_AUDIT_SHA256=3dad48d4678e0de31f6332cc7674f9d7dd1805f86babf3796f41c2fd879cb812
TRIVY_VERSION=0.75.0
declare -A TRIVY_SHA256=(
  [amd64]=c6e65abddb348e25f10549df887045629cf28cc72453cd1c63acb717316b3f3f
  [arm64]=a1ee9f6ffb7d112b64ff726a2a0717c21175c1114361391f4a132956751a13b3
)

usage() {
  sed -n '2,6p' "$0" | sed 's/^# \{0,1\}//'
  cat <<'EOF'

Options:
  --out DIR          write results here instead of audit/results/<label>-<host>-<time>
  --no-trivy         skip the vulnerability scan (the slowest step)
  --no-lynis         skip the Lynis hardening scan
  --sbom             also write a CycloneDX software bill of materials (needs trivy)
  --no-install       don't install missing scanners; skip them instead
  --no-apt-update    don't refresh package lists before counting pending updates
EOF
}

have() { command -v "$1" >/dev/null 2>&1; }

# cap FILE CMD...: save CMD's stdout+stderr to $OUT/FILE and log its exit code.
cap() {
  local file=$1 rc
  shift
  timeout "${CAP_TIMEOUT:-300}" "$@" >"$OUT/$file" 2>&1
  rc=$?
  printf '%s\t%s\t%s\n' "$file" "$rc" "$*" >>"$OUT/_commands.tsv"
}

install_scanners() {
  if ((RUN_LYNIS)) && ! have lynis; then
    log "installing lynis from Ubuntu's repositories"
    DEBIAN_FRONTEND=noninteractive apt-get install -y -q --no-install-recommends lynis >/dev/null \
      || warn "could not install lynis; that scan will be skipped"
  fi
  install_ssh_audit
  ((RUN_TRIVY)) && install_trivy
}

# fetch_verified URL SHA256 DEST: download, and keep the file only if the checksum matches.
fetch_verified() {
  local tmp
  tmp=$(mktemp)
  if curl -fsSL -o "$tmp" "$1" && echo "$2  $tmp" | sha256sum -c --quiet; then
    install -D -m 0644 "$tmp" "$3"
    rm -f "$tmp"
  else
    rm -f "$tmp"
    return 1
  fi
}

install_ssh_audit() {
  SSH_AUDIT_WHEEL=/opt/sgs-audit/$(basename "$SSH_AUDIT_WHEEL_URL")
  [[ -f $SSH_AUDIT_WHEEL ]] && return 0
  log "installing ssh-audit (checksum-verified)"
  fetch_verified "$SSH_AUDIT_WHEEL_URL" "$SSH_AUDIT_SHA256" "$SSH_AUDIT_WHEEL" \
    || { warn "ssh-audit download or checksum verification failed; skipping"; SSH_AUDIT_WHEEL=""; }
}

install_trivy() {
  local arch asset dir tmp
  arch=$(dpkg --print-architecture)
  dir=/opt/sgs-audit/trivy-$TRIVY_VERSION
  TRIVY=$dir/trivy
  [[ -x $TRIVY ]] && return 0
  case $arch in
    amd64) asset=Linux-64bit ;;
    arm64) asset=Linux-ARM64 ;;
    *) warn "no pinned trivy build for $arch; skipping vulnerability scan"; RUN_TRIVY=0; return 0 ;;
  esac
  log "installing trivy $TRIVY_VERSION (checksum-verified)"
  tmp=$(mktemp -d)
  if fetch_verified "https://github.com/aquasecurity/trivy/releases/download/v$TRIVY_VERSION/trivy_${TRIVY_VERSION}_$asset.tar.gz" \
       "${TRIVY_SHA256[$arch]}" "$tmp/trivy.tgz"; then
    install -d -m 0755 "$dir"
    tar -xzf "$tmp/trivy.tgz" -C "$dir" trivy
  else
    warn "trivy download or checksum verification failed; skipping vulnerability scan"
    RUN_TRIVY=0
  fi
  rm -rf "$tmp"
}

collect_meta() {
  local gpu=none
  have nvidia-smi && gpu=$(timeout 30 nvidia-smi --query-gpu=name --format=csv,noheader 2>/dev/null | head -n1)
  # shellcheck source=/dev/null
  . /etc/os-release
  {
    echo "label=$LABEL"
    echo "hostname=$(hostname)"
    echo "collected_at=$(date -Is)"
    echo "os=$PRETTY_NAME"
    echo "kernel=$(uname -r)"
    echo "arch=$(dpkg --print-architecture)"
    echo "gpu=${gpu:-none}"
    echo "sgs_installed=$([[ -f /etc/ssh/sshd_config.d/00-secure-gpu-stack.conf ]] && echo yes || echo no)"
    echo "sgs_version=$(git -c safe.directory="$SGS_ROOT" -C "$SGS_ROOT" describe --always --dirty 2>/dev/null \
      || cat "$SGS_ROOT/VERSION" 2>/dev/null || echo unknown)"
  } >"$OUT/meta.txt"
}

collect_ssh() {
  local akf user uid home shell f n methods port
  cap sshd_T.txt sshd -T -C "user=root,host=audit.example,addr=$PROBE_ADDR"
  cap pam_sshd.txt cat /etc/pam.d/sshd
  cap sshd_config_files.txt bash -c \
    'for f in /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf; do [ -f "$f" ] && { echo "=== $f"; cat "$f"; }; done'
  cap totp_store.txt bash -c "stat -c '%a %U:%G %n' '$TOTP_DIR' '$TOTP_DIR'/* 2>&1"

  # Every account that can present an SSH key, and what sshd would demand from it.
  akf=$(sshd -T 2>/dev/null | awk '$1 == "authorizedkeysfile" { $1 = ""; print }')
  printf 'user\tuid\tshell\tkeys\ttotp_secret\thome_ga_file\tauth_methods\n' >"$OUT/ssh_users.tsv"
  while IFS=: read -r user _ uid _ _ home shell; do
    n=0
    for f in $akf; do
      f=${f//%h/$home}; f=${f//%u/$user}; f=${f//%%/%}
      [[ $f == /* ]] || f=$home/$f
      [[ -f $f ]] && n=$((n + $(grep -cE '^[^#[:space:]]' "$f")))
    done
    ((n > 0)) || continue
    methods=$(sshd -T -C "user=$user,host=audit.example,addr=$PROBE_ADDR" 2>/dev/null \
      | awk '$1 == "authenticationmethods" { $1 = ""; sub(/^ /, ""); print }')
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$user" "$uid" "$shell" "$n" \
      "$([[ -s $TOTP_DIR/$user ]] && echo yes || echo no)" \
      "$([[ -e $home/.google_authenticator ]] && echo yes || echo no)" "$methods"
  done < <(getent passwd) >>"$OUT/ssh_users.tsv"

  if [[ -n $SSH_AUDIT_WHEEL ]]; then
    port=$(sshd -T 2>/dev/null | awk '$1 == "port" { print $2; exit }')
    cap ssh_audit.json env PYTHONPATH="$SSH_AUDIT_WHEEL" python3 -m ssh_audit -j -p "${port:-22}" 127.0.0.1
    cap ssh_audit.txt env PYTHONPATH="$SSH_AUDIT_WHEEL" python3 -m ssh_audit -n -p "${port:-22}" 127.0.0.1
  fi
}

collect_network() {
  cap listening.txt ss -H -tulpn
  cap ufw.txt ufw status verbose
  cap iptables_filter.txt iptables-save -t filter
  cap iptables_nat.txt iptables-save -t nat
  cap ip6tables_filter.txt ip6tables-save -t filter
  cap fail2ban.txt bash -c 'fail2ban-client status && fail2ban-client status sshd'
  if have docker; then
    cap docker_version.txt docker version --format '{{.Server.Version}}'
    cap docker_ps.txt docker ps --format '{{.Names}}\t{{.Ports}}'
    cap docker_daemon.json bash -c 'cat /etc/docker/daemon.json 2>/dev/null || echo "{}"'
  fi
}

collect_packages() {
  ((APT_UPDATE)) && cap apt_update.txt apt-get update -q
  cap apt_upgrades.txt apt-get -s -o Debug::NoLocking=1 dist-upgrade
  cap apt_holds.txt apt-mark showhold
  cap apt_preferences.txt bash -c 'for f in /etc/apt/preferences /etc/apt/preferences.d/*; do [ -f "$f" ] && { echo "=== $f"; cat "$f"; }; done'
  cap unattended.txt bash -c \
    'dpkg-query -W -f="\${Package} \${Status}\n" unattended-upgrades; apt-config dump | grep -E "^(APT::Periodic|Unattended-Upgrade::)"; systemctl is-enabled apt-daily-upgrade.timer'
  cap reboot_required.txt bash -c 'cat /var/run/reboot-required.pkgs 2>/dev/null || echo "none"'
  cap gpu_packages.txt bash -c \
    "dpkg-query -W -f='\${Package}\t\${Version}\n' | grep -E '^(nvidia|libnvidia|cuda|libcudnn|libnccl|lambda)'"
}

collect_kernel_and_logging() {
  cap sysctl.txt sysctl -a
  cap apparmor.txt aa-status
  cap auditd.txt bash -c 'systemctl is-active auditd; auditctl -l'
  cap journald.txt bash -c \
    'ls -ld /var/log/journal 2>&1; systemd-analyze cat-config systemd/journald.conf 2>/dev/null | grep -E "^[[:space:]]*Storage"'
}

collect_gpu() {
  if have nvidia-smi; then
    cap gpu_smi.txt nvidia-smi --query-gpu=name,driver_version,memory.total --format=csv,noheader
    cap nvidia_params.txt cat /proc/driver/nvidia/params
  fi
  cap gpu_devices.txt bash -c 'ls -l /dev/nvidia* 2>&1'
  cap nvidia_modprobe.txt bash -c 'grep -rhs "^options nvidia" /etc/modprobe.d/ || echo "none"'
  cap services.txt systemctl list-units --type=service --state=running --no-legend --no-pager
  # Browser IDEs (e.g. Lambda's Cloud IDE JupyterLab) are a way in that skips SSH.
  # Tokens in their command lines are redacted before saving.
  cap ide_processes.txt bash -c \
    'ps -eo user,pid,args --no-headers | grep -iE "[j]upyter|[n]otebook|[c]ode-server|[l]ambda|[c]loudflared" | sed -E "s/(token|password)=[^ ]*/\1=REDACTED/Ig"; systemctl list-unit-files --no-legend --no-pager | grep -iE "[j]upyter|[l]ambda|[c]ode-server|[c]loudflared"'
}

collect_supply_chain() {
  cap apt_sources.txt bash -c \
    'for f in /etc/apt/sources.list /etc/apt/sources.list.d/*; do [ -f "$f" ] && { echo "=== $f"; grep -vE "^[[:space:]]*(#|$)" "$f"; }; done'
  cap ml_defaults.txt bash -c 'grep -rhs "TORCH_FORCE_WEIGHTS_ONLY_LOAD\|HF_HUB_DISABLE_TELEMETRY" /etc/profile.d/ /etc/environment || echo none'
  cap model_scanner.txt bash -c 'command -v sgs-scan-model || echo none'
  CAP_TIMEOUT=120 cap torch_version.txt python3 -c 'import torch; print(torch.__version__)'
}

collect_tunnels() {
  # Outbound tunnels (e.g. Lambda's Cloud IDE via cloudflared) bypass inbound firewalls.
  cap tunnel_creds.txt bash -c "stat -c '%a %U:%G %n' /etc/cloudflared/* 2>/dev/null || echo none"
}

collect_lynis() {
  have lynis || { warn "lynis not available; skipping"; return 0; }
  log "running Lynis (1-3 minutes)"
  CAP_TIMEOUT=900 cap lynis.txt lynis audit system --quick --no-colors \
    --logfile "$OUT/lynis.log" --report-file "$OUT/lynis-report.dat"
}

collect_trivy() {
  log "running trivy vulnerability scan of the filesystem (a few minutes on a full ML image)"
  CAP_TIMEOUT=2400 cap trivy.log "$TRIVY" rootfs --quiet --scanners vuln --format json \
    --output "$OUT/trivy.json" --timeout 35m \
    --skip-dirs /proc --skip-dirs /sys --skip-dirs /dev --skip-dirs /run \
    --skip-dirs /var/lib/docker --skip-dirs /var/lib/containerd --skip-dirs /snap \
    --skip-dirs /opt/sgs-audit --skip-dirs "$SGS_ROOT/audit/results" /
  [[ -s $OUT/trivy.json ]] || return 0

  # The full JSON carries advisory text for every finding (tens to hundreds of MB),
  # so keep a compact table for the report and gzip the original as evidence.
  python3 -I - "$OUT/trivy.json" "$OUT/trivy_summary.json" <<'EOF'
import json, sys
src, dst = sys.argv[1:3]
with open(src) as fh:
    report = json.load(fh)
fields = ["class", "type", "target", "pkg", "installed", "fixed", "status", "severity", "id"]
rows = [[r.get("Class"), r.get("Type"), r.get("Target"), v.get("PkgName"), v.get("InstalledVersion"),
         v.get("FixedVersion") or "", v.get("Status") or "", v.get("Severity"), v.get("VulnerabilityID")]
        for r in report.get("Results") or [] for v in r.get("Vulnerabilities") or []]
with open(dst, "w") as fh:
    json.dump({"trivy": (report.get("Trivy") or {}).get("Version"), "fields": fields, "rows": rows}, fh)
EOF
  gzip -f "$OUT/trivy.json"
}

collect_sbom() {
  log "writing a CycloneDX SBOM of everything installed (another full filesystem pass)"
  CAP_TIMEOUT=2400 cap sbom.log "$TRIVY" rootfs --quiet --format cyclonedx --output "$OUT/sbom.cdx.json" \
    --skip-dirs /proc --skip-dirs /sys --skip-dirs /dev --skip-dirs /run \
    --skip-dirs /var/lib/docker --skip-dirs /var/lib/containerd --skip-dirs /snap \
    --skip-dirs /opt/sgs-audit --skip-dirs "$SGS_ROOT/audit/results" /
  [[ -s $OUT/sbom.cdx.json ]] && gzip -f "$OUT/sbom.cdx.json"
}

LABEL="" OUT="" RUN_TRIVY=1 RUN_LYNIS=1 RUN_SBOM=0 INSTALL=1 APT_UPDATE=1 TRIVY="" SSH_AUDIT_WHEEL=""
while (($#)); do
  case $1 in
    --out) OUT=${2:?--out needs a directory}; shift ;;
    --no-trivy) RUN_TRIVY=0 ;;
    --no-lynis) RUN_LYNIS=0 ;;
    --sbom) RUN_SBOM=1 ;;
    --no-install) INSTALL=0 ;;
    --no-apt-update) APT_UPDATE=0 ;;
    -h|--help) usage; exit 0 ;;
    -*) usage >&2; die "unknown option: $1" ;;
    *) [[ -z $LABEL ]] || die "only one label allowed"; LABEL=$1 ;;
  esac
  shift
done
[[ $LABEL =~ ^[A-Za-z0-9_.-]+$ ]] || { usage >&2; die "give a label such as 'before' or 'after'"; }

require_root
require_ubuntu
OUT=${OUT:-$SGS_ROOT/audit/results/$LABEL-$(hostname -s)-$(date +%Y%m%d-%H%M%S)}
install -d -m 0700 "$OUT"
: >"$OUT/_commands.tsv"

if ((INSTALL)); then
  install_scanners
else
  # Use scanners a previous run installed; download nothing.
  SSH_AUDIT_WHEEL=/opt/sgs-audit/$(basename "$SSH_AUDIT_WHEEL_URL")
  [[ -f $SSH_AUDIT_WHEEL ]] || { warn "ssh-audit not installed; skipping"; SSH_AUDIT_WHEEL=""; }
  TRIVY=/opt/sgs-audit/trivy-$TRIVY_VERSION/trivy
  if ((RUN_TRIVY)) && [[ ! -x $TRIVY ]]; then warn "trivy not installed; skipping"; RUN_TRIVY=0; fi
fi

log "collecting into $OUT"
collect_meta
collect_ssh
collect_network
collect_packages
collect_kernel_and_logging
collect_gpu
collect_supply_chain
collect_tunnels
((RUN_LYNIS)) && collect_lynis
((RUN_TRIVY)) && collect_trivy
((RUN_TRIVY && RUN_SBOM)) && collect_sbom

# Let the invoking admin copy the results off the box without sudo.
[[ -n ${SUDO_USER:-} ]] && chown -R "$SUDO_USER:" "$OUT"
ok "done: $OUT"
log "view on this host:  python3 $SGS_ROOT/audit/report.py $OUT"
log "compare two runs:   python3 audit/report.py BEFORE_DIR AFTER_DIR -o audit/report"
