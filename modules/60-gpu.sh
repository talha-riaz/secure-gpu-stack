# 60-gpu: close the browser-IDE way around SSH MFA, restrict GPU profiling, patch container escapes
#
# - Browser IDE: Lambda's console can open JupyterLab in the browser ("Cloud IDE"), and a
#   Jupyter terminal is a shell that never asks for the SSH key or the authenticator code.
#   Any Jupyter/code-server service is stopped, disabled and masked, along with the
#   outbound cloudflared tunnel that publishes it (SGS_BROWSER_IDE=keep to leave both).
#   Jupyter stays usable the safe way: bind it to 127.0.0.1 and reach it with
#   `ssh -L 8888:localhost:8888`, which goes through key + code.
# - GPU profiling: performance counters only for admins (NVreg_RestrictProfilingToAdminUsers),
#   since unprivileged profiling enables side-channel attacks (CVE-2018-6260). Current
#   drivers default to this; the setting makes it explicit so it can't silently regress.
# - NVIDIA Container Toolkit: versions before 1.17.8 allow a malicious container image to
#   escape to the host (CVE-2024-0132, CVE-2025-23266 "NVIDIAScape"). Upgraded if older.
#   It ships from NVIDIA's repository, so OS vulnerability scanners don't flag it.

NVIDIA_MODPROBE=/etc/modprobe.d/secure-gpu-stack-nvidia.conf
NVIDIA_PARAMS=/proc/driver/nvidia/params
TOOLKIT_MIN=1.17.8
: "${SGS_BROWSER_IDE:=off}"   # off | keep

module_main() {
  close_browser_ide
  restrict_gpu_profiling
  patch_container_toolkit
}

# Service units that run Jupyter or code-server, by unit name or by command line.
ide_units() {
  local unit pid
  {
    systemctl list-units --type=service --all --no-legend --plain 2>/dev/null \
      | awk '{ print $1 }' | grep -iE 'jupyter|code-server'
    for pid in $(pgrep -f -i 'jupyter|code-server' || true); do
      unit=$(ps -o unit= -p "$pid" 2>/dev/null | tr -d ' ')
      [[ $unit == *.service ]] && echo "$unit"
    done
  } | sort -u
}

# Masking survives reboots and package upgrades re-enabling the unit. It needs the unit's
# path in /etc/systemd/system, so a locally created unit file is moved to backups first.
mask_unit() {
  local path
  path=$(systemctl show -p FragmentPath --value "$1")
  if [[ $path == /etc/systemd/system/* && -f $path && ! -L $path ]]; then
    backup_file "$path"
    run rm -f "$path"
    run systemctl daemon-reload
  fi
  run systemctl mask "$1"
}

close_browser_ide() {
  local units unit pid
  mapfile -t units < <(ide_units)
  if ((${#units[@]} == 0)); then
    ok "no Jupyter/code-server service running"
  elif [[ $SGS_BROWSER_IDE == keep ]]; then
    warn "SGS_BROWSER_IDE=keep: leaving ${units[*]} running; its terminal bypasses SSH MFA"
  else
    for unit in "${units[@]}"; do
      run systemctl disable --now "$unit"
      mask_unit "$unit"
      ok "stopped and masked $unit (browser terminal that bypassed SSH MFA)"
    done
  fi
  close_ide_tunnels
  # Anything still running outside a service unit can't be managed safely; report it.
  for pid in $(pgrep -f -i 'jupyter|code-server' || true); do
    warn "IDE process outside systemd still running: pid $pid $(ps -o args= -p "$pid" | cut -c1-80)"
  done
  return 0
}

# Lambda publishes the Cloud IDE through an outbound cloudflared tunnel
# (*.lambdaspaces.com -> localhost:7000). It connects out, so no inbound firewall ever
# sees it; with the IDE off, all it could still do is publish whatever later listens on
# that port. Its credentials file ships world-readable, letting any local process run
# its own connector for the tunnel.
close_ide_tunnels() {
  local unit
  [[ -d /etc/cloudflared ]] || return 0
  run find /etc/cloudflared -maxdepth 1 -name '*.json' -exec chmod 0600 {} +
  ok "tunnel credentials in /etc/cloudflared readable by root only"
  [[ $SGS_BROWSER_IDE == keep ]] && return 0
  for unit in $(systemctl list-unit-files --no-legend 'cloudflared*.service' | awk '{ print $1 }'); do
    if [[ $(systemctl is-enabled "$unit" 2>/dev/null || true) == masked ]] && ! systemctl is-active -q "$unit"; then
      ok "$unit already masked (outbound tunnel to the browser IDE)"
      continue
    fi
    log "$unit publishes: $(awk '$1 ~ /hostname:|service:/ { print $NF }' /etc/cloudflared/config.yml 2>/dev/null | paste -sd ' ' -)"
    run systemctl disable --now "$unit"
    mask_unit "$unit"
    ok "stopped and masked $unit (outbound tunnel to the browser IDE, invisible to inbound firewalls)"
  done
}

restrict_gpu_profiling() {
  local current
  if [[ ! -r $NVIDIA_PARAMS ]]; then
    log "no NVIDIA driver loaded; skipping GPU profiling restriction"
    return 0
  fi
  write_file "$NVIDIA_MODPROBE" 0644 <<'EOF'
# Managed by secure-gpu-stack. GPU performance counters for admins only (CVE-2018-6260).
options nvidia NVreg_RestrictProfilingToAdminUsers=1
EOF
  current=$(awk -F': *' '$1 == "RmProfilingAdminOnly" { print $2 }' "$NVIDIA_PARAMS")
  if [[ $current == 1 ]]; then
    ok "GPU profiling restricted to admins (already active; now pinned in $NVIDIA_MODPROBE)"
  else
    is_dry || run update-initramfs -u
    warn "GPU profiling is open to all users until the next reboot (setting applies when the driver reloads)"
  fi
}

patch_container_toolkit() {
  local version
  version=$(dpkg-query -W -f='${Version}' nvidia-container-toolkit 2>/dev/null || true)
  if [[ -z $version ]]; then
    log "NVIDIA Container Toolkit not installed; nothing to patch"
    return 0
  fi
  if dpkg --compare-versions "$version" ge "$TOOLKIT_MIN"; then
    ok "NVIDIA Container Toolkit $version (>= $TOOLKIT_MIN, container-escape fixes included)"
    return 0
  fi
  log "NVIDIA Container Toolkit $version is older than $TOOLKIT_MIN (container escapes); upgrading"
  apt_update_once
  run env DEBIAN_FRONTEND=noninteractive apt-get install -y -q --only-upgrade \
    nvidia-container-toolkit nvidia-container-toolkit-base libnvidia-container-tools libnvidia-container1
  is_dry && return 0
  version=$(dpkg-query -W -f='${Version}' nvidia-container-toolkit)
  if dpkg --compare-versions "$version" ge "$TOOLKIT_MIN"; then
    ok "NVIDIA Container Toolkit upgraded to $version"
  else
    warn "NVIDIA Container Toolkit still $version: no newer build in the configured repositories"
  fi
}
