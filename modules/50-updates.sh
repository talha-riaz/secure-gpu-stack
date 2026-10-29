# 50-updates: apply security updates now and every day, without breaking the GPU stack
#
# - Installs pending security updates now, with unattended-upgrade itself, so the policy
#   applied at install time is exactly the one that runs every day afterwards.
# - Also auto-updates the container runtime and other security-relevant third-party repos
#   (Docker, NVIDIA Container Toolkit, cloudflared): container escapes live there, and
#   Ubuntu's security pocket never covers them. Lambda's own repo (PyTorch, CUDA) stays
#   manual: upgrading research libraries under running work can break it.
# - Holds the kernel, the NVIDIA driver and CUDA/cuDNN/NCCL back from automatic upgrades.
#   Upgrading the driver's libraries under a loaded kernel module breaks every new GPU
#   process ("Driver/library version mismatch") until a reboot, and a kernel without
#   matching NVIDIA modules boots without a GPU. Those move together in a planned
#   window: sudo apt-get dist-upgrade && sudo reboot (or SGS_PATCH_ALL=1 at install).
# - Never reboots and never restarts services on its own: either would kill running
#   training jobs. Pending restarts and reboots are reported instead.

UU_CONF=/etc/apt/apt.conf.d/52secure-gpu-stack-updates
: "${SGS_PATCH_ALL:=0}"   # 1 = also upgrade the held kernel/GPU packages now (reboot needed)

# Third-party origins (apt-cache policy: o=..., a=...) whose updates install automatically.
# shellcheck disable=SC2016  # ${distro_codename} is expanded by unattended-upgrades
EXTRA_ORIGINS=(
  'origin=Docker,archive=${distro_codename},label=Docker CE'
  'origin=https://nvidia.github.io/libnvidia-container/stable'
  'origin=cloudflared,codename=${distro_codename}'
)

# Python regexes matched from the start of package names (unattended-upgrades semantics).
# The container toolkit (nvidia-container-*, libnvidia-container*) is excluded from the
# NVIDIA hold: it is user space, independent of the driver, and patches container escapes.
HOLD_PATTERNS=(
  'linux-image-' 'linux-headers-' 'linux-modules-' 'linux-tools-' 'linux-objects-nvidia-'
  'linux-signatures-nvidia-' 'linux-nvidia' 'linux-generic' 'linux-virtual' 'linux-aws' 'linux-gcp'
  'nvidia-(?!container)' 'libnvidia-(?!container)' 'cuda' 'libcuda' 'libcudnn' 'libnccl' 'libcuinj' 'lambda-stack'
  'libcu(blas|fft|rand|solver|sparse|pti|tensor|file)' 'libnv(rtc|jitlink|toolsext|infer|jpeg|blas|vm|sdm)'
)

module_main() {
  apt_install unattended-upgrades
  write_update_policy
  apply_security_updates
  ((SGS_PATCH_ALL)) && apply_held_updates
  is_dry || report_pending
}

write_update_policy() {
  local p
  {
    echo "// Managed by secure-gpu-stack. Local edits will be overwritten."
    echo "// Daily: refresh package lists and install security updates."
    echo 'APT::Periodic::Update-Package-Lists "1";'
    echo 'APT::Periodic::Unattended-Upgrade "1";'
    echo 'APT::Periodic::AutocleanInterval "7";'
    echo "// Never reboot by itself: that would kill running training jobs."
    echo 'Unattended-Upgrade::Automatic-Reboot "false";'
    echo "// One dpkg transaction instead of one per package group: a fresh image can carry"
    echo "// hundreds of pending updates, and per-step hooks made that take hours."
    echo 'Unattended-Upgrade::MinimalSteps "false";'
    echo "// Security-relevant third-party repos: container runtime, NVIDIA toolkit, cloudflared."
    echo "Unattended-Upgrade::Origins-Pattern {"
    for p in "${EXTRA_ORIGINS[@]}"; do
      echo "    \"$p\";"
    done
    echo "};"
    echo "// Kernel + NVIDIA driver + CUDA move together, in a planned window with a reboot."
    echo "Unattended-Upgrade::Package-Blacklist {"
    for p in "${HOLD_PATTERNS[@]}"; do
      echo "    \"$p\";"
    done
    echo "};"
  } | write_file "$UU_CONF" 0644
  run systemctl enable --now apt-daily.timer apt-daily-upgrade.timer
}

apply_security_updates() {
  log "installing pending security updates (kernel, NVIDIA and CUDA held back; can take several minutes)"
  # Skip needrestart's scan of every process during this run (it ran after each step and
  # dominated the time); services needing a restart are listed by report_pending instead.
  if ! run env NEEDRESTART_SUSPEND=1 DEBIAN_FRONTEND=noninteractive unattended-upgrade -v; then
    warn "unattended-upgrade failed (apt busy?); security updates were not applied. Re-run: sudo unattended-upgrade -v"
  fi
}

apply_held_updates() {
  warn "SGS_PATCH_ALL=1: upgrading the kernel, NVIDIA driver and CUDA too; reboot afterwards"
  run env NEEDRESTART_MODE=l DEBIAN_FRONTEND=noninteractive apt-get -y -q \
    -o Dpkg::Options::=--force-confold dist-upgrade
}

report_pending() {
  local pending held other
  pending=$(apt-get -s -o Debug::NoLocking=1 dist-upgrade 2>/dev/null | awk '/^Inst / && /-security/ { print $2 }')
  held=$(printf '%s\n' "$pending" | python3 -c '
import re, sys
patterns = sys.argv[1:]
print(sum(1 for pkg in sys.stdin.read().split() if any(re.match(p, pkg) for p in patterns)))' "${HOLD_PATTERNS[@]}")
  other=$(( $(printf '%s\n' "$pending" | grep -c .) - held ))
  if ((other)); then
    warn "$other security update(s) still pending outside the held set; check: sudo unattended-upgrade -v --dry-run"
  else
    ok "all security updates applied except $held held for the kernel/GPU maintenance window"
  fi
  [[ -f /var/run/reboot-required ]] && warn "a reboot is needed to activate some updates (not done automatically)"
  if command -v needrestart >/dev/null 2>&1; then
    log "services running old library versions (restart them when convenient):"
    NEEDRESTART_MODE=l needrestart -b 2>/dev/null | awk -F': ' '/^NEEDRESTART-SVC/ { print "    " $2 }' >&2
  fi
  return 0
}
