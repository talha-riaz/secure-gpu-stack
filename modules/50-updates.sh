# 50-updates: apply security updates now and every day, without breaking the GPU stack
#
# - Installs pending security updates now, with unattended-upgrade itself, so the policy
#   applied at install time is exactly the one that runs every day afterwards.
# - Holds the kernel, the NVIDIA driver and CUDA/cuDNN/NCCL back from automatic upgrades.
#   Upgrading the driver's libraries under a loaded kernel module breaks every new GPU
#   process ("Driver/library version mismatch") until a reboot, and a kernel without
#   matching NVIDIA modules boots without a GPU. Those move together in a planned
#   window: sudo apt-get dist-upgrade && sudo reboot (or SGS_PATCH_ALL=1 at install).
# - Never reboots and never restarts services on its own: either would kill running
#   training jobs. Pending restarts and reboots are reported instead.

UU_CONF=/etc/apt/apt.conf.d/52secure-gpu-stack-updates
: "${SGS_PATCH_ALL:=0}"   # 1 = also upgrade the held kernel/GPU packages now (reboot needed)

# Python regexes matched from the start of package names (unattended-upgrades semantics).
HOLD_PATTERNS=(
  'linux-image-' 'linux-headers-' 'linux-modules-' 'linux-objects-nvidia-'
  'linux-signatures-nvidia-' 'linux-generic' 'linux-virtual' 'linux-aws' 'linux-gcp'
  'nvidia-' 'libnvidia-' 'cuda' 'libcuda' 'libcudnn' 'libnccl'
  'libcu(blas|fft|rand|solver|sparse|pti|tensor|file)' 'libnv(rtc|jitlink|toolsext|infer|jpeg)'
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
  log "installing pending security updates (kernel, NVIDIA and CUDA held back)"
  # List services that need a restart instead of restarting them (Docker included).
  if ! run env NEEDRESTART_MODE=l DEBIAN_FRONTEND=noninteractive unattended-upgrade; then
    warn "unattended-upgrade failed (apt busy?); security updates were not applied. Re-run: sudo unattended-upgrade -v"
  fi
}

apply_held_updates() {
  warn "SGS_PATCH_ALL=1: upgrading the kernel, NVIDIA driver and CUDA too; reboot afterwards"
  run env NEEDRESTART_MODE=l DEBIAN_FRONTEND=noninteractive apt-get -y -q \
    -o Dpkg::Options::=--force-confold dist-upgrade
}

report_pending() {
  local pending held=0 other=0 pkg p
  pending=$(apt-get -s -o Debug::NoLocking=1 dist-upgrade 2>/dev/null | awk '/^Inst / && /-security/ { print $2 }')
  for pkg in $pending; do
    for p in "${HOLD_PATTERNS[@]}"; do
      if [[ $pkg =~ ^$p ]]; then held=$((held + 1)); continue 2; fi
    done
    other=$((other + 1))
  done
  if ((other)); then
    warn "$other security update(s) still pending outside the held set; check: sudo unattended-upgrade -v --dry-run"
  else
    ok "all security updates applied except $held held for the kernel/GPU maintenance window"
  fi
  [[ -f /var/run/reboot-required ]] && warn "a reboot is needed to activate some updates (not done automatically)"
  return 0
}
