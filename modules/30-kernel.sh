# 30-kernel: kernel hardening (sysctl) and AppArmor, tuned not to break Docker or debugging
#
# Limits what an attacker who already has a foothold (a malicious pip package, a stolen
# key + code) can do next: no kernel addresses for exploit writers, no unprivileged eBPF,
# no core dumps of privileged programs, no tricks with links in /tmp, and the network
# stack ignores spoofed and redirected packets.
# Deliberately NOT changed:
#   - net.ipv4.ip_forward: Docker needs it; generic guides turn it off and break containers.
#   - kernel.yama.ptrace_scope stays 1 (Ubuntu default): users can still attach py-spy or gdb
#     to their own stuck training jobs. 2 (admin only) is stricter but breaks that workflow.

# Boot applies sysctl files in filename order and the last value wins. Ubuntu's own
# 99-protect-links.conf resets fs.protected_fifos, so ours has to sort after it.
SYSCTL_FILE=/etc/sysctl.d/99-secure-gpu-stack.conf
OLD_SYSCTL_FILE=/etc/sysctl.d/60-secure-gpu-stack.conf

module_main() {
  write_file "$SYSCTL_FILE" 0644 <<'EOF'
# Managed by secure-gpu-stack. Local edits will be overwritten.

# Kernel information and attack surface
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.unprivileged_bpf_disabled = 1
net.core.bpf_jit_harden = 2
# One-way until reboot: no loading a different kernel into the running one.
kernel.kexec_load_disabled = 1
kernel.yama.ptrace_scope = 1

# Filesystem tricks (links and FIFOs in world-writable directories) and secret-leaking dumps
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.protected_fifos = 2
fs.protected_regular = 2
fs.suid_dumpable = 0

# Network: drop spoofed and redirected packets; IP forwarding is left on for Docker
net.ipv4.conf.all.rp_filter = 2
net.ipv4.conf.default.rp_filter = 2
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
EOF
  if [[ -f $OLD_SYSCTL_FILE ]]; then
    backup_file "$OLD_SYSCTL_FILE"
    run rm -f "$OLD_SYSCTL_FILE"
  fi
  # Apply every sysctl file the way boot does, so the values verified now are the ones
  # the next boot produces. -e: skip keys this kernel lacks (e.g. IPv6 disabled).
  run sysctl -q -e --system
  is_dry || verify_sysctl

  if is_dry || aa-status --enabled 2>/dev/null; then
    ok "AppArmor enabled"
  else
    warn "AppArmor is not enabled; it needs a kernel boot parameter and a reboot (apparmor=1 security=apparmor)"
  fi
}

verify_sysctl() {
  local key want have bad=()
  while IFS='=' read -r key want; do
    key=${key// /} want=${want// /}
    [[ -z $key || $key == \#* ]] && continue
    have=$(sysctl -n "$key" 2>/dev/null) || continue   # not in this kernel
    [[ $have == "$want" ]] || bad+=("$key=$have (want $want)")
  done <"$SYSCTL_FILE"
  if ((${#bad[@]})); then
    warn "overridden by a sysctl file applied after $SYSCTL_FILE: ${bad[*]}"
  else
    ok "kernel hardening settings applied and checked in boot order (they survive a reboot)"
  fi
}
