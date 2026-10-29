# 40-audit-logging: kernel audit trail (auditd) of the actions an intruder would take
#
# Records, with the real login user even after `sudo su`:
#   - changes to SSH, PAM, sudoers, accounts, firewall, Docker, apt sources, cron, systemd units
#   - any access to the MFA secrets, including reads
#   - changes to ~/.ssh (adding a key is the most common way attackers keep access)
#   - every command a logged-in person runs as root; kernel module loads; clock changes
# Trade-offs:
#   - Logs live on this host, so root can delete them. The real fix is shipping them off
#     the box (SIEM / central log store), like CloudTrail writing to a bucket the instance
#     can't touch. Out of scope here; see the README.
#   - Rules are not made immutable (-e 2) by default: that blocks re-running this installer
#     until a reboot. SGS_AUDIT_IMMUTABLE=1 turns it on.
#   - Ubuntu's auditd rotates logs when full instead of halting the machine: halting a GPU
#     box mid-training is the wrong failure mode here.

AUDIT_RULES=/etc/audit/rules.d/60-secure-gpu-stack.rules
RELOAD_UNIT=sgs-audit-rules-reload.service
: "${SGS_AUDIT_IMMUTABLE:=0}"

module_main() {
  apt_install auditd
  audit_rules | write_file "$AUDIT_RULES" 0640
  reload_after_boot
  run systemctl enable --now auditd
  if is_dry; then run augenrules --load; else augenrules --load >/dev/null; fi   # it prints auditctl -s per file
  is_dry || verify_rules
}

# auditd loads its rules early in boot, before every home directory necessarily exists
# (cloud-init creates and mounts them later). A watch on a missing ~/.ssh fails, and on
# the Lambda instance /home/ubuntu/.ssh was unwatched after a reboot. Load the rules once
# more when the system starts accepting logins, by which point every home exists.
reload_after_boot() {
  if ((SGS_AUDIT_IMMUTABLE)); then
    warn "immutable audit rules: ~/.ssh watches for homes missing at early boot stay off until the next reboot"
    return 0
  fi
  write_file "/etc/systemd/system/$RELOAD_UNIT" 0644 <<'EOF'
# Managed by secure-gpu-stack.
[Unit]
Description=Reload audit rules once home directories exist
After=auditd.service local-fs.target remote-fs.target systemd-user-sessions.service
Requires=auditd.service

[Service]
Type=oneshot
ExecStart=/sbin/augenrules --load

[Install]
WantedBy=multi-user.target
EOF
  run systemctl daemon-reload
  run systemctl enable "$RELOAD_UNIT"
}

verify_rules() {
  local expected loaded
  expected=$(grep -c -E '^-[aw] ' /etc/audit/audit.rules || true)
  loaded=$(auditctl -l | grep -c -E '^-[aw] ' || true)
  if ((loaded < expected)); then
    warn "only $loaded of $expected audit rules loaded; see: sudo augenrules --load"
  else
    ok "audit rules loaded: $loaded (search: sudo ausearch -i -k <key>; add --input-logs in scripts)"
  fi
}

audit_rules() {
  local user home
  cat <<'EOF'
## Managed by secure-gpu-stack. Search with: sudo ausearch -i -k <key>

## Accounts, privileges and authentication
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/sudoers -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers
-w /etc/pam.d/ -p wa -k pam
-w /etc/ssh/sshd_config -p wa -k sshd_config
-w /etc/ssh/sshd_config.d/ -p wa -k sshd_config

## MFA secrets: any access at all, reads included
-w /var/lib/secure-gpu-stack/totp/ -p rwa -k totp_secrets

## Network exposure and software sources
-w /etc/ufw/ -p wa -k firewall
-w /etc/docker/ -p wa -k docker_config
-w /etc/apt/sources.list -p wa -k apt_sources
-w /etc/apt/sources.list.d/ -p wa -k apt_sources

## Persistence: scheduled jobs and services
-w /etc/crontab -p wa -k cron
-w /etc/cron.d/ -p wa -k cron
-w /var/spool/cron/ -p wa -k cron
-w /etc/systemd/system/ -p wa -k systemd_units

## Root commands run by a logged-in person (auid = who logged in, kept across sudo/su)
-a always,exit -F arch=b64 -S execve -F euid=0 -F auid>=1000 -F auid!=unset -k root_commands

## Kernel modules (rootkits) and clock changes made by people (TOTP and log timelines rely on time)
-a always,exit -F arch=b64 -S init_module,finit_module,delete_module -k kernel_modules
-a always,exit -F arch=b64 -S adjtimex,settimeofday,clock_settime -F auid>=1000 -F auid!=unset -k time_change

## SSH keys: adding one is the most common way an intruder keeps access
-w /root/.ssh/ -p wa -k ssh_keys
EOF
  # Existing accounts' ~/.ssh; accounts created later need a re-run of the installer.
  # -i: a home that doesn't exist yet at early boot must not stop the rules after it.
  echo "-i"
  while IFS=: read -r user _ _ _ _ home _; do
    [[ $user != root && -d $home/.ssh ]] && echo "-w $home/.ssh/ -p wa -k ssh_keys"
  done < <(getent passwd)
  if ((SGS_AUDIT_IMMUTABLE)); then
    echo
    echo "## Immutable: rules can't be changed (or auditing stopped) until reboot"
    echo "-e 2"
  fi
  return 0
}
