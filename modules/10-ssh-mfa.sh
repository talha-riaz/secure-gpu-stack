# 10-ssh-mfa: SSH requires an SSH key AND an authenticator code; passwords and root login off
#
# Bypasses this closes, and how:
#   - no `nullok`: a user without an enrolled secret is refused, not waved through
#   - secrets live in /var/lib/secure-gpu-stack/totp (root-only), not ~/.google_authenticator,
#     so a shell running as the user can't read the secret and clone the authenticator
#   - codes can't be reused, attempts are rate-limited (see bin/sgs-enroll)
#   - the key is checked before the code is asked for, so bots without a key never
#     get to guess codes; password and root login are off entirely
# Lockout safety: enforcement only switches on after the admin has entered a valid code,
# and the new sshd config is validated (sshd -t) before reload, with rollback on failure.

TOTP_DIR=$SGS_STATE_DIR/totp
SSHD_DROPIN=/etc/ssh/sshd_config.d/00-secure-gpu-stack.conf
PAM_SSHD=/etc/pam.d/sshd
MODULI=/etc/ssh/moduli
# Evaluate sshd Match blocks as for a client on the internet (TEST-NET-3, never routed).
PROBE_ADDR=203.0.113.10
: "${SGS_SSH_MAX_SESSIONS:=1}"

# shellcheck disable=SC2016  # ${USER} is expanded by PAM at login, not by bash
PAM_BLOCK='# >>> secure-gpu-stack >>>
# Password step removed: factor 1 is the SSH key (sshd AuthenticationMethods),
# factor 2 is the TOTP code below. No `nullok`: users without a secret are refused.
#@include common-auth
auth required pam_google_authenticator.so secret=/var/lib/secure-gpu-stack/totp/${USER} user=root
# <<< secure-gpu-stack <<<'

module_main() {
  check_admin_user
  apt_install openssh-server libpam-google-authenticator oathtool qrencode chrony
  run systemctl enable --now chrony   # TOTP codes depend on an accurate clock
  run install -m 0755 "$SGS_ROOT/bin/sgs-enroll" /usr/local/sbin/sgs-enroll
  enroll_admin
  apply_sshd_and_pam
  check_all_accounts
}

check_admin_user() {
  local home
  id "$SGS_USER" >/dev/null 2>&1 || die "admin user '$SGS_USER' does not exist (use --user)"
  home=$(home_of "$SGS_USER")
  [[ -s $home/.ssh/authorized_keys ]] \
    || die "$SGS_USER has no ~/.ssh/authorized_keys; the SSH key is factor 1, refusing to continue"
}

enroll_admin() {
  if [[ -s $TOTP_DIR/$SGS_USER ]]; then
    ok "$SGS_USER already enrolled for MFA"
    return 0
  fi
  if is_dry; then
    log "would enroll $SGS_USER (QR code + code confirmation)"
    return 0
  fi
  log "enrolling $SGS_USER: have Google or Microsoft Authenticator ready"
  /usr/local/sbin/sgs-enroll "$SGS_USER"
  [[ -s $TOTP_DIR/$SGS_USER ]] || die "enrollment did not complete; SSH config left unchanged"
}

sshd_dropin() {
  # sshd uses the FIRST value it sees for each option, and the Include of
  # sshd_config.d/*.conf sits at the top of sshd_config, so "00-" wins over the
  # cloud image's own drop-ins (e.g. 50-cloud-init.conf turning passwords on).
  cat <<EOF
# Managed by secure-gpu-stack. Local edits will be overwritten.

# --- Authentication: key first, then authenticator code ---
AuthenticationMethods publickey,keyboard-interactive
PubkeyAuthentication yes
KbdInteractiveAuthentication yes
UsePAM yes
PasswordAuthentication no
PermitEmptyPasswords no
PermitRootLogin no
HostbasedAuthentication no
MaxAuthTries 3
LoginGraceTime 30
# At most 3 unauthenticated connections per source IP at a time: blunts the DHEat
# key-exchange CPU flood (CVE-2002-20001), which fail2ban can't see (no failed login).
PerSourceMaxStartups 3

# One session per connection, so client-side multiplexing (ControlMaster)
# can't turn a single code into many shells. Set SGS_SSH_MAX_SESSIONS to relax.
MaxSessions $SGS_SSH_MAX_SESSIONS

# --- Reduce what an authenticated session can reach ---
X11Forwarding no
AllowAgentForwarding no
# Local forwarding stays on: it's how Jupyter/TensorBoard are reached safely (ssh -L).
AllowTcpForwarding local
GatewayPorts no
PermitTunnel no
PermitUserEnvironment no
ClientAliveInterval 300
ClientAliveCountMax 2

# --- Logging: VERBOSE records which key fingerprint logged in ---
LogLevel VERBOSE

# --- Cryptography (ssh-audit hardening guide for Ubuntu 22.04/24.04) ---
HostKey /etc/ssh/ssh_host_ed25519_key
HostKey /etc/ssh/ssh_host_rsa_key
KexAlgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com
HostKeyAlgorithms ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,sk-ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256,rsa-sha2-256-cert-v01@openssh.com
EOF
}

pam_sshd_content() {
  # Replace `@include common-auth` (or our previous block) with PAM_BLOCK.
  BLOCK=$PAM_BLOCK awk '
    /^# >>> secure-gpu-stack/ { print ENVIRON["BLOCK"]; skip = 1; next }
    skip { if (/^# <<< secure-gpu-stack/) skip = 0; next }
    /^@include common-auth/ { print ENVIRON["BLOCK"]; next }
    { print }
  ' "$PAM_SSHD"
}

apply_sshd_and_pam() {
  local snap
  snap=$(mktemp -d)
  cp -a "$PAM_SSHD" "$snap/pam"
  [[ -f $SSHD_DROPIN ]] && cp -a "$SSHD_DROPIN" "$snap/dropin"
  [[ -f $MODULI ]] && cp -a "$MODULI" "$snap/moduli"

  sshd_dropin | write_file "$SSHD_DROPIN" 0644
  pam_sshd_content | write_file "$PAM_SSHD" 0644
  # Drop Diffie-Hellman groups under 3072 bits (flagged by ssh-audit).
  [[ -f $MODULI ]] && awk '$1 ~ /^#/ || $5 >= 3071' "$MODULI" | write_file "$MODULI" 0644

  if is_dry; then
    rm -rf "$snap"
    return 0
  fi

  if ! sshd -t 2>"$snap/err"; then
    warn "sshd rejected the new config, rolling back:"
    cat "$snap/err" >&2
    cp -a "$snap/pam" "$PAM_SSHD"
    if [[ -f $snap/dropin ]]; then cp -a "$snap/dropin" "$SSHD_DROPIN"; else rm -f "$SSHD_DROPIN"; fi
    [[ -f $snap/moduli ]] && cp -a "$snap/moduli" "$MODULI"
    rm -rf "$snap"
    die "SSH configuration unchanged"
  fi
  rm -rf "$snap"

  # Reload keeps existing sessions open, including the one running this installer.
  systemctl reload ssh 2>/dev/null || systemctl restart ssh
  verify_effective_config
  ok "SSH now requires key + authenticator code"
  warn "KEEP THIS SESSION OPEN. In a NEW terminal, confirm: ssh $SGS_USER@<this-host> asks for a verification code."
}

verify_effective_config() {
  local eff
  eff=$(sshd -T -C "user=$SGS_USER,host=check.invalid,addr=$PROBE_ADDR")
  grep -qx 'authenticationmethods publickey,keyboard-interactive' <<<"$eff" || die "AuthenticationMethods not in effect"
  grep -qx 'passwordauthentication no' <<<"$eff" || die "PasswordAuthentication still on"
  grep -qx 'permitrootlogin no' <<<"$eff" || die "PermitRootLogin still on"
  grep -q '^auth required pam_google_authenticator.so' "$PAM_SSHD" || die "PAM TOTP line missing"
  ! grep -Eq '^[^#]*nullok' "$PAM_SSHD" || die "nullok present in $PAM_SSHD"
  ! grep -Eq '^[[:space:]]*@include common-auth' "$PAM_SSHD" || die "password step still active in $PAM_SSHD"
}

# Every non-root account holding SSH keys: flag any that a Match block exempts from the
# code (a key alone would let it in), and any that can't log in until enrolled.
check_all_accounts() {
  local user home methods
  while IFS=: read -r user _ _ _ _ home _; do
    [[ $user != root && -s $home/.ssh/authorized_keys ]] || continue
    if ! is_dry; then
      methods=$(sshd -T -C "user=$user,host=check.invalid,addr=$PROBE_ADDR" 2>/dev/null \
        | awk '$1 == "authenticationmethods" { print $2 }')
      if [[ $methods != "publickey,keyboard-interactive" ]]; then
        warn "$user is EXEMPT from MFA (sshd Match block sets AuthenticationMethods $methods): a key alone lets it in"
        continue
      fi
    fi
    [[ -s $TOTP_DIR/$user ]] && continue
    is_dry && [[ $user == "$SGS_USER" ]] && continue   # would be enrolled by a real run
    warn "$user has SSH keys but no MFA enrollment, so can no longer log in. Enroll with: sudo sgs-enroll $user"
  done < <(getent passwd)
}
