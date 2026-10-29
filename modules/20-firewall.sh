# 20-firewall: deny all inbound except SSH, close Docker's firewall bypass, ban brute-force IPs
#
# Three layers:
#   - ufw: default deny inbound; only the SSH port is open. Anything else that starts
#     listening (Jupyter, TensorBoard, a debug server on 0.0.0.0) is unreachable from
#     outside and is meant to be used through an SSH tunnel (ssh -L), i.e. key + code.
#   - Docker: published container ports are DNAT'ed and routed through the FORWARD
#     chain, where Docker's rules run before ufw's, so `docker run -p 8888:...` is
#     public even with ufw "deny incoming". We (a) make Docker publish on 127.0.0.1
#     by default and (b) drop new outside connections in DOCKER-USER, the one chain
#     Docker evaluates before its own, which also covers explicit -p 0.0.0.0:...
#   - fail2ban: bans an IP (through ufw) after repeated failed SSH logins, including
#     failed authenticator codes.
# Lockout safety: the SSH port is allowed before ufw is enabled, and enabling ufw
# keeps established connections (this session) alive.

UFW_AFTER_RULES=/etc/ufw/after.rules
UFW_AFTER6_RULES=/etc/ufw/after6.rules
DOCKER_DAEMON_JSON=/etc/docker/daemon.json
FAIL2BAN_JAIL=/etc/fail2ban/jail.d/secure-gpu-stack.local
: "${SGS_ALLOW_PORTS:=}"        # extra inbound ports, e.g. "443/tcp,51820/udp"
: "${SGS_FAIL2BAN_IGNOREIP:=}"  # never ban these, e.g. an office IP (space-separated)

DOCKER_USER_BLOCK='# >>> secure-gpu-stack >>>
# Docker routes published ports through FORWARD, where its own rules run before
# ufw, so ufw alone does not protect containers. DOCKER-USER runs first: drop NEW
# connections from outside to containers. Replies, traffic the containers start,
# and connections from this host itself are unaffected.
*filter
:DOCKER-USER - [0:0]
-A DOCKER-USER -m conntrack --ctstate RELATED,ESTABLISHED -j RETURN
-A DOCKER-USER -i docker0 -j RETURN
-A DOCKER-USER -i br-+ -j RETURN
-A DOCKER-USER -m conntrack --ctstate NEW -m limit --limit 3/min -j LOG --log-prefix "[SGS DOCKER BLOCK] "
-A DOCKER-USER -m conntrack --ctstate NEW -j DROP
-A DOCKER-USER -j RETURN
COMMIT
# <<< secure-gpu-stack <<<'

module_main() {
  apt_install ufw fail2ban python3-systemd
  configure_docker_publish_default
  configure_docker_user_chain
  configure_ufw
  configure_fail2ban
  is_dry || verify_firewall
}

ssh_ports() {
  sshd -T 2>/dev/null | awk '$1 == "port" { print $2 }' | sort -u
}

configure_ufw() {
  local port
  run ufw default deny incoming
  run ufw default allow outgoing
  for port in $(ssh_ports); do
    run ufw allow "$port/tcp" comment 'SSH (key + authenticator code)'
  done
  for port in ${SGS_ALLOW_PORTS//,/ }; do
    run ufw allow "$port" comment 'secure-gpu-stack: SGS_ALLOW_PORTS'
  done
  run ufw logging low
  run ufw --force enable
  run ufw reload   # picks up the DOCKER-USER rules in after.rules
}

# Replace our block in a ufw after*.rules file, or append it.
with_docker_user_block() {
  BLOCK=$DOCKER_USER_BLOCK awk '
    /^# >>> secure-gpu-stack/ { print ENVIRON["BLOCK"]; skip = 1; done = 1; next }
    skip { if (/^# <<< secure-gpu-stack/) skip = 0; next }
    { print }
    END { if (!done) print ENVIRON["BLOCK"] }
  ' "$1"
}

configure_docker_user_chain() {
  with_docker_user_block "$UFW_AFTER_RULES" | write_file "$UFW_AFTER_RULES" 0640
  with_docker_user_block "$UFW_AFTER6_RULES" | write_file "$UFW_AFTER6_RULES" 0640
}

configure_docker_publish_default() {
  local desired current=""
  command -v dockerd >/dev/null 2>&1 || { log "Docker not installed; skipping daemon.json"; return 0; }

  # Merge rather than overwrite: Lambda Stack / nvidia-container-toolkit keep the
  # NVIDIA runtime in this file.
  desired=$(python3 - "$DOCKER_DAEMON_JSON" <<'EOF'
import json, os, sys
path = sys.argv[1]
cfg = json.load(open(path)) if os.path.exists(path) and os.path.getsize(path) else {}
cfg["ip"] = "127.0.0.1"
print(json.dumps(cfg, indent=2))
EOF
  )
  [[ -f $DOCKER_DAEMON_JSON ]] && current=$(<"$DOCKER_DAEMON_JSON")
  [[ $desired == "$current" ]] && { ok "Docker already publishes ports on 127.0.0.1 by default"; return 0; }

  printf '%s\n' "$desired" | write_file "$DOCKER_DAEMON_JSON" 0644
  is_dry && return 0

  # Restarting dockerd stops running containers, so never do it under a live workload.
  if [[ -n $(docker ps -q 2>/dev/null) ]]; then
    warn "containers are running; not restarting Docker. New default applies after: sudo systemctl restart docker"
    warn "until then the DOCKER-USER rules still block outside access to published ports"
  else
    systemctl restart docker
    ok "Docker now publishes container ports on 127.0.0.1 unless told otherwise"
  fi
}

configure_fail2ban() {
  write_file "$FAIL2BAN_JAIL" 0644 <<EOF
# Managed by secure-gpu-stack. Local edits will be overwritten.
[DEFAULT]
# Bans show up in 'ufw status' and are enforced before sshd sees the connection.
banaction = ufw
backend = systemd
ignoreip = 127.0.0.1/8 ::1 $SGS_FAIL2BAN_IGNOREIP

[sshd]
enabled = true
# aggressive: also counts failed authenticator codes and connections that give up
# after a rejected key, not only failed passwords.
mode = aggressive
maxretry = 5
findtime = 10m
bantime = 1h
# Repeat offenders get longer bans (1h, 2h, 4h, ... up to a week).
bantime.increment = true
bantime.maxtime = 1w
EOF
  run systemctl enable fail2ban
  run systemctl restart fail2ban
}

verify_firewall() {
  local port
  ufw status | grep -q '^Status: active' || die "ufw is not active"
  ufw status verbose | grep -q 'deny (incoming)' || die "ufw default inbound policy is not deny"
  for port in $(ssh_ports); do
    ufw status | grep -Eq "^$port/tcp +ALLOW" || die "SSH port $port is not allowed; refusing to leave you locked out"
  done
  if iptables -S DOCKER-USER >/dev/null 2>&1; then
    iptables -S DOCKER-USER | grep -q -- '--ctstate NEW -j DROP' || die "DOCKER-USER drop rule not loaded"
  fi
  # fail2ban needs a moment to start its jails.
  for _ in 1 2 3 4 5; do fail2ban-client status sshd >/dev/null 2>&1 && break; sleep 1; done
  fail2ban-client status sshd >/dev/null 2>&1 || die "fail2ban sshd jail is not running"
  ok "inbound: only SSH ($(ssh_ports | paste -sd, -)) is open; containers not reachable from outside; fail2ban active"
}
