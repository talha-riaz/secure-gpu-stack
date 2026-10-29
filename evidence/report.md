# Secure GPU Stack: before/after security report

| | Before | After |
|---|---|---|
| Host | 132-145-167-169 | 132-145-167-169 |
| OS | Ubuntu 22.04.5 LTS | Ubuntu 22.04.5 LTS |
| GPU | NVIDIA A10 | NVIDIA A10 |
| Collected | 2026-10-29T19:47:07+00:00 | 2026-10-29T22:48:24+00:00 |
| Secure GPU Stack installed | no | yes |
| Version | unknown | ccdfae7 |
| Results | `before` | `after` |

## Headline

| | Before | After |
|---|---|---|
| **Checks passed** | **8 / 33** | **30 / 33** |
| Key alone enough to log in? | yes | no |
| Ports reachable from the internet | 22, 111, 8000, 8080 | 22 |
| Docker bypasses the firewall? | yes | no |
| Pending security updates | 202 | 0 |
| OS package CVEs | 10 | 0 |
| Kernel CVEs | 404 | 0 |
| Docker & other binary CVEs | 63 | 5 |
| Python package CVEs | 44 | 45 |
| ssh-audit findings | 6 fail, 16 warn | 0 fail, 5 warn |
| Lynis hardening index | 61 / 100 | 70 / 100 |

_CVE counts are unique critical/high CVEs (Trivy) that already have a fixed version. Kernel CVEs are fixed by installing a newer kernel and rebooting._

## SSH access

| Check | Before | After | Why it matters |
|---|---|---|---|
| **Every SSH login needs key + authenticator code**<br><sub>evidence: ssh_users.tsv, sshd_T.txt, pam_sshd.txt</sub> | ❌ key alone is enough<br><sub>no authenticator step in PAM; key-only accounts: root, ubuntu</sub> | ✅ all 1 account(s)<br><sub>ubuntu</sub> | A stolen or leaked SSH key alone must not be enough to get in. |
| **Code step can't be skipped (no nullok, no password fallback)**<br><sub>evidence: pam_sshd.txt</sub> | – no code step configured | ✅ no nullok, no password step | nullok silently lets un-enrolled users in; a leftover password step weakens the second factor. |
| **Every SSH account enrolled for the code**<br><sub>evidence: ssh_users.tsv</sub> | – no code step configured | ✅ 1 of 1 | An account with keys but no secret can't log in at all, so this finds forgotten users. |
| **Authenticator secrets readable by root only**<br><sub>evidence: totp_store.txt, ssh_users.tsv</sub> | – no code step configured | ✅ root-only (0700 directory) | A secret the user can read can be copied into another app, cloning the second factor. |
| **Password login disabled**<br><sub>evidence: sshd_T.txt, pam_sshd.txt</sub> | ✅ off | ✅ off | Passwords are what internet-wide bots guess; keys can't be guessed. |
| **Root can't log in over SSH**<br><sub>evidence: sshd_T.txt</sub> | ⚠️ without-password<br><sub>root can still log in with a key</sub> | ✅ no | Admins log in as themselves and use sudo, so every action is tied to a person. |
| **Session limits and forwarding locked down**<br><sub>evidence: sshd_T.txt</sub> | ⚠️ 1/8 hardened<br><sub>maxauthtries=6 (want ≤ 3); maxsessions=10 (want 1); logingracetime=120 (want ≤ 30s); persourcemaxstartups=none (want ≤ 3); x11forwarding=yes (want no); allowagentforwarding=yes (want no); allowtcpforwarding=yes (want local/no)</sub> | ✅ 8/8 hardened | Limits guessing per connection, one code per session, and stops agent/X11 hijacking. |
| **SSH cryptography (ssh-audit)**<br><sub>evidence: ssh_audit.json, ssh_audit.txt</sub> | ❌ 6 fail, 16 warn<br><sub>fail: ecdh-sha2-nistp256, ecdh-sha2-nistp384, ecdh-sha2-nistp521, ecdsa-sha2-nistp256, hmac-sha1-etm@openssh.com, hmac-sha1; warn: curve25519-sha256, curve25519-sha256@libssh.org, ecdh-sha2-nistp256, ecdh-sha2-nistp384, ecdh-sha2-nistp521, diffie-hellman-group-exchange-sha256 (+10 more)</sub> | ⚠️ 0 fail, 5 warn<br><sub>warn: curve25519-sha256, curve25519-sha256@libssh.org, diffie-hellman-group16-sha512, diffie-hellman-group18-sha512, diffie-hellman-group-exchange-sha256 (only 'not post-quantum'; kept as fallbacks for older clients, post-quantum is offered first)</sub> | Weak key exchanges, ciphers or MACs let attackers downgrade or break the connection. |

## Network exposure

| Check | Before | After | Why it matters |
|---|---|---|---|
| **Ports reachable from the internet (external scan)**<br><sub>evidence: external.json</sub> | ❌ 22, 111, 8000, 8080<br><sub>22 SSH; 111 rpcbind (NFS portmapper); 8000 vLLM / FastAPI / http.server; 8080 HTTP alt / containers</sub> | ✅ 22<br><sub>22 SSH</sub> | What an attacker actually sees, after the cloud firewall and the host firewall. |
| **SSH offers no password method (external view)**<br><sub>evidence: external.json</sub> | ✅ publickey | ✅ publickey | Confirms from outside that sshd never asks a stranger for a password. |
| **Host firewall denies inbound by default**<br><sub>evidence: ufw.txt</sub> | ❌ inactive | ✅ deny by default; open: 22/tcp | Anything that starts listening later (Jupyter, a debug server) stays unreachable. |
| **Docker can't bypass the firewall**<br><sub>evidence: iptables_filter.txt, docker_version.txt</sub> | ❌ published ports bypass the firewall | ✅ outside traffic to containers dropped | Docker routes published ports around ufw; without DOCKER-USER rules `docker run -p` is public. |
| **Docker publishes on localhost by default**<br><sub>evidence: docker_daemon.json</sub> | ⚠️ all interfaces<br><sub>daemon.json has no "ip": "127.0.0.1"</sub> | ✅ 127.0.0.1 | `docker run -p 8888:8888` should not mean 'open to the internet'. |
| **Brute-force IPs banned (fail2ban)**<br><sub>evidence: fail2ban.txt</sub> | ❌ not running | ✅ sshd jail active<br><sub>banned now: 0, total: 0</sub> | Cuts off scanners after a few failures instead of letting them try forever. |
| **Services listening on all interfaces (host view)**<br><sub>evidence: listening.txt</sub> | ℹ️ 4 TCP port(s)<br><sub>22 sshd, 111 rpcbind, 8000 python3, 8080 docker-proxy</sub> | ℹ️ 4 TCP port(s)<br><sub>22 sshd, 111 rpcbind, 8000 python3, 8080 docker-proxy</sub> | Listening is not the same as reachable, but each one is exposure the firewall must cover. |

## Patching

| Check | Before | After | Why it matters |
|---|---|---|---|
| **No pending security updates**<br><sub>evidence: apt_upgrades.txt</sub> | ❌ 202 pending<br><sub>not held: bsdutils, coreutils, diffutils, gzip, ncurses-bin, libperl5.34 (+196 more); 240 updates pending in total</sub> | ✅ 0 pending<br><sub>0 updates pending in total</sub> | Each pending security update is a published, fixable vulnerability still on the box. |
| **Security updates install automatically**<br><sub>evidence: unattended.txt</sub> | ❌ off<br><sub>unattended-upgrades installed, periodic run disabled</sub> | ✅ on | Fixes published after launch get applied without anyone remembering to. |
| **NVIDIA driver and CUDA pinned**<br><sub>evidence: gpu_packages.txt, apt_holds.txt, apt_preferences.txt</sub> | ⚠️ 21 of 21 can change<br><sub>can be upgraded automatically: lambda-stack-cuda, libnccl-dev, libnccl2, libnvidia-cfg1-580-server, libnvidia-compute-580-server, libnvidia-extra-580-server (+15 more)</sub> | ✅ held from automatic upgrades<br><sub>21 NVIDIA/CUDA packages</sub> | An unattended upgrade must not swap the GPU driver under a running training job. |
| **No reboot pending**<br><sub>evidence: reboot_required.txt</sub> | ✅ none | ✅ none | Patched kernels and libraries only take effect after a reboot. |

## GPU & ML tooling

| Check | Before | After | Why it matters |
|---|---|---|---|
| **GPU performance counters restricted to admins**<br><sub>evidence: nvidia_params.txt</sub> | ✅ admin only | ✅ admin only | Unprivileged GPU profiling enables side-channel attacks on other users' workloads (CVE-2018-6260). |
| **No browser IDE bypassing SSH**<br><sub>evidence: ide_processes.txt, listening.txt</sub> | ❌ published via outbound tunnel (cloudflared)<br><sub>inbound firewalls can't see an outbound tunnel; /home/ubuntu/.local/pipx/venvs/jupyter-core/bin/python /home/ubuntu/.local/pipx/venvs/jupyter-core/bin/jupyter-lab --config /home/ubuntu/.jupyter/jupyter_config.py</sub> | ✅ none running | A web Jupyter/IDE terminal is a way in that never asks for the SSH key or the code. |
| **Tunnel credentials readable by root only**<br><sub>evidence: tunnel_creds.txt</sub> | ❌ world/group readable<br><sub>/etc/cloudflared/jupyter-tunnel.json (644)</sub> | ✅ 0600 | Readable tunnel credentials let any local process run its own connector and intercept the tunnel. |
| **NVIDIA Container Toolkit has the container-escape fixes**<br><sub>evidence: gpu_packages.txt</sub> | ✅ 1.18.1-0lambda0.22.04.1 | ✅ 1.20.1-1 | Before 1.17.8 a malicious container image can take over the host (CVE-2024-0132, CVE-2025-23266). It comes from NVIDIA's repository, so OS scanners miss it. |
| **GPU device permissions**<br><sub>evidence: gpu_devices.txt</sub> | ℹ️ 5 world-writable of 7<br><sub>crw-rw-rw- ×5, cr-------- ×1, cr--r--r-- ×1</sub> | ℹ️ 5 world-writable of 7<br><sub>crw-rw-rw- ×5, cr-------- ×1, cr--r--r-- ×1</sub> | World-writable /dev/nvidia* lets any local account use (and probe) the GPU. |
| **GPU and driver**<br><sub>evidence: gpu_smi.txt</sub> | ℹ️ NVIDIA A10, 580.105.08, 23028 MiB | ℹ️ NVIDIA A10, 580.105.08, 23028 MiB | Context for the comparison. |

## ML supply chain

| Check | Before | After | Why it matters |
|---|---|---|---|
| **Pickled checkpoints can't run code on load (torch weights-only)**<br><sub>evidence: ml_defaults.txt, torch_version.txt</sub> | ⚠️ torch default only<br><sub>torch 2.7.0 defaults to weights_only=True, but any script can pass False</sub> | ✅ forced for all logins<br><sub>torch 2.7.0</sub> | A .pt/.bin checkpoint is a pickle: loading an untrusted one runs whatever code it carries. |
| **Model scanner available (sgs-scan-model)**<br><sub>evidence: model_scanner.txt</sub> | ⚠️ none | ✅ /usr/local/bin/sgs-scan-model | Lets researchers check downloaded checkpoints for code before anyone loads them. |
| **Package repositories are signature-verified**<br><sub>evidence: apt_sources.txt</sub> | ✅ all signed<br><sub>8 third-party: http://archive.lambdalabs.com/ubuntu, http://linux.mellanox.com/public/repo/doca/2.9.3/ubuntu22.04/x86_64, http://ppa.launchpadcontent.net/deadsnakes/ppa/ubuntu, https://download.docker.com/linux/ubuntu, https://nvidia.github.io/libnvidia-container/stable/deb/amd64, https://packages.microsoft.com/repos/azure-cli/, https://pkg.cloudflare.com/cloudflared, https://ppa.launchpadcontent.net/flexiondotorg/nvtop/ubuntu</sub> | ✅ all signed<br><sub>8 third-party: http://archive.lambdalabs.com/ubuntu, http://linux.mellanox.com/public/repo/doca/2.9.3/ubuntu22.04/x86_64, http://ppa.launchpadcontent.net/deadsnakes/ppa/ubuntu, https://download.docker.com/linux/ubuntu, https://nvidia.github.io/libnvidia-container/stable/deb/amd64, https://packages.microsoft.com/repos/azure-cli/, https://pkg.cloudflare.com/cloudflared, https://ppa.launchpadcontent.net/flexiondotorg/nvtop/ubuntu</sub> | A repository marked trusted=yes lets anyone on the network path substitute packages. |

## Kernel & OS

| Check | Before | After | Why it matters |
|---|---|---|---|
| **Kernel hardening settings (sysctl)**<br><sub>evidence: sysctl.txt</sub> | ⚠️ 13/21 hardened<br><sub>kernel.kptr_restrict=1, net.core.bpf_jit_harden=0, kernel.kexec_load_disabled=0, fs.protected_fifos=1, net.ipv4.conf.default.accept_redirects=1, net.ipv6.conf.all.accept_redirects=1, net.ipv4.conf.all.send_redirects=1, net.ipv4.conf.all.log_martians=0</sub> | ✅ 21/21 hardened | Hides kernel addresses, restricts eBPF and core dumps, ignores spoofed/redirected packets. |
| **AppArmor enforcing**<br><sub>evidence: apparmor.txt</sub> | ✅ 34 profiles enforced | ✅ 33 profiles enforced | Confines programs (Docker containers included) to what they need. |

## Logging & detection

| Check | Before | After | Why it matters |
|---|---|---|---|
| **Audit trail of security-relevant actions (auditd)**<br><sub>evidence: auditd.txt</sub> | ❌ not running | ✅ 23 rules | Records who changed SSH/PAM/sudo config, touched secrets or keys, or ran root commands. |
| **Logs survive a reboot (persistent journal)**<br><sub>evidence: journald.txt</sub> | ✅ persistent | ✅ persistent | Evidence of an intrusion shouldn't vanish with a restart. |
| **SSH logs record which key logged in**<br><sub>evidence: sshd_T.txt</sub> | ⚠️ INFO | ✅ VERBOSE | LogLevel VERBOSE logs the key fingerprint, so a login can be traced to a specific key. |

## Vulnerabilities

| Check | Before | After | Why it matters |
|---|---|---|---|
| **OS packages: fixable critical/high CVEs (Trivy)**<br><sub>evidence: trivy_summary.json</sub> | ⚠️ 10 fixable critical/high + 404 kernel<br><sub>0 critical among them; 685 more critical/high have no fix yet; 404 kernel CVEs fixed in a newer kernel (reboot + NVIDIA modules: maintenance window); most affected: snapd (3), libssl3 (2), openssl (2), rsync (2), gir1.2-packagekitglib-1.0 (1)</sub> | ✅ 0 fixable critical/high<br><sub>0 critical among them; 685 more critical/high have no fix yet</sub> | Known vulnerabilities in installed Ubuntu packages that a patch would remove. |
| **Bundled binaries (Docker, containerd, cloudflared, ...): fixable critical/high CVEs (Trivy)**<br><sub>evidence: trivy_summary.json</sub> | ❌ 63 fixable critical/high<br><sub>2 critical among them; 2 more critical/high have no fix yet; most affected: stdlib (166), golang.org/x/crypto (41), golang.org/x/net (36), google.golang.org/grpc (16), github.com/containerd/containerd/v2 (15)</sub> | ⚠️ 5 fixable critical/high<br><sub>0 critical among them; 2 more critical/high have no fix yet; most affected: stdlib (16), golang.org/x/net (2), github.com/moby/go-archive (1)</sub> | Go and other compiled tools from third-party repos; the container runtime is where escapes live. |
| **Python packages: fixable critical/high CVEs (Trivy)**<br><sub>evidence: trivy_summary.json</sub> | ❌ 44 fixable critical/high<br><sub>4 critical among them; 0 more critical/high have no fix yet; most affected: urllib3 (8), tornado (7), PyJWT (6), jupyterlab (6), mistune (6)</sub> | ❌ 45 fixable critical/high<br><sub>4 critical among them; 0 more critical/high have no fix yet; most affected: urllib3 (8), PyJWT (7), tornado (7), jupyterlab (6), mistune (6)</sub> | ML and research libraries; upgrading them can break experiments, so they are triaged, not auto-applied. |
| **Lynis hardening index**<br><sub>evidence: lynis-report.dat</sub> | ℹ️ 61 / 100<br><sub>1 warnings, 51 suggestions</sub> | ℹ️ 70 / 100<br><sub>0 warnings, 43 suggestions</sub> | Broad, third-party heuristic score (0-100) across hundreds of tests. |

## Notes

- Each check lists the raw files it read; they are in the results directories named above.
- The external scan reflects the cloud firewall and the host firewall together. A demo ruleset opened the scanned ports to the scanning IP only, so the host firewall is what's being measured; with the cloud provider's default rules a stranger would see only SSH.
- Both hosts ran audit/demo_services.sh first: a plain service on :8000 and a Docker container on :8080, stand-ins for what researchers commonly start (jupyter --ip 0.0.0.0, docker run -p). Any other open port is the image's own.
- Nothing was weakened before the 'before' audit: every setting measured there is the image default. The audit installs its scanners (Lynis, ssh-audit, Trivy) and refreshes apt package lists; it changes no security setting.
- Counts that depend on the day (pending updates, CVEs) drift as the image and vulnerability databases are updated; the security posture itself reproduces.
- Vulnerability counts are unique CVE IDs rated critical or high by Trivy that already have a fixed version. Python package CVEs are reported for triage: upgrading ML libraries can break research code, so the stack does not auto-upgrade them. Container runtime and other third-party binaries are auto-updated.
- Lynis is a broad heuristic; it is shown for context, not used as the measure of success.

_Generated 2026-10-29 18:49 by `audit/report.py`._
