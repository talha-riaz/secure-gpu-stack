# Findings

What the stock Lambda Stack image exposes, and what is still open after hardening. All of it comes from one
`gpu_1x_a10` instance on 2026-10-29. Paths are under [`evidence/lambda-a10/`](../evidence/lambda-a10/).

## The stock Lambda Stack image

Ordered by how directly each one lets someone in.

| # | Finding | Evidence | Fixed by |
|---|---|---|---|
| 1 | **The browser IDE is a root shell with no SSH key and no MFA.** The console's "Launch" button opens JupyterLab, whose terminal runs as `ubuntu` with passwordless sudo. Access is decided by the Lambda console login alone, so the SSH key, any SSH MFA and the host firewall never get a say. | `before/cloud_ide.txt`, [GIF](../evidence/media/cloud-ide-before-root-shell.gif) | `60-gpu`: Jupyter service stopped and masked |
| 2 | **That IDE reaches the internet through an outbound Cloudflare tunnel** (`<id>.lambdaspaces.com` → `127.0.0.1:7000`). Because the connection goes out, no inbound firewall rule (Lambda's or the host's) can see or block it. | `before/cloud_ide.txt`, `before/ide_processes.txt` | `60-gpu`: `cloudflared` and its updater masked |
| 3 | **The tunnel's credentials file is world-readable** (`/etc/cloudflared/jupyter-tunnel.json`, mode 644): any local account or compromised process could run its own connector for that hostname. | `before/tunnel_creds.txt` | `60-gpu`: mode 600 |
| 4 | **SSH accepts a key alone.** No second factor exists, so a key copied from a laptop, CI system or dotfiles repository is full access. | `before/ssh_login.txt`, `before/sshd_T.txt`, [GIF](../evidence/media/ssh-before-key-alone-logs-in.gif) | `10-ssh-mfa` |
| 5 | **No host firewall** (ufw inactive), and services listen on all interfaces: rpcbind on 111 by default, plus whatever a researcher starts. With the cloud firewall opened to the tester, ports 22, 111, 8000 and 8080 all answered from outside. | `before/ufw.txt`, `before/listening.txt`, `before/external.json` | `20-firewall` |
| 6 | **Docker bypasses any host firewall.** Published ports are forwarded before ufw's rules run, and Docker publishes on `0.0.0.0` by default, so `docker run -p 8080:80` is public even with ufw set to deny. | `before/iptables_filter.txt`, `before/docker_daemon.json` | `20-firewall`: `DOCKER-USER` drop + `"ip": "127.0.0.1"` |
| 7 | **202 security updates pending on a freshly launched image**, with automatic updates off. 10 critical/high OS CVEs had fixes available, plus 404 in the kernel (24 critical), and 63 in Docker, containerd and cloudflared, whose fixes were in their own repositories. | `before/apt_upgrades.txt`, `before/unattended.txt`, `before/trivy_summary.json` | `50-updates` |
| 8 | **Lambda pins its own repository at priority 1001**, which lets apt *downgrade* packages. Any `apt upgrade` replaced NVIDIA's patched container toolkit (1.20.1) with Lambda's older build (1.18.1). | `before/apt_preferences.txt`, `extra/apt_upgrades.txt` ("4 downgraded") | `50-updates`: toolkit pinned to NVIDIA's repo at the same priority |
| 9 | **A malicious checkpoint runs code when loaded.** PyTorch 2.7 defaults to `weights_only=True`, but any script that passes `False` (common in older code and tutorials) runs the pickle's payload, and no scanner is installed. | `before/gpu_smoke.txt` (1/3), [GIF](../evidence/media/pickle-before-runs-code.gif) | `70-supply-chain` |
| 10 | **SSH settings and crypto are loose.** 6 attempts per connection, 10 sessions, 120 s to log in, no per-IP limit on unauthenticated connections (the DHEat flood), X11, agent and TCP forwarding on, NIST-curve key exchanges and host key, SHA-1 MACs (ssh-audit: 6 fail, 16 warn). Root may log in with a key, though cloud-init's forced command only prints "log in as ubuntu" and disconnects. | `before/sshd_T.txt`, `before/ssh_audit.txt` | `10-ssh-mfa` |
| 11 | **No audit trail** (auditd not running), SSH logs omit which key logged in, and kernel hardening is partial (13/21 settings: kernel pointers hidden only from unprivileged users, eBPF JIT unhardened, `kexec` allowed, FIFO protection in shared directories off, ICMP redirects accepted and sent, spoofed packets not logged). | `before/auditd.txt`, `before/sysctl.txt` | `40-audit-logging`, `30-kernel` |
| 12 | **8 third-party apt repositories**: Lambda, Mellanox, Docker, NVIDIA, Microsoft (Azure CLI), Cloudflare and two PPAs. All are signed, but each vendor can install code as root. | `before/apt_sources.txt` | Reported, not changed |
| 13 | **Lambda's global firewall rules don't cover us-south-1** (the console says so), so there the host firewall is the only one. Elsewhere the default allows SSH and ICMP from anywhere. | [screenshot](../evidence/media/lambda-global-firewall-default.png) | `20-firewall` (defence in depth) |

Already fine on the stock image: password login off, NVIDIA Container Toolkit 1.18.1 (past the container-escape
fixes in 1.17.8), GPU performance counters restricted to admins, persistent journal, AppArmor enforcing.

## Still open

The 3 of 33 checks that don't pass, and the other numbers that didn't move:

- **ssh-audit: 5 warnings.** Each says only "not post-quantum": `curve25519-sha256` (two names),
  `diffie-hellman-group16/18-sha512` and `diffie-hellman-group-exchange-sha256`. They are kept as fallbacks for
  older clients; the post-quantum `sntrup761x25519` is offered first. Remove them once every client runs
  OpenSSH 9.0 or later.
- **Bundled binaries: 5 CVEs.** These are in the newest builds the vendors publish: issues in the Go standard
  library, `golang.org/x/net` and `moby/go-archive` compiled into NVIDIA's container tools and Docker's buildx
  and compose plugins. They
  clear when the vendors rebuild, and automatic updates will pick that up.
- **Python packages: 45 CVEs** (44 before):
  - 33 are in Lambda's Jupyter environment for the browser IDE (`~/.local/pipx/venvs/jupyter-core`), which no
    longer runs.
  - The rest are inside the Azure CLI, which bundles its own Python. Its update to 2.91.0 fixed 5 but brought 6
    new ones in its newer libraries (3 in PyJWT 2.13, 3 in its own copy of pip's pinned dependencies).

  Neither is auto-upgraded: one belongs to Lambda's IDE and one to Microsoft. If the IDE is ever turned back on,
  `pipx upgrade-all --include-injected` would likely clear most of the first group (not tested).
- **GPU device files are world-writable** (`/dev/nvidia*`, mode 666). That is the NVIDIA driver's design: every
  user and container needs the GPU. Restricting it to a group is possible but breaks unprivileged containers, so
  it is reported, not changed.
- **AppArmor: 34 → 33 profiles enforced.** The missing one is `snap-confine//mount-namespace-capture-helper`, a
  sub-profile snapd stopped loading after its own update (2.76 → 2.77) during the kernel update.
- **685 critical/high CVEs have no fix yet** from Ubuntu or the vendors. Nothing on the host can apply a patch
  that doesn't exist. Automatic updates will install fixes as they ship.
