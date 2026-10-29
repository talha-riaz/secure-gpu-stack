# Threat model

## System

A single cloud GPU instance (Lambda Cloud, Lambda Stack on Ubuntu 22.04) with a public IPv4 address, used by
a small ML team over SSH. Researchers run training jobs, notebooks and containers. They download models and
datasets from the internet and install Python packages freely. Admins have sudo.

**What an attacker wants from it:**
- the GPU itself (crypto-mining, someone else's training)
- the data, model weights and checkpoints
- the credentials that live on such boxes: Hugging Face and W&B tokens, cloud keys in `~/.aws` or the Azure CLI,
  Git deploy keys, and the SSH keys of everyone who logs in
- a quiet foothold that survives the next login

## Threats and controls

| # | Threat | How it gets in on the stock image | Control | What remains |
|---|---|---|---|---|
| T1 | Internet-wide scanning and SSH brute force | SSH open to the world (Lambda's default rule) | Keys only, no passwords; `MaxAuthTries 3`, `LoginGraceTime 30`; fail2ban bans via ufw (1 h, escalating to a week); `PerSourceMaxStartups 3` for the DHEat flood, which fail2ban can't see | SSH must stay reachable; the cloud firewall can narrow it to known IPs |
| T2 | **Stolen SSH private key**: laptop malware, a key in a repository or CI system, a shared team key | Key alone logs in | **Authenticator code on every new connection** (`AuthenticationMethods publickey,keyboard-interactive`); no `nullok`, so an account without a secret is refused; secrets in a root-only directory, never `~/.google_authenticator`; codes single-use, 3 attempts per 30 s; `LogLevel VERBOSE` records which key was used | A connection that is already authenticated can be reused by its owner's client (see below) |
| T3 | Stolen or lost phone, or a leaked TOTP secret | n/a | The SSH key is still required; emergency codes for a lost phone; `sgs-enroll --force` replaces a secret; enrollment only activates after a valid code, so a bad scan can't lock anyone out | Whoever holds both the key and the phone is in: that is the design |
| T4 | **Side door around SSH**: the browser IDE | Lambda's Cloud IDE: a root-capable terminal reached through an outbound tunnel, invisible to inbound firewalls, guarded only by the Lambda console login | Jupyter and its tunnel stopped and masked (they survive reboots and package upgrades); tunnel credentials made root-only; the audit fails any IDE published through a tunnel | Jupyter still works the safe way: on `127.0.0.1` through `ssh -L`, which needs key + code. `SGS_BROWSER_IDE=keep` turns this off for teams that accept the console login as their gate |
| T5 | **Accidentally exposed services**: Jupyter, TensorBoard, Ray, vLLM or Gradio bound to `0.0.0.0` | ufw inactive; Docker ports public and outside ufw's control | ufw default deny (only SSH open); `DOCKER-USER` drops new outside connections to containers; Docker publishes on `127.0.0.1` unless told otherwise | Ports opened on purpose (`SGS_ALLOW_PORTS`) are the operator's decision |
| T6 | **Malicious model checkpoint** (pickle code execution) from a model hub or a shared drive | `torch.load(..., weights_only=False)` runs the payload | `TORCH_FORCE_WEIGHTS_ONLY_LOAD=1` for every login shell; `sgs-scan-model` (picklescan, pinned and checksum-verified) to check files before loading | Only login shells get the variable (every interactive SSH session does). Commands run as `ssh host 'cmd'`, systemd units, cron jobs and containers don't; other pickle-based formats (joblib, `numpy.load(allow_pickle=True)`) aren't covered |
| T7 | **Malicious container image** escaping to the host | NVIDIA Container Toolkit escapes (CVE-2024-0132, CVE-2025-23266) are fixed in 1.17.8+; the stock 1.18.1 has the fixes, but nothing kept it current | Toolkit updated automatically from NVIDIA's repository, pinned so Lambda's older build can't replace it | Membership in the `docker` group is root-equivalent; `--privileged` containers are the operator's decision |
| T8 | **Known vulnerabilities**: unpatched OS, Docker, kernel | 202 pending security updates; automatic updates off | Daily unattended upgrades for Ubuntu security, Docker, the NVIDIA Container Toolkit and cloudflared; kernel, driver and CUDA held for a planned window (`SGS_PATCH_ALL=1` + reboot), so a training job is never broken mid-run | Between windows, kernel fixes wait. The audit reports how many, and which services need a restart |
| T9 | Local privilege escalation after a foothold (a malicious pip package, a compromised job) | Kernel hardening partial; GPU counters admin-only already | sysctl hardening (kernel pointers, eBPF, kexec, link and FIFO protections, setuid core dumps); AppArmor enforcing; GPU profiling pinned to admins (CVE-2018-6260) | `/dev/nvidia*` is world-writable by driver design |
| T10 | **Covering tracks / persistence** | No audit trail | auditd records changes to SSH, PAM, sudoers, accounts, firewall, Docker, apt sources, cron and units; any read of the MFA secrets; changes to `~/.ssh`; every root command with the person who logged in (`auid`); kernel module loads; clock changes | Logs live on the host, so root can erase them. Off-box shipping is future work |
| T11 | Network tricks: spoofed sources, ICMP redirects, weak SSH crypto | Redirects accepted; NIST curves and SHA-1 MACs offered | Loose reverse-path filtering (strict breaks multi-homed and Docker setups), redirects off, martians logged; ssh-audit's hardening profile with post-quantum key exchange first | Classical fallbacks kept for older clients (5 ssh-audit warnings) |

### Connection reuse (T2)

`MaxSessions 1` stops one authenticated connection from carrying many simultaneous shells. A client that keeps
its connection open (`ControlMaster`/`ControlPersist`) can still open new sessions over it one after another,
without a new code. That reuse happens on the user's own machine, with their own authenticated socket. Anyone
able to use that socket already controls the user's account on the laptop, which is outside what server-side
MFA can defend.

## Assumptions

- **The cloud provider is trusted**: hypervisor, network and the Lambda console. The console account should
  have its own MFA. The console can still terminate or re-image the instance.
- **Signed vendor repositories are trusted.** Eight third-party apt repositories can install code as root; they
  are listed, not removed.
- **The installer runs right after first boot.** Until it does, the stock exposure applies, narrowed by
  Lambda's default cloud rule (SSH and ping only). Baking the stack into a custom image would close that window
  (future work).
- **People have their own accounts.** The admin is enrolled at install time; other users are enrolled with
  `sudo sgs-enroll <user>` and can't log in until they are.

## Out of scope

- Push-approval MFA ("tap Approve") needs a cloud service, such as Duo or Microsoft Entra ID; see the README's
  design decisions.
- Data protection: encryption at rest, secrets management for API tokens, egress filtering against
  exfiltration.
- Isolation between researchers sharing one GPU (MIG, per-user GPU quotas).
- Centralised logging and alerting (SIEM).
- Attacks on the GPU firmware, the hypervisor or the physical host.
