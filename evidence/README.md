# Evidence

Everything here was collected on one real Lambda Cloud instance on 2026-10-29: `gpu_1x_a10`
(NVIDIA A10), region us-east-1, stock Lambda Stack image (Ubuntu 22.04.5, driver 580.105.08,
PyTorch 2.7.0). The instance has since been terminated.

- **[report.html](report.html)** / **[report.md](report.md)**: the before/after report (stock image vs final state).
- **[lambda-a10/](lambda-a10/)**: the raw evidence each check in the report was judged from.
- **[media/](media/)**: screen recordings (GIF, plus a PNG of each final frame) and screenshots.

Regenerate the report from the raw files (Python 3 standard library only):

```bash
python3 audit/report.py evidence/lambda-a10/before evidence/lambda-a10/after -o evidence/report
```

## The two audits

Each audit is a folder of raw command output written by [`audit/run_audit.sh`](../audit/run_audit.sh)
on the instance, plus `external.json` from [`audit/external_scan.py`](../audit/external_scan.py)
run from the tester's laptop. `meta.txt` in each folder records the host, kernel, time and code version.

| Folder | Collected (UTC) | Code | Kernel | State | Checks passed |
|---|---|---|---|---|---|
| [`before/`](lambda-a10/before/) | 19:47 | none | 6.8.0-1046-nvidia | Stock Lambda Stack image | 8 / 33 |
| [`after/`](lambda-a10/after/) | 21:30 | `192aba1` | 6.8.0-1064-nvidia | `install.sh` applied, then the maintenance window: held kernel updates installed, rebooted, old kernel removed | **30 / 33** |

[`extra/`](lambda-a10/extra/) holds four files collected at 20:27–21:00 UTC, right after `install.sh` and
before the maintenance window (the state the recordings show): the server's SSH log, an audit-trail sample, a
check of the container-runtime updates, and the upgrade preview that exposed Lambda's repository downgrading the
container toolkit ([finding 8](../docs/FINDINGS.md#the-stock-lambda-stack-image)).

Same conditions for both audits, so the comparison is fair:

- **Demo services.** [`audit/demo_services.sh`](../audit/demo_services.sh) was started before every audit: a
  plain web server on `0.0.0.0:8000` and a Docker container published with `-p 0.0.0.0:8080`. They stand in for
  what researchers start by accident (`jupyter --ip 0.0.0.0`, `docker run -p`). They kept listening in every
  run, so the after-scan shows the firewall blocking them rather than nothing running.
- **Cloud firewall opened to the tester only.** Lambda's default cloud firewall allows TCP 22 and ICMP from anywhere
  ([screenshot](media/lambda-global-firewall-default.png)). For the scans, a ruleset allowed all TCP from the
  tester's IP only ([screenshot](media/lambda-demo-ruleset-my-ip-only.png)), so the external scan measures the
  **host** firewall. The console also states that global rules don't apply in us-south-1, where the host firewall
  is the only one.

## Requirement → evidence

| Claim | Evidence (before → after) |
|---|---|
| A key alone logged in on the stock image | [`before/ssh_login.txt`](lambda-a10/before/ssh_login.txt) ("Authenticated using publickey"), [`before/sshd_T.txt`](lambda-a10/before/sshd_T.txt), [GIF](media/ssh-before-key-alone-logs-in.gif) |
| Every SSH login now needs key **and** authenticator code | [`after/sshd_T.txt`](lambda-a10/after/sshd_T.txt) (`authenticationmethods publickey,keyboard-interactive`), [`after/pam_sshd.txt`](lambda-a10/after/pam_sshd.txt) (`pam_google_authenticator`, no `nullok`), [`after/ssh_users.tsv`](lambda-a10/after/ssh_users.tsv) (effective policy per account) |
| Login sequence on the server: key accepted, then the code | [`extra/ssh_server_log.txt`](lambda-a10/extra/ssh_server_log.txt) (`Partial publickey` → `Accepted keyboard-interactive/pam`) |
| Key + code accepted; wrong code, key alone, and repeat offenders refused | GIFs: [accepted](media/ssh-after-key-and-code.gif), [wrong code](media/ssh-after-wrong-code-denied.gif), [key alone](media/ssh-after-key-alone-denied.gif), [banned](media/ssh-after-fail2ban-ban.gif); [`fail2ban_ban.txt`](lambda-a10/fail2ban_ban.txt) |
| Enrollment: QR for Google/Microsoft Authenticator, confirmed by a code before it takes effect | [`media/enrollment-redacted.png`](media/enrollment-redacted.png), [`install.log`](lambda-a10/install.log) |
| Secrets are root-only, never in the user's home | [`after/totp_store.txt`](lambda-a10/after/totp_store.txt) |
| SSH crypto: 6 fail / 16 warn → 0 fail / 5 warn | [`before/ssh_audit.txt`](lambda-a10/before/ssh_audit.txt) → [`after/ssh_audit.txt`](lambda-a10/after/ssh_audit.txt) |
| Browser IDE gave a root shell with no SSH key or code | [`before/cloud_ide.txt`](lambda-a10/before/cloud_ide.txt), [`before/tunnel_creds.txt`](lambda-a10/before/tunnel_creds.txt) (644), [GIF](media/cloud-ide-before-root-shell.gif), [screenshot](media/before-cloud-ide-root-shell.png) |
| …now closed, and it stays closed after a reboot | [`after/ide_processes.txt`](lambda-a10/after/ide_processes.txt) (masked), [`after/tunnel_creds.txt`](lambda-a10/after/tunnel_creds.txt) (600), [`after/reboot_check.txt`](lambda-a10/after/reboot_check.txt), [screenshot](media/after-cloud-ide-down.png) |
| Ports reachable from outside: 22, 111, 8000, 8080 → 22 | [`before/external.json`](lambda-a10/before/external.json) → [`after/external.json`](lambda-a10/after/external.json), GIFs: [before](media/ports-before-exposed.gif), [after](media/ports-after-blocked.gif) |
| Docker no longer bypasses the host firewall | [`before/iptables_filter.txt`](lambda-a10/before/iptables_filter.txt) → [`after/iptables_filter.txt`](lambda-a10/after/iptables_filter.txt) (`DOCKER-USER` drop), [`after/docker_daemon.json`](lambda-a10/after/docker_daemon.json), [`extra/container_updates_verification.txt`](lambda-a10/extra/container_updates_verification.txt) |
| Security updates: 202 pending → 0; kernel CVEs 404 → 0 | [`before/apt_upgrades.txt`](lambda-a10/before/apt_upgrades.txt) → [`after/apt_upgrades.txt`](lambda-a10/after/apt_upgrades.txt), [`after/maintenance.log`](lambda-a10/after/maintenance.log), [`after/old_kernel_purge.txt`](lambda-a10/after/old_kernel_purge.txt), `*/trivy_summary.json` |
| GPU still works after hardening and after the new kernel | [`after/gpu_smoke.txt`](lambda-a10/after/gpu_smoke.txt) (3/3), [`after/docker_gpu.txt`](lambda-a10/after/docker_gpu.txt), [`after/gpu_smi.txt`](lambda-a10/after/gpu_smi.txt), [GIF](media/gpu-in-container-after.gif) |
| A booby-trapped checkpoint runs code on the stock image, is refused after | [`before/gpu_smoke.txt`](lambda-a10/before/gpu_smoke.txt) (1/3) → [`after/gpu_smoke.txt`](lambda-a10/after/gpu_smoke.txt) (3/3), GIFs: [before](media/pickle-before-runs-code.gif), [after](media/pickle-after-blocked.gif) |
| Hardening survives a real reboot | [`after/reboot_check.txt`](lambda-a10/after/reboot_check.txt) (boot IDs before/after; MFA, firewall, Docker rules, IDE and tunnel masks, auditd). Two items did **not** survive the Lambda reboot; both were fixed afterwards and verified with a real reboot of a fresh VM: `fs.protected_fifos` ([`after/sysctl_after_reboot_before_fix.txt`](lambda-a10/after/sysctl_after_reboot_before_fix.txt) shows 1; fixed in `192aba1` before the final audit, which shows 21/21) and the audit watch on `/home/ubuntu/.ssh` (missing from [`after/auditd.txt`](lambda-a10/after/auditd.txt); fixed in `e69acdf`, not re-run on Lambda) |
| Safe to re-run: second run changes nothing | [`after/install_rerun.log`](lambda-a10/after/install_rerun.log) ("files rewritten by this run: 0") |
| Audit trail attributes root actions to the person who logged in | [`extra/audit_trail_sample.txt`](lambda-a10/extra/audit_trail_sample.txt) (`auid=ubuntu` on sudo actions) |
| What would change, before changing it | [`dry-run.txt`](lambda-a10/dry-run.txt) |

## Recordings

Each GIF has a PNG of its final frame next to it (same name, `.png`) for viewers that can't play animations.
Recorded on the tester's Mac against the instance, with Google Authenticator on the tester's phone providing the
codes; most clips print the date first, then the output.

| Recording | Command (from the Mac) | Shows |
|---|---|---|
| [ssh-before-key-alone-logs-in](media/ssh-before-key-alone-logs-in.gif) | `ssh -i ~/.ssh/lambda_gpu ubuntu@<ip> 'echo "Logged in as $(whoami) on $(hostname) with the key alone"'` | Stock image: key only, straight in |
| [ssh-after-key-and-code](media/ssh-after-key-and-code.gif) | same, after `install.sh` | `Verification code:` prompt, then logged in |
| [ssh-after-wrong-code-denied](media/ssh-after-wrong-code-denied.gif) | `ssh -i ~/.ssh/lambda_gpu ubuntu@<ip> 'echo "should not get here"'` + three wrong codes | `Too many authentication failures` |
| [ssh-after-key-alone-denied](media/ssh-after-key-alone-denied.gif) | `ssh -o BatchMode=yes -i ~/.ssh/lambda_gpu ubuntu@<ip> 'echo "should not get here"'` | Key accepted, no code: `Permission denied (keyboard-interactive)` |
| [ssh-after-fail2ban-ban](media/ssh-after-fail2ban-ban.gif) | same, after repeated wrong codes from the tester's IP | `Connection refused`: fail2ban had banned the tester, along with two real attackers ([`fail2ban_ban.txt`](lambda-a10/fail2ban_ban.txt)) |
| [cloud-ide-before-root-shell](media/cloud-ide-before-root-shell.gif) | Lambda console → Launch (Cloud IDE) → Terminal: `whoami; hostname; sudo -n true && echo "ROOT WITHOUT PASSWORD"` | Root in a browser, no SSH key or code involved |
| [ports-before-exposed](media/ports-before-exposed.gif) / [ports-after-blocked](media/ports-after-blocked.gif) | `curl -m 5 http://<ip>:8000; curl -m 5 http://<ip>:8080; nc -vz -G 3 <ip> 111` | Before: both demo services and rpcbind answer. After: all time out |
| [pickle-before-runs-code](media/pickle-before-runs-code.gif) / [pickle-after-blocked](media/pickle-after-blocked.gif) | `ssh … "bash -lc 'python3 ~/secure-gpu-stack/tests/gpu_smoke.py'"` | Before 1/3: the payload ran. After 3/3: flagged by the scanner and refused by `torch.load` |
| [gpu-in-container-after](media/gpu-in-container-after.gif) | `ssh … 'nvidia-smi --query-gpu=name,driver_version,memory.total --format=csv; sudo docker run --rm --gpus all ubuntu:22.04 nvidia-smi -L'` | GPU works on the host and in a container after hardening |
| [jupyter-via-ssh-tunnel-after](media/jupyter-via-ssh-tunnel-after.gif) | `ssh -L 8888:localhost:8888 …`, Jupyter bound to 127.0.0.1 (2× speed) | The supported way to use Jupyter: behind key + code |

`<ip>` is the instance's public address, 132.145.167.169, now released.

## What was curated or redacted

Nothing here was edited except as listed:

- **The tester's home IP** is replaced by `198.51.100.7` (a reserved documentation address, RFC 5737) in
  `fail2ban_ban.txt` and `extra/ssh_server_log.txt`, and covered in `media/lambda-demo-ruleset-my-ip-only.png`.
- **Enrollment**: the full recording shows a live QR code, secret and emergency codes, so it isn't published.
  [`media/enrollment-redacted.png`](media/enrollment-redacted.png) is one frame of it with those three blurred.
  The installer itself never writes them to `install.log`.
- **Collected already redacted**: the Jupyter token in process arguments (`token=REDACTED`) and the cloudflared
  tunnel ID and credentials path in `before/cloud_ide.txt`. TOTP files are recorded by name and permissions only.
- **Size**: `trivy_summary.json` keeps only the CRITICAL and HIGH rows (the report uses no others; each file
  says so in its `note` field). The raw Trivy JSON (28–47 MB per run) and Lynis's debug log are left out. Both
  are regenerated by `run_audit.sh`.
- **Superseded runs** from earlier in the day (before the last fixes) are left out. So are the local VM test runs.
