#!/usr/bin/env python3
"""Turn run_audit.sh results into a security report.

    python3 audit/report.py RESULTS_DIR                            # one host, printed
    python3 audit/report.py BEFORE_DIR AFTER_DIR -o audit/report   # report.md + report.html

Every result is computed from the raw files run_audit.sh saved (plus external.json
from external_scan.py), and each check names the files it read, so any number in
the report can be traced back to its evidence. Stdlib only.
"""

import argparse
import csv
import datetime
import html
import json
import os
import re
import sys
from collections import Counter

PASS, WARN, FAIL, INFO, NA = "pass", "warn", "fail", "info", "n/a"
ICON = {PASS: "✅", WARN: "⚠️", FAIL: "❌", INFO: "ℹ️", NA: "–"}
SCORED = (PASS, WARN, FAIL)
HIGH = ("CRITICAL", "HIGH")


class Result:
    def __init__(self, status, value, detail="", num=None):
        self.status, self.value, self.detail, self.num = status, value, detail, num


class Check:
    def __init__(self, fn, area, title, why, evidence):
        self.id, self.fn = fn.__name__, fn
        self.area, self.title, self.why, self.evidence = area, title, why, evidence

    def run(self, host):
        try:
            return self.fn(host)
        except Exception as exc:  # a malformed file must not sink the whole report
            return Result(NA, "could not evaluate", "%s: %s" % (type(exc).__name__, exc))


CHECKS = []


def check(area, title, why, evidence):
    def register(fn):
        CHECKS.append(Check(fn, area, title, why, evidence))
        return fn
    return register


class Host:
    """Read-only view of one run_audit.sh results directory."""

    def __init__(self, path):
        self.path = path.rstrip("/")
        if not os.path.isfile(os.path.join(self.path, "meta.txt")):
            raise SystemExit("%s: not a run_audit.sh results directory (no meta.txt)" % path)
        self.meta = dict(l.split("=", 1) for l in self.lines("meta.txt") if "=" in l)
        self._cache = {}

    @property
    def name(self):
        return os.path.basename(self.path)

    def text(self, name):
        p = os.path.join(self.path, name)
        if not os.path.isfile(p):
            return None
        with open(p, errors="replace") as fh:
            return fh.read()

    def lines(self, name):
        t = self.text(name)
        return t.splitlines() if t else []

    def json(self, name):
        t = self.text(name)
        if not t or "{" not in t:
            return None
        return json.loads(t[t.index("{"):])  # captured output may start with a warning line

    def cached(self, key, build):
        if key not in self._cache:
            self._cache[key] = build()
        return self._cache[key]

    def sshd(self, key):
        def build():
            values = {}
            for line in self.lines("sshd_T.txt"):
                k, _, v = line.partition(" ")
                values.setdefault(k.lower(), v.strip())
            return values
        return self.cached("sshd", build).get(key)

    def ssh_users(self):
        t = self.text("ssh_users.tsv")
        if t is None:
            return None
        return list(csv.DictReader(t.splitlines(), delimiter="\t"))

    def pam(self):
        """(TOTP step present, nullok on it, password step still active) for sshd."""
        def build():
            active = [l.strip() for l in self.lines("pam_sshd.txt") if l.strip() and not l.lstrip().startswith("#")]
            totp = [l for l in active if "pam_google_authenticator.so" in l and l.split()[0] == "auth"]
            password = any(l == "@include common-auth" or ("pam_unix.so" in l and l.split()[0] == "auth") for l in active)
            return bool(totp), any("nullok" in l for l in totp), password
        return self.cached("pam", build)

    def login_accounts(self):
        """Accounts holding SSH keys that sshd would actually let log in."""
        users = self.ssh_users() or []
        root_ok = self.sshd("permitrootlogin") != "no"
        return [u for u in users if u["user"] != "root" or root_ok]

    def sysctl(self):
        def build():
            values = {}
            for line in self.lines("sysctl.txt"):
                k, sep, v = line.partition(" = ")
                if sep:
                    values[k.strip()] = v.strip()
            return values
        return self.cached("sysctl", build)

    def vulns(self):
        def build():
            d = self.json("trivy_summary.json")
            return None if d is None else [dict(zip(d["fields"], row)) for row in d["rows"]]
        return self.cached("vulns", build)


def is_auto_update_held(host, pkg):
    """True if unattended-upgrades' Package-Blacklist (regexes from the start of the name) skips pkg."""
    patterns = host.cached("uu_blacklist", lambda: re.findall(
        r'^Unattended-Upgrade::Package-Blacklist:: "(.+)";$', host.text("unattended.txt") or "", re.M))
    return any(re.match(p, pkg) for p in patterns)


def needs_key_and_code(methods):
    """True if every AuthenticationMethods alternative includes key AND keyboard-interactive."""
    if not methods or methods.strip() == "any":
        return False
    for alternative in methods.split():
        steps = {s.split(":")[0] for s in alternative.split(",")}
        if not {"publickey", "keyboard-interactive"} <= steps:
            return False
    return True


def listeners(host):
    """TCP sockets listening on non-loopback addresses: [(port, process, pid)]."""
    found = []
    for line in host.lines("listening.txt"):
        f = line.split()
        if len(f) < 5 or f[0] != "tcp":
            continue
        addr, _, port = f[4].rpartition(":")
        if addr.startswith("127.") or addr.startswith("[::1]") or "%lo" in addr:
            continue
        m = re.search(r'\(\("([^"]+)",pid=(\d+)', line)
        found.append((port, m.group(1) if m else "?", m.group(2) if m else ""))
    return sorted(set(found), key=lambda x: int(x[0]) if x[0].isdigit() else 0)


def short_list(items, limit=6):
    items = list(items)
    more = len(items) - limit
    return ", ".join(items[:limit]) + (" (+%d more)" % more if more > 0 else "")


# --------------------------------------------------------------------------- SSH

@check("SSH access", "Every SSH login needs key + authenticator code",
       "A stolen or leaked SSH key alone must not be enough to get in.",
       ["ssh_users.tsv", "sshd_T.txt", "pam_sshd.txt"])
def ssh_mfa(h):
    if h.ssh_users() is None:
        return Result(NA, "no data")
    accounts = h.login_accounts()
    if not accounts:
        return Result(INFO, "no accounts with SSH keys")
    names = [u["user"] for u in accounts]
    totp, _, _ = h.pam()
    if not totp:
        return Result(FAIL, "key alone is enough", "no authenticator step in PAM; key-only accounts: " + ", ".join(names), 0)
    key_only = [u["user"] for u in accounts if not needs_key_and_code(u["auth_methods"])]
    if key_only:
        return Result(FAIL, "%d of %d accounts skip the code" % (len(key_only), len(names)),
                      "key alone lets in: " + ", ".join(key_only), 0)
    return Result(PASS, "all %d account(s)" % len(names), ", ".join(names), 1)


@check("SSH access", "Code step can't be skipped (no nullok, no password fallback)",
       "nullok silently lets un-enrolled users in; a leftover password step weakens the second factor.",
       ["pam_sshd.txt"])
def ssh_pam_strict(h):
    if h.text("pam_sshd.txt") is None:
        return Result(NA, "no data")
    totp, nullok, password = h.pam()
    if not totp:
        return Result(NA, "no code step configured")
    problems = (["nullok lets accounts without a secret skip the code"] if nullok else []) + \
               (["password step still active"] if password else [])
    if problems:
        return Result(FAIL, "bypassable", "; ".join(problems))
    return Result(PASS, "no nullok, no password step")


@check("SSH access", "Every SSH account enrolled for the code",
       "An account with keys but no secret can't log in at all, so this finds forgotten users.",
       ["ssh_users.tsv"])
def ssh_enrolled(h):
    if not h.pam()[0]:
        return Result(NA, "no code step configured")
    accounts = h.login_accounts()
    missing = [u["user"] for u in accounts if u["totp_secret"] != "yes"]
    if missing:
        return Result(WARN, "%d not enrolled" % len(missing), "locked out until `sgs-enroll`: " + ", ".join(missing))
    return Result(PASS, "%d of %d" % (len(accounts), len(accounts)))


@check("SSH access", "Authenticator secrets readable by root only",
       "A secret the user can read can be copied into another app, cloning the second factor.",
       ["totp_store.txt", "ssh_users.tsv"])
def ssh_secret_storage(h):
    if not h.pam()[0]:
        return Result(NA, "no code step configured")
    in_home = [u["user"] for u in h.ssh_users() or [] if u["home_ga_file"] == "yes"]
    exposed = []
    for line in h.lines("totp_store.txt"):
        f = line.split()
        if len(f) == 3 and f[0].isdigit():
            mode, owner, path = int(f[0], 8), f[1], f[2]
            if owner != "root:root" or mode & 0o077:
                exposed.append("%s (%s %s)" % (path, f[0], owner))
    if in_home:
        exposed.insert(0, "~/.google_authenticator for " + ", ".join(in_home))
    if exposed:
        return Result(FAIL, "exposed", "; ".join(exposed))
    return Result(PASS, "root-only (0700 directory)")


@check("SSH access", "Password login disabled",
       "Passwords are what internet-wide bots guess; keys can't be guessed.",
       ["sshd_T.txt", "pam_sshd.txt"])
def ssh_passwords(h):
    if not h.sshd("passwordauthentication"):
        return Result(NA, "no data")
    if h.sshd("passwordauthentication") == "yes":
        return Result(FAIL, "password login on")
    if h.sshd("kbdinteractiveauthentication") == "yes" and h.pam()[2]:
        return Result(FAIL, "passwords accepted via keyboard-interactive")
    return Result(PASS, "off")


@check("SSH access", "Root can't log in over SSH",
       "Admins log in as themselves and use sudo, so every action is tied to a person.",
       ["sshd_T.txt"])
def ssh_root(h):
    v = h.sshd("permitrootlogin")
    if not v:
        return Result(NA, "no data")
    if v == "no":
        return Result(PASS, "no")
    if v in ("prohibit-password", "without-password", "forced-commands-only"):
        return Result(WARN, v, "root can still log in with a key")
    return Result(FAIL, v)


SSH_LIMITS = [
    ("maxauthtries", "≤ 3", lambda v: int(v) <= 3),
    ("maxsessions", "1", lambda v: int(v) <= 1),
    ("logingracetime", "≤ 30s", lambda v: 0 < int(v) <= 30),
    ("persourcemaxstartups", "≤ 3", lambda v: v != "none" and int(v) <= 3),
    ("x11forwarding", "no", lambda v: v == "no"),
    ("allowagentforwarding", "no", lambda v: v == "no"),
    ("allowtcpforwarding", "local/no", lambda v: v in ("local", "no")),
    ("permituserenvironment", "no", lambda v: v == "no"),
]


@check("SSH access", "Session limits and forwarding locked down",
       "Limits guessing per connection, one code per session, and stops agent/X11 hijacking.",
       ["sshd_T.txt"])
def ssh_limits(h):
    if not h.sshd("maxsessions"):
        return Result(NA, "no data")
    bad = []
    for key, want, ok in SSH_LIMITS:
        v = h.sshd(key)
        try:
            good = v is not None and ok(v)
        except ValueError:
            good = False
        if not good:
            bad.append("%s=%s (want %s)" % (key, v, want))
    n = len(SSH_LIMITS)
    return Result(PASS if not bad else WARN, "%d/%d hardened" % (n - len(bad), n), "; ".join(bad), n - len(bad))


@check("SSH access", "SSH cryptography (ssh-audit)",
       "Weak key exchanges, ciphers or MACs let attackers downgrade or break the connection.",
       ["ssh_audit.json", "ssh_audit.txt"])
def ssh_crypto(h):
    d = h.json("ssh_audit.json")
    if not d:
        return Result(NA, "not scanned")
    fails, warns, pq_only = [], [], True
    for kind in ("kex", "key", "enc", "mac"):
        for alg in d.get(kind) or []:
            notes = alg.get("notes") or {}
            if notes.get("fail"):
                fails.append(alg["algorithm"])
            if notes.get("warn"):
                warns.append(alg["algorithm"])
                pq_only &= all("post-quantum" in w for w in notes["warn"])
    detail = ""
    if fails:
        detail = "fail: " + short_list(fails)
    if warns:
        detail += ("; " if detail else "") + "warn: " + short_list(warns)
        if pq_only and not fails:
            detail += " (only 'not post-quantum'; kept as fallbacks for older clients, post-quantum is offered first)"
    status = FAIL if fails else WARN if warns else PASS
    return Result(status, "%d fail, %d warn" % (len(fails), len(warns)), detail, len(fails) + len(warns))


# ------------------------------------------------------------------- network

@check("Network exposure", "Ports reachable from the internet (external scan)",
       "What an attacker actually sees, after the cloud firewall and the host firewall.",
       ["external.json"])
def net_external(h):
    d = h.json("external.json")
    if not d:
        return Result(NA, "not scanned", "run audit/external_scan.py from outside the host")
    open_ports = [(p, v["service"]) for p, v in d["ports"].items() if v["state"] == "open"]
    ssh = str(h.sshd("port") or 22)
    extra = [p for p, _ in open_ports if p != ssh]
    value = ", ".join(p for p, _ in open_ports) or "none"
    detail = "; ".join("%s %s" % (p, s) for p, s in open_ports)
    return Result(FAIL if extra else PASS, value, detail, len(open_ports))


@check("Network exposure", "SSH offers no password method (external view)",
       "Confirms from outside that sshd never asks a stranger for a password.",
       ["external.json"])
def net_external_ssh(h):
    d = h.json("external.json")
    if not d:
        return Result(NA, "not scanned")
    methods = d.get("ssh_auth_methods")
    if not methods:
        return Result(NA, "unknown", d.get("ssh_probe_output", ""))
    return Result(FAIL if "password" in methods.split(",") else PASS, methods)


@check("Network exposure", "Host firewall denies inbound by default",
       "Anything that starts listening later (Jupyter, a debug server) stays unreachable.",
       ["ufw.txt"])
def net_firewall(h):
    t = h.text("ufw.txt")
    if t is None or "Status:" not in t:
        return Result(FAIL, "no host firewall")
    if "Status: active" not in t:
        return Result(FAIL, "inactive")
    if not re.search(r"Default: (deny|reject) \(incoming\)", t):
        return Result(FAIL, "active, but inbound allowed by default")
    allowed = []
    for line in t.splitlines():
        cols = re.split(r"\s{2,}", line.strip())
        if len(cols) >= 3 and cols[1].startswith("ALLOW"):
            target = cols[0].replace(" (v6)", "")
            if target not in allowed:
                allowed.append(target)
    ssh_ports = {str(h.sshd("port") or 22), "OpenSSH"}
    extra = [a for a in allowed if a.split("/")[0] not in ssh_ports]
    value = "deny by default; open: " + (", ".join(allowed) or "nothing")
    return Result(WARN if extra else PASS, value, ("also open: " + ", ".join(extra)) if extra else "")


@check("Network exposure", "Docker can't bypass the firewall",
       "Docker routes published ports around ufw; without DOCKER-USER rules `docker run -p` is public.",
       ["iptables_filter.txt", "docker_version.txt"])
def net_docker_bypass(h):
    if h.text("docker_version.txt") is None:
        return Result(NA, "Docker not installed")
    rules = [l for l in h.lines("iptables_filter.txt") if l.startswith("-A DOCKER-USER")]
    if any("--ctstate NEW" in l and re.search(r"-j (DROP|REJECT)", l) for l in rules):
        return Result(PASS, "outside traffic to containers dropped")
    return Result(FAIL, "published ports bypass the firewall")


@check("Network exposure", "Docker publishes on localhost by default",
       "`docker run -p 8888:8888` should not mean 'open to the internet'.",
       ["docker_daemon.json"])
def net_docker_default(h):
    if h.text("docker_version.txt") is None:
        return Result(NA, "Docker not installed")
    ip = (h.json("docker_daemon.json") or {}).get("ip")
    return Result(PASS, "127.0.0.1") if ip == "127.0.0.1" else Result(WARN, "all interfaces", "daemon.json has no \"ip\": \"127.0.0.1\"")


@check("Network exposure", "Brute-force IPs banned (fail2ban)",
       "Cuts off scanners after a few failures instead of letting them try forever.",
       ["fail2ban.txt"])
def net_fail2ban(h):
    t = h.text("fail2ban.txt") or ""
    if "Status for the jail: sshd" not in t:
        return Result(FAIL, "not running")
    now = re.search(r"Currently banned:\s*(\d+)", t)
    total = re.search(r"Total banned:\s*(\d+)", t)
    return Result(PASS, "sshd jail active", "banned now: %s, total: %s" % (now.group(1) if now else "?", total.group(1) if total else "?"))


@check("Network exposure", "Services listening on all interfaces (host view)",
       "Listening is not the same as reachable, but each one is exposure the firewall must cover.",
       ["listening.txt"])
def net_listeners(h):
    if h.text("listening.txt") is None:
        return Result(NA, "no data")
    found = listeners(h)
    return Result(INFO, "%d TCP port(s)" % len(found), ", ".join("%s %s" % (p, proc) for p, proc, _ in found), len(found))


# ------------------------------------------------------------------ patching

@check("Patching", "No pending security updates",
       "Each pending security update is a published, fixable vulnerability still on the box.",
       ["apt_upgrades.txt"])
def pkg_security_updates(h):
    lines = [l for l in h.lines("apt_upgrades.txt") if l.startswith("Inst ")]
    if h.text("apt_upgrades.txt") is None:
        return Result(NA, "no data")
    sec = [l.split()[1] for l in lines if "-security" in l]
    held = [p for p in sec if is_auto_update_held(h, p)]
    other = [p for p in sec if p not in held]
    detail = "%d updates pending in total" % len(lines)
    if held:
        detail = "%d held for the kernel/GPU maintenance window (%s); %s" % (len(held), short_list(held, 3), detail)
    if other:
        detail = "not held: %s; %s" % (short_list(other), detail)
    status = FAIL if other else WARN if held else PASS
    return Result(status, "%d pending" % len(other) + (" + %d held" % len(held) if held else ""), detail, len(sec))


@check("Patching", "Security updates install automatically",
       "Fixes published after launch get applied without anyone remembering to.",
       ["unattended.txt"])
def pkg_auto_updates(h):
    t = h.text("unattended.txt")
    if t is None:
        return Result(NA, "no data")
    installed = "install ok installed" in t
    enabled = 'APT::Periodic::Unattended-Upgrade "1"' in t
    if installed and enabled:
        return Result(PASS, "on")
    return Result(FAIL, "off", "unattended-upgrades %s, periodic run %s" %
                  ("installed" if installed else "missing", "enabled" if enabled else "disabled"))


@check("Patching", "NVIDIA driver and CUDA pinned",
       "An unattended upgrade must not swap the GPU driver under a running training job.",
       ["gpu_packages.txt", "apt_holds.txt", "apt_preferences.txt"])
def pkg_gpu_pinned(h):
    # lambda-repository only carries the repository signing key: not part of the GPU stack.
    pkgs = [l.split("\t")[0] for l in h.lines("gpu_packages.txt") if "\t" in l and not l.startswith("lambda-repository")]
    if not pkgs:
        return Result(NA, "no NVIDIA/CUDA packages")
    holds = set(h.lines("apt_holds.txt"))
    prefs = h.text("apt_preferences.txt") or ""
    if re.search(r"Package:.*(nvidia|cuda)", prefs):
        return Result(PASS, "pinned (apt preferences)")
    loose = [p for p in pkgs if p not in holds and not is_auto_update_held(h, p)]
    if not loose:
        return Result(PASS, "held from automatic upgrades", "%d NVIDIA/CUDA packages" % len(pkgs))
    return Result(WARN, "%d of %d can change" % (len(loose), len(pkgs)),
                  "can be upgraded automatically: " + short_list(loose))


@check("Patching", "No reboot pending",
       "Patched kernels and libraries only take effect after a reboot.",
       ["reboot_required.txt"])
def pkg_reboot(h):
    lines = h.lines("reboot_required.txt")
    if not lines:
        return Result(NA, "no data")
    if lines == ["none"]:
        return Result(PASS, "none")
    return Result(WARN, "reboot needed", "for " + short_list(lines))


# ----------------------------------------------------------------------- GPU

@check("GPU & ML tooling", "GPU performance counters restricted to admins",
       "Unprivileged GPU profiling enables side-channel attacks on other users' workloads (CVE-2018-6260).",
       ["nvidia_params.txt"])
def gpu_profiling(h):
    t = h.text("nvidia_params.txt")
    if t is None:
        return Result(NA, "no NVIDIA driver")
    m = re.search(r"RmProfilingAdminOnly:\s*(\d+)", t)
    if not m:
        return Result(NA, "parameter not reported")
    return Result(PASS, "admin only") if m.group(1) == "1" else Result(FAIL, "any user")


@check("GPU & ML tooling", "No browser IDE bypassing SSH",
       "A web Jupyter/IDE terminal is a way in that never asks for the SSH key or the code.",
       ["ide_processes.txt", "listening.txt"])
def gpu_browser_ide(h):
    if h.text("ide_processes.txt") is None:
        return Result(NA, "no data")
    procs = [l for l in h.lines("ide_processes.txt") if re.match(r"^\S+\s+\d+\s", l)]
    ide = [l for l in procs if re.search(r"jupyter|notebook|code-server", l, re.I)]
    tunnels = [l for l in procs if re.search(r"cloudflared", l, re.I)]
    if not ide:
        return Result(PASS, "none running") if not tunnels else \
            Result(WARN, "IDE off, tunnel still running", "cloudflared would publish whatever listens on its target port")
    pids = {l.split()[1] for l in ide}
    listening = {pid for _, _, pid in listeners(h)}
    public = ["%s (%s)" % (p, proc) for p, proc, pid in listeners(h) if pid in pids]
    ide.sort(key=lambda l: l.split()[1] not in listening)  # the one serving the IDE first
    summary = "; ".join(" ".join(l.split()[2:6]) for l in ide[:2])
    if public:
        return Result(FAIL, "listening on " + ", ".join(public), summary)
    if tunnels:
        return Result(FAIL, "published via outbound tunnel (cloudflared)",
                      "inbound firewalls can't see an outbound tunnel; " + summary)
    loopback = [l for l in h.lines("listening.txt") if any("pid=%s," % p in l for p in pids)]
    if loopback and all(re.search(r"\s(127\.[\d.]+|\[::1\]):\d+\s", l) for l in loopback):
        return Result(PASS, "localhost only, no tunnel", "reachable only through ssh -L (key + code): " + summary)
    return Result(WARN, "%d IDE process(es) running" % len(ide), summary + "; check how it is reached")


@check("GPU & ML tooling", "Tunnel credentials readable by root only",
       "Readable tunnel credentials let any local process run its own connector and intercept the tunnel.",
       ["tunnel_creds.txt"])
def tunnel_creds(h):
    lines = [l for l in h.lines("tunnel_creds.txt") if l.strip() and l.strip() != "none"]
    if not h.text("tunnel_creds.txt"):
        return Result(NA, "no data")
    creds = [l.split() for l in lines if l.endswith(".json") and len(l.split()) == 3]
    if not creds:
        return Result(NA, "no tunnel credentials")
    exposed = ["%s (%s)" % (p, m) for m, _, p in creds if int(m, 8) & 0o077]
    return Result(FAIL, "world/group readable", ", ".join(exposed)) if exposed else Result(PASS, "0600")


TOOLKIT_MIN = (1, 17, 8)


@check("GPU & ML tooling", "NVIDIA Container Toolkit has the container-escape fixes",
       "Before 1.17.8 a malicious container image can take over the host (CVE-2024-0132, CVE-2025-23266). "
       "It comes from NVIDIA's repository, so OS scanners miss it.",
       ["gpu_packages.txt"])
def gpu_container_toolkit(h):
    version = next((l.split("\t")[1] for l in h.lines("gpu_packages.txt")
                    if l.startswith("nvidia-container-toolkit\t")), None)
    if not version:
        return Result(NA, "not installed")
    upstream = tuple(int(x) for x in re.findall(r"\d+", version.split("-")[0])[:3])
    if upstream >= TOOLKIT_MIN:
        return Result(PASS, version)
    return Result(FAIL, version, "older than %s: container escape to the host" % ".".join(map(str, TOOLKIT_MIN)))


@check("GPU & ML tooling", "GPU device permissions",
       "World-writable /dev/nvidia* lets any local account use (and probe) the GPU.",
       ["gpu_devices.txt"])
def gpu_devices(h):
    devs = [l for l in h.lines("gpu_devices.txt") if l.startswith("c")]
    if not devs:
        return Result(NA, "no NVIDIA devices")
    modes = Counter(l.split()[0] for l in devs)
    world = sum(n for m, n in modes.items() if m[7:9] == "rw")
    return Result(INFO, "%d world-writable of %d" % (world, len(devs)), ", ".join("%s ×%d" % mn for mn in modes.items()))


@check("GPU & ML tooling", "GPU and driver",
       "Context for the comparison.",
       ["gpu_smi.txt"])
def gpu_driver(h):
    t = (h.text("gpu_smi.txt") or "").strip()
    return Result(INFO, t.splitlines()[0]) if t else Result(NA, "no NVIDIA driver")


# --------------------------------------------------------- ML supply chain

@check("ML supply chain", "Pickled checkpoints can't run code on load (torch weights-only)",
       "A .pt/.bin checkpoint is a pickle: loading an untrusted one runs whatever code it carries.",
       ["ml_defaults.txt", "torch_version.txt"])
def ml_weights_only(h):
    forced = "TORCH_FORCE_WEIGHTS_ONLY_LOAD=1" in (h.text("ml_defaults.txt") or "")
    torch = (h.text("torch_version.txt") or "").strip()
    version = torch if re.match(r"^\d+\.\d+", torch) else None
    if forced:
        return Result(PASS, "forced for all logins", "torch %s" % version if version else "PyTorch not installed")
    if not version:
        return Result(WARN, "not configured", "PyTorch not installed yet; nothing enforces safe loading when it is")
    major_minor = tuple(int(x) for x in version.split(".")[:2])
    if major_minor >= (2, 6):
        return Result(WARN, "torch default only", "torch %s defaults to weights_only=True, but any script can pass False" % version)
    return Result(FAIL, "torch.load runs pickled code", "torch %s defaults to weights_only=False" % version)


@check("ML supply chain", "Model scanner available (sgs-scan-model)",
       "Lets researchers check downloaded checkpoints for code before anyone loads them.",
       ["model_scanner.txt"])
def ml_scanner(h):
    t = (h.text("model_scanner.txt") or "").strip()
    if not t:
        return Result(NA, "no data")
    return Result(WARN, "none") if t == "none" else Result(PASS, t)


@check("ML supply chain", "Package repositories are signature-verified",
       "A repository marked trusted=yes lets anyone on the network path substitute packages.",
       ["apt_sources.txt"])
def pkg_sources_signed(h):
    lines = h.lines("apt_sources.txt")
    if not lines:
        return Result(NA, "no data")
    insecure = [l for l in lines if re.search(r"trusted=yes|allow-insecure=yes|allow-weak=yes|^Trusted:\s*yes", l, re.I)]
    urls = sorted({u for l in lines for u in re.findall(r"https?://[^\s\]]+", l)})
    third_party = [u for u in urls if not re.search(r"(archive|security|ports)\.ubuntu\.com|esm\.ubuntu\.com", u)]
    detail = ("third-party: " + short_list(third_party, 4)) if third_party else "Ubuntu archives only"
    if insecure:
        return Result(FAIL, "%d unverified" % len(insecure), "; ".join(insecure[:3]))
    return Result(PASS, "all signed", detail)


# -------------------------------------------------------------------- kernel

SYSCTL_WANT = {
    "kernel.kptr_restrict": ("2",),
    "kernel.dmesg_restrict": ("1",),
    "kernel.unprivileged_bpf_disabled": ("1", "2"),
    "net.core.bpf_jit_harden": ("2",),
    "kernel.kexec_load_disabled": ("1",),
    "kernel.yama.ptrace_scope": ("1", "2", "3"),
    "fs.protected_hardlinks": ("1",),
    "fs.protected_symlinks": ("1",),
    "fs.protected_fifos": ("2",),
    "fs.protected_regular": ("2",),
    "fs.suid_dumpable": ("0",),
    "net.ipv4.conf.all.rp_filter": ("1", "2"),
    "net.ipv4.conf.all.accept_redirects": ("0",),
    "net.ipv4.conf.default.accept_redirects": ("0",),
    "net.ipv6.conf.all.accept_redirects": ("0",),
    "net.ipv4.conf.all.send_redirects": ("0",),
    "net.ipv4.conf.all.accept_source_route": ("0",),
    "net.ipv6.conf.all.accept_source_route": ("0",),
    "net.ipv4.conf.all.log_martians": ("1",),
    "net.ipv4.tcp_syncookies": ("1",),
    "net.ipv4.icmp_echo_ignore_broadcasts": ("1",),
}


@check("Kernel & OS", "Kernel hardening settings (sysctl)",
       "Hides kernel addresses, restricts eBPF and core dumps, ignores spoofed/redirected packets.",
       ["sysctl.txt"])
def kernel_sysctl(h):
    values = h.sysctl()
    if not values:
        return Result(NA, "no data")
    bad = ["%s=%s" % (k, values.get(k, "missing")) for k, ok in SYSCTL_WANT.items() if values.get(k) not in ok]
    n = len(SYSCTL_WANT)
    return Result(PASS if not bad else WARN, "%d/%d hardened" % (n - len(bad), n), short_list(bad, 8), n - len(bad))


@check("Kernel & OS", "AppArmor enforcing",
       "Confines programs (Docker containers included) to what they need.",
       ["apparmor.txt"])
def kernel_apparmor(h):
    t = h.text("apparmor.txt")
    if t is None:
        return Result(NA, "no data")
    m = re.search(r"(\d+) profiles are in enforce mode", t)
    if "apparmor module is loaded" in t and m and int(m.group(1)) > 0:
        return Result(PASS, "%s profiles enforced" % m.group(1))
    return Result(FAIL, "not enforcing")


# ------------------------------------------------------------------- logging

@check("Logging & detection", "Audit trail of security-relevant actions (auditd)",
       "Records who changed SSH/PAM/sudo config, touched secrets or keys, or ran root commands.",
       ["auditd.txt"])
def log_auditd(h):
    lines = h.lines("auditd.txt")
    if not lines or lines[0] != "active":
        return Result(FAIL, "not running")
    rules = [l for l in lines if l.startswith("-")]
    return Result(PASS if len(rules) >= 5 else WARN, "%d rules" % len(rules))


@check("Logging & detection", "Logs survive a reboot (persistent journal)",
       "Evidence of an intrusion shouldn't vanish with a restart.",
       ["journald.txt"])
def log_journal(h):
    t = h.text("journald.txt")
    if t is None:
        return Result(NA, "no data")
    if t.startswith("d") or re.search(r"Storage\s*=\s*persistent", t):
        return Result(PASS, "persistent")
    return Result(WARN, "volatile")


@check("Logging & detection", "SSH logs record which key logged in",
       "LogLevel VERBOSE logs the key fingerprint, so a login can be traced to a specific key.",
       ["sshd_T.txt"])
def log_ssh_verbose(h):
    v = h.sshd("loglevel")
    if not v:
        return Result(NA, "no data")
    return Result(PASS, v) if v in ("VERBOSE", "DEBUG", "DEBUG1", "DEBUG2", "DEBUG3") else Result(WARN, v)


# ----------------------------------------------------------- vulnerabilities

def vuln_result(h, cls):
    rows = h.vulns()
    if rows is None:
        return Result(NA, "not scanned")
    rows = [r for r in rows if r["class"] == cls and r["severity"] in HIGH]
    # Kernel fixes need a new kernel + reboot and, on a GPU box, matching NVIDIA modules:
    # a maintenance-window decision, so they are counted apart from everything else.
    kernel = {r["id"] for r in rows if r["status"] == "fixed" and r["pkg"].startswith("linux-")}
    fixed = [r for r in rows if r["status"] == "fixed" and not r["pkg"].startswith("linux-")]
    fixable = {r["id"] for r in fixed}
    crit = {r["id"] for r in fixed if r["severity"] == "CRITICAL"}
    unfixed = {r["id"] for r in rows if r["status"] != "fixed"}
    top = Counter(r["pkg"] for r in fixed).most_common(5)
    detail = "%d critical among them; %d more critical/high have no fix yet" % (len(crit), len(unfixed))
    if kernel:
        detail += "; %d kernel CVEs fixed in a newer kernel (reboot + NVIDIA modules: maintenance window)" % len(kernel)
    if top:
        detail += "; most affected: " + ", ".join("%s (%d)" % pt for pt in top)
    value = "%d fixable critical/high" % len(fixable) + (" + %d kernel" % len(kernel) if kernel else "")
    status = FAIL if crit else WARN if fixable or kernel else PASS
    return Result(status, value, detail, len(fixable))


@check("Vulnerabilities", "OS packages: fixable critical/high CVEs (Trivy)",
       "Known vulnerabilities in installed Ubuntu packages that a patch would remove.",
       ["trivy_summary.json"])
def vuln_os(h):
    return vuln_result(h, "os-pkgs")


@check("Vulnerabilities", "Python and other libraries: fixable critical/high CVEs (Trivy)",
       "ML libraries and bundled binaries; upgrades here can break research code, so they are triaged, not auto-applied.",
       ["trivy_summary.json"])
def vuln_lang(h):
    return vuln_result(h, "lang-pkgs")


@check("Vulnerabilities", "Lynis hardening index",
       "Broad, third-party heuristic score (0-100) across hundreds of tests.",
       ["lynis-report.dat"])
def lynis_index(h):
    lines = h.lines("lynis-report.dat")
    idx = next((l.split("=", 1)[1] for l in lines if l.startswith("hardening_index=")), None)
    if idx is None:
        return Result(NA, "not scanned")
    warnings = sum(l.startswith("warning[]=") for l in lines)
    suggestions = sum(l.startswith("suggestion[]=") for l in lines)
    return Result(INFO, "%s / 100" % idx, "%d warnings, %d suggestions" % (warnings, suggestions), int(idx))


# -------------------------------------------------------------------- output

HEADLINE = [
    ("ssh_mfa", "Key alone enough to log in?", lambda r: "no" if r.status == PASS else r.value),
    ("net_external", "Ports reachable from the internet", lambda r: r.value),
    ("net_docker_bypass", "Docker bypasses the firewall?", lambda r: "no" if r.status == PASS else "yes" if r.status == FAIL else r.value),
    ("pkg_security_updates", "Pending security updates", lambda r: str(r.num) if r.num is not None else r.value),
    ("vuln_os", "Fixable critical/high CVEs (OS)", lambda r: r.value.replace(" fixable critical/high", "")),
    ("vuln_lang", "Fixable critical/high CVEs (libraries)", lambda r: str(r.num) if r.num is not None else r.value),
    ("ssh_crypto", "ssh-audit findings", lambda r: r.value),
    ("lynis_index", "Lynis hardening index", lambda r: r.value),
]

NOTES = [
    "Each check lists the raw files it read; they are in the results directories named above.",
    "The external scan reflects the cloud firewall and the host firewall together. A demo ruleset opened the scanned "
    "ports to the scanning IP only, so the host firewall is what's being measured; with the cloud provider's default "
    "rules a stranger would see only SSH.",
    "Both hosts ran audit/demo_services.sh first: a plain service on :8000 and a Docker container on :8080, stand-ins "
    "for what researchers commonly start (jupyter --ip 0.0.0.0, docker run -p). Any other open port is the image's own.",
    "Nothing was weakened before the 'before' audit: every setting measured there is the image default. The audit "
    "installs its scanners (Lynis, ssh-audit, Trivy) and refreshes apt package lists; it changes no security setting.",
    "Counts that depend on the day (pending updates, CVEs) drift as the image and vulnerability databases are updated; "
    "the security posture itself reproduces.",
    "Vulnerability counts are unique CVE IDs rated critical or high by Trivy that already have a fixed version. "
    "Library CVEs are reported for triage: upgrading ML libraries can break research code, so the stack does not auto-upgrade them.",
    "Lynis is a broad heuristic; it is shown for context, not used as the measure of success.",
]


def evaluate(host):
    return {c.id: c.run(host) for c in CHECKS}


def scorecard(results, other=None):
    """(passed, total). With `other`, a check scored on either host counts on both, so a
    control that is simply absent on one host (n/a there) counts as not passed."""
    ids = [cid for cid, r in results.items()
           if r.status in SCORED or (other is not None and other[cid].status in SCORED)]
    return sum(results[cid].status == PASS for cid in ids), len(ids)


def host_label(host):
    m = host.meta
    return "%s (%s)" % (m.get("label", host.name), m.get("hostname", "?"))


def print_single(host):
    results = evaluate(host)
    passed, total = scorecard(results)
    print("%s  |  %s  |  %s  |  %s" % (host_label(host), host.meta.get("os", "?"), host.meta.get("gpu", "?"),
                                        host.meta.get("collected_at", "?")))
    print("Checks passed: %d/%d\n" % (passed, total))
    area = None
    for c in CHECKS:
        if c.area != area:
            area = c.area
            print("== %s" % area)
        r = results[c.id]
        print("  %s %-62s %s" % (ICON[r.status], c.title[:62], r.value))
        if r.detail and r.status in (FAIL, WARN):
            print("       %s" % r.detail[:160])


def md_escape(text):
    return text.replace("|", "\\|").replace("\n", " ")


def cell(r):
    return "%s %s" % (ICON[r.status], md_escape(r.value))


def build_markdown(before, after, rb, ra):
    pb, tb = scorecard(rb, ra)
    pa, ta = scorecard(ra, rb)
    out = ["# Secure GPU Stack: before/after security report", ""]
    out += ["| | Before | After |", "|---|---|---|"]
    for key, label in (("hostname", "Host"), ("os", "OS"), ("gpu", "GPU"), ("collected_at", "Collected"),
                       ("sgs_installed", "Secure GPU Stack installed"), ("sgs_version", "Version")):
        out.append("| %s | %s | %s |" % (label, md_escape(before.meta.get(key, "?")), md_escape(after.meta.get(key, "?"))))
    out.append("| Results | `%s` | `%s` |" % (before.name, after.name))
    out += ["", "## Headline", "", "| | Before | After |", "|---|---|---|",
            "| **Checks passed** | **%d / %d** | **%d / %d** |" % (pb, tb, pa, ta)]
    for cid, label, fmt in HEADLINE:
        out.append("| %s | %s | %s |" % (label, md_escape(fmt(rb[cid])), md_escape(fmt(ra[cid]))))
    area = None
    for c in CHECKS:
        if c.area != area:
            area = c.area
            out += ["", "## %s" % area, "", "| Check | Before | After | Why it matters |", "|---|---|---|---|"]
        b, a = rb[c.id], ra[c.id]
        title = "**%s**<br><sub>evidence: %s</sub>" % (md_escape(c.title), ", ".join(c.evidence))
        after_cell = cell(a) + ("<br><sub>%s</sub>" % md_escape(a.detail) if a.detail and a.status != PASS else "")
        before_cell = cell(b) + ("<br><sub>%s</sub>" % md_escape(b.detail) if b.detail and b.status in (FAIL, WARN) else "")
        out.append("| %s | %s | %s | %s |" % (title, before_cell, after_cell, md_escape(c.why)))
    out += ["", "## Notes", ""] + ["- " + n for n in NOTES]
    out += ["", "_Generated %s by `audit/report.py`._" % datetime.datetime.now().strftime("%Y-%m-%d %H:%M"), ""]
    return "\n".join(out)


CSS = """
:root { --bg:#fbfaf7; --fg:#1d1d1b; --muted:#6b6a64; --line:#e3e1d9; --card:#ffffff;
        --pass:#1f7a3d; --pass-bg:#e5f3e9; --fail:#b42318; --fail-bg:#fbe9e7;
        --warn:#8a5a00; --warn-bg:#fdf3dc; --info:#36588a; --info-bg:#e8eef8; --na:#8b8a84; }
@media (prefers-color-scheme: dark) {
  :root { --bg:#161614; --fg:#ecebe6; --muted:#a3a29b; --line:#2f2e2a; --card:#1e1e1b;
          --pass:#6fcf8e; --pass-bg:#173322; --fail:#ff8a7a; --fail-bg:#3a1a16;
          --warn:#f2c46b; --warn-bg:#352a12; --info:#9bb8e8; --info-bg:#1b2638; --na:#77766f; }
}
* { box-sizing:border-box; }
body { margin:0; background:var(--bg); color:var(--fg);
       font:15px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
main { max-width:1100px; margin:0 auto; padding:32px 20px 64px; }
h1 { font-size:26px; margin:0 0 4px; } h2 { font-size:18px; margin:36px 0 10px; }
.sub { color:var(--muted); margin:0 0 24px; }
.tiles { display:grid; grid-template-columns:repeat(auto-fit, minmax(220px, 1fr)); gap:12px; }
.tile { background:var(--card); border:1px solid var(--line); border-radius:10px; padding:14px 16px; }
.tile .k { color:var(--muted); font-size:13px; }
.tile .v { font-size:20px; font-weight:600; margin-top:4px; font-variant-numeric:tabular-nums; }
.tile .v .arrow { color:var(--muted); font-weight:400; padding:0 6px; }
.scroll { overflow-x:auto; }
table { width:100%; border-collapse:collapse; background:var(--card); border:1px solid var(--line);
        border-radius:10px; overflow:hidden; font-size:14px; }
th, td { text-align:left; vertical-align:top; padding:10px 12px; border-bottom:1px solid var(--line); }
th { font-size:12px; text-transform:uppercase; letter-spacing:.04em; color:var(--muted); font-weight:600; }
tr:last-child td { border-bottom:none; }
td.title { width:30%; font-weight:600; } td.title small, td small { display:block; font-weight:400; color:var(--muted); margin-top:3px; }
td.why { color:var(--muted); width:28%; }
.badge { display:inline-block; padding:2px 8px; border-radius:999px; font-size:13px; font-weight:600; white-space:nowrap; }
.pass { color:var(--pass); background:var(--pass-bg); } .fail { color:var(--fail); background:var(--fail-bg); }
.warn { color:var(--warn); background:var(--warn-bg); } .info { color:var(--info); background:var(--info-bg); }
.na { color:var(--na); background:transparent; border:1px solid var(--line); }
ul.notes { color:var(--muted); padding-left:18px; } code { font-size:13px; }
"""


def badge(r):
    word = {PASS: "pass", WARN: "warn", FAIL: "fail", INFO: "info", NA: "n/a"}[r.status]
    css = "na" if r.status == NA else r.status
    return '<span class="badge %s">%s</span> %s' % (css, word, html.escape(r.value))


def build_html(before, after, rb, ra):
    e = html.escape
    pb, tb = scorecard(rb, ra)
    pa, ta = scorecard(ra, rb)
    p = ["<!doctype html><html lang='en'><head><meta charset='utf-8'>",
         "<meta name='viewport' content='width=device-width, initial-scale=1'>",
         "<title>Secure GPU Stack report</title><style>%s</style></head><body><main>" % CSS,
         "<h1>Secure GPU Stack: before/after security report</h1>",
         "<p class='sub'>%s &rarr; %s &middot; %s &middot; %s</p>" % (
             e(host_label(before)), e(host_label(after)), e(after.meta.get("os", "")), e(after.meta.get("gpu", ""))),
         "<div class='tiles'>",
         "<div class='tile'><div class='k'>Checks passed</div><div class='v'>%d/%d<span class='arrow'>&rarr;</span>%d/%d</div></div>"
         % (pb, tb, pa, ta)]
    for cid, label, fmt in HEADLINE:
        p.append("<div class='tile'><div class='k'>%s</div><div class='v'>%s<span class='arrow'>&rarr;</span>%s</div></div>"
                 % (e(label), e(fmt(rb[cid])), e(fmt(ra[cid]))))
    p.append("</div>")
    area = None
    for c in CHECKS:
        if c.area != area:
            if area is not None:
                p.append("</tbody></table></div>")
            area = c.area
            p += ["<h2>%s</h2><div class='scroll'><table><thead><tr><th>Check</th><th>Before</th><th>After</th>"
                  "<th>Why it matters</th></tr></thead><tbody>" % e(area)]
        b, a = rb[c.id], ra[c.id]
        bd = "<small>%s</small>" % e(b.detail) if b.detail and b.status in (FAIL, WARN) else ""
        ad = "<small>%s</small>" % e(a.detail) if a.detail and a.status != PASS else ""
        p.append("<tr><td class='title'>%s<small>evidence: %s</small></td><td>%s%s</td><td>%s%s</td><td class='why'>%s</td></tr>"
                 % (e(c.title), e(", ".join(c.evidence)), badge(b), bd, badge(a), ad, e(c.why)))
    p.append("</tbody></table></div>")
    p.append("<h2>Machines compared</h2><div class='scroll'><table><thead><tr><th></th><th>Before</th><th>After</th></tr></thead><tbody>")
    for key, label in (("hostname", "Host"), ("os", "OS"), ("kernel", "Kernel"), ("gpu", "GPU"), ("collected_at", "Collected"),
                       ("sgs_installed", "Secure GPU Stack installed"), ("sgs_version", "Version")):
        p.append("<tr><td class='title'>%s</td><td>%s</td><td>%s</td></tr>" % (e(label), e(before.meta.get(key, "?")), e(after.meta.get(key, "?"))))
    p.append("<tr><td class='title'>Results</td><td><code>%s</code></td><td><code>%s</code></td></tr></tbody></table></div>"
             % (e(before.name), e(after.name)))
    p.append("<h2>Notes</h2><ul class='notes'>%s</ul>" % "".join("<li>%s</li>" % e(n) for n in NOTES))
    p.append("<p class='sub'>Generated %s by <code>audit/report.py</code>.</p></main></body></html>"
             % datetime.datetime.now().strftime("%Y-%m-%d %H:%M"))
    return "\n".join(p)


def main():
    parser = argparse.ArgumentParser(description="Build a security report from run_audit.sh results.")
    parser.add_argument("results", nargs="+", help="one results dir (print) or BEFORE AFTER (compare)")
    parser.add_argument("-o", "--out", help="output path prefix for the comparison (writes .md and .html)")
    args = parser.parse_args()

    hosts = [Host(p) for p in args.results]
    if len(hosts) == 1:
        print_single(hosts[0])
        return 0
    if len(hosts) != 2:
        parser.error("give one results directory, or exactly two (before, after)")
    before, after = hosts
    rb, ra = evaluate(before), evaluate(after)
    md, page = build_markdown(before, after, rb, ra), build_html(before, after, rb, ra)
    if not args.out:
        print(md)
        return 0
    for ext, content in ((".md", md), (".html", page)):
        with open(args.out + ext, "w") as fh:
            fh.write(content)
        print("wrote %s%s" % (args.out, ext))
    return 0


if __name__ == "__main__":
    sys.exit(main())
