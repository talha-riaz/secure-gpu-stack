#!/usr/bin/env python3
"""Probe a host from the outside: which ports answer, and how SSH lets you in.

    python3 audit/external_scan.py 203.0.113.7 --out audit/results/before-xyz/external.json

Run it from your laptop, not from the server: it measures what the internet can
reach, which is what the host firewall and the cloud firewall together allow.
The default port list covers SSH plus services ML boxes commonly expose by
accident (Jupyter, TensorBoard, Gradio, Ray, MLflow, vLLM, Ollama, ...).
Stdlib only.
"""

import argparse
import concurrent.futures
import datetime
import json
import re
import socket
import subprocess
import sys

DEFAULT_PORTS = {
    22: "SSH",
    80: "HTTP",
    111: "rpcbind (NFS portmapper)",
    443: "HTTPS",
    3000: "Grafana / dev servers",
    5000: "MLflow / Flask",
    6006: "TensorBoard",
    7860: "Gradio",
    8000: "vLLM / FastAPI / http.server",
    8080: "HTTP alt / containers",
    8265: "Ray dashboard",
    8501: "Streamlit",
    8787: "Dask dashboard",
    8888: "Jupyter",
    9090: "Prometheus",
    11434: "Ollama",
}


def probe(host, port, timeout):
    """open: something answered. closed: host refused (RST). filtered: no answer."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return "open"
    except ConnectionRefusedError:
        return "closed"
    except (socket.timeout, TimeoutError):
        return "filtered"
    except OSError as exc:
        return "error: %s" % exc.strerror


def ssh_auth_methods(host, user, port):
    """Ask sshd which methods it offers before any credential is presented."""
    cmd = [
        "ssh", "-p", str(port), "-o", "BatchMode=yes", "-o", "ConnectTimeout=8",
        "-o", "PreferredAuthentications=none", "-o", "PubkeyAuthentication=no",
        "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
        "-o", "LogLevel=ERROR", "%s@%s" % (user, host), "true",
    ]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=20).stderr
    except (OSError, subprocess.TimeoutExpired) as exc:
        return None, str(exc)
    match = re.search(r"Permission denied \(([^)]*)\)", out)
    return (match.group(1) if match else None), out.strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("host")
    parser.add_argument("--ports", help="comma-separated list (default: SSH + common ML services)")
    parser.add_argument("--ssh-user", default="ubuntu")
    parser.add_argument("--ssh-port", type=int, default=22)
    parser.add_argument("--timeout", type=float, default=3.0)
    parser.add_argument("--out", help="write JSON here (e.g. into the run_audit results dir)")
    args = parser.parse_args()

    if args.ports:
        ports = {int(p): DEFAULT_PORTS.get(int(p), "") for p in args.ports.split(",")}
    else:
        ports = dict(DEFAULT_PORTS)

    # One probe first: on a fresh LAN/NAT address, a burst of parallel connects can
    # all fail with "no route to host" while the neighbour (ARP) entry is resolved.
    probe(args.host, args.ssh_port, args.timeout)
    with concurrent.futures.ThreadPoolExecutor(max_workers=32) as pool:
        states = dict(zip(ports, pool.map(lambda p: probe(args.host, p, args.timeout), ports)))
    methods, raw = ssh_auth_methods(args.host, args.ssh_user, args.ssh_port)

    result = {
        "host": args.host,
        "scanned_at": datetime.datetime.now().astimezone().isoformat(timespec="seconds"),
        "ports": {str(p): {"state": states[p], "service": ports[p]} for p in sorted(ports)},
        "ssh_auth_methods": methods,
        "ssh_probe_output": raw,
    }

    for p in sorted(ports):
        print("%5d  %-9s %s" % (p, states[p], ports[p]))
    print("SSH methods offered before login: %s" % (methods or "unknown (%s)" % raw))
    if args.out:
        with open(args.out, "w") as fh:
            json.dump(result, fh, indent=2)
        print("saved %s" % args.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
