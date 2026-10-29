#!/usr/bin/env python3
"""After hardening: the GPU still works, and booby-trapped checkpoints don't.

    bash -lc 'python3 tests/gpu_smoke.py'     # -l: a login shell picks up /etc/profile.d

1. CUDA: PyTorch sees the GPU and runs a matrix multiply on it.
2. Model scanner: sgs-scan-model flags a checkpoint whose pickle carries code.
3. Safe loading: torch.load refuses that checkpoint, even when a script passes
   weights_only=False, so its payload never runs.

The payload is harmless: it would only create a marker file in a temp directory,
which is how the test tells whether it ran.
"""

import os
import pickle
import shutil
import subprocess
import sys
import tempfile

results = []


def report(name, ok, detail):
    results.append(ok)
    print("%s %-48s %s" % ("PASS" if ok else "FAIL", name, detail))


class Payload:
    """Unpickling this calls os.system: what a malicious checkpoint would do."""

    def __init__(self, marker):
        self.marker = marker

    def __reduce__(self):
        return (os.system, ("touch %s" % self.marker,))


def main():
    try:
        import torch
    except ImportError:
        torch = None

    if torch is None:
        report("CUDA available to PyTorch", False, "PyTorch not installed")
    elif not torch.cuda.is_available():
        report("CUDA available to PyTorch", False, "torch %s sees no GPU" % torch.__version__)
    else:
        a = torch.randn(2048, 2048, device="cuda")
        value = (a @ a).sum().item()
        report("CUDA available to PyTorch", True, "torch %s on %s (matmul ok, sum=%.1f)"
               % (torch.__version__, torch.cuda.get_device_name(0), value))

    tmp = tempfile.mkdtemp(prefix="sgs-smoke-")
    marker = os.path.join(tmp, "payload-ran")
    checkpoint = os.path.join(tmp, "model.pt")
    with open(checkpoint, "wb") as fh:
        pickle.dump({"weights": [0.1, 0.2], "trap": Payload(marker)}, fh)

    scanner = shutil.which("sgs-scan-model")
    if scanner is None:
        report("sgs-scan-model flags the checkpoint", False, "scanner not installed")
    else:
        out = subprocess.run([scanner, checkpoint], capture_output=True, text=True)
        flagged = out.returncode != 0 and "system" in out.stdout + out.stderr
        report("sgs-scan-model flags the checkpoint", flagged,
               "exit %d, dangerous import reported" % out.returncode if flagged else (out.stdout + out.stderr).strip()[:120])

    if torch is None:
        report("torch.load refuses code (weights_only=False)", False, "PyTorch not installed")
    else:
        forced = os.environ.get("TORCH_FORCE_WEIGHTS_ONLY_LOAD", "unset")
        try:
            torch.load(checkpoint, weights_only=False)
            refused = False
        except Exception as exc:  # weights-only unpickler raises on the os.system global
            refused, why = True, type(exc).__name__
        ran = os.path.exists(marker)
        report("torch.load refuses code (weights_only=False)", refused and not ran,
               "refused (%s), payload did not run; TORCH_FORCE_WEIGHTS_ONLY_LOAD=%s" % (why, forced)
               if refused and not ran else "payload ran: %s; TORCH_FORCE_WEIGHTS_ONLY_LOAD=%s" % (ran, forced))

    shutil.rmtree(tmp, ignore_errors=True)
    print("\n%d/%d passed" % (sum(results), len(results)))
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())
