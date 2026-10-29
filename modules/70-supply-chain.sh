# 70-supply-chain: safe model loading by default, a model scanner, and package-source checks
#
# - PyTorch checkpoints are pickles, and unpickling can run arbitrary code. Login shells get
#   TORCH_FORCE_WEIGHTS_ONLY_LOAD=1, so torch.load only accepts tensors and plain data even
#   when a script passes weights_only=False. For a checkpoint you trust, opt out per command:
#   TORCH_FORCE_WEIGHTS_ONLY_LOAD=0 python train.py
# - sgs-scan-model: checks model files (pickle, .bin, .pt, .ckpt, zip) for code-running
#   imports before anyone loads them. picklescan, pinned by version and SHA-256.
# - Package sources: warns about apt repositories that skip signature checks (trusted=yes,
#   allow-insecure), which would let anyone on the network path substitute packages.

ML_PROFILE=/etc/profile.d/secure-gpu-stack-ml.sh
TOOLS_DIR=/opt/secure-gpu-stack-tools
SCAN_MODEL=/usr/local/bin/sgs-scan-model
PICKLESCAN_URL=https://files.pythonhosted.org/packages/5c/88/dd6e4c9b9a7a7fccd7203c4745203a0eec6ec77426a987411ddd7eb845b7/picklescan-1.0.4-py3-none-any.whl
PICKLESCAN_SHA256=6e156d130326da09ca6d195b0f38fdb81b90cbd1ac2ec69d16694e7e5062f8e7

module_main() {
  write_ml_defaults
  install_model_scanner
  check_package_sources
}

write_ml_defaults() {
  write_file "$ML_PROFILE" 0644 <<'EOF'
# Managed by secure-gpu-stack: safer defaults for loading ML models.
# torch.load accepts only tensors and plain data, never pickled code, even if a script
# passes weights_only=False. For a checkpoint you trust:
#   TORCH_FORCE_WEIGHTS_ONLY_LOAD=0 python ...
# Scan downloaded models first: sgs-scan-model <file-or-dir>
export TORCH_FORCE_WEIGHTS_ONLY_LOAD=1
# Don't send usage telemetry to Hugging Face.
export HF_HUB_DISABLE_TELEMETRY=1
EOF
  ok "torch.load refuses code-carrying checkpoints by default (login shells)"
}

install_model_scanner() {
  local wheel tmp
  wheel=$TOOLS_DIR/$(basename "$PICKLESCAN_URL")
  if [[ ! -f $wheel ]]; then
    if is_dry; then
      log "would download picklescan and verify SHA-256 $PICKLESCAN_SHA256"
    else
      tmp=$(mktemp)
      curl -fsSL -o "$tmp" "$PICKLESCAN_URL" || { rm -f "$tmp"; die "could not download picklescan"; }
      echo "$PICKLESCAN_SHA256  $tmp" | sha256sum -c --quiet || { rm -f "$tmp"; die "picklescan checksum mismatch"; }
      install -D -m 0644 "$tmp" "$wheel"
      rm -f "$tmp"
    fi
  fi
  # python3 -I: ignore PYTHONPATH, user site-packages and the current directory, so a
  # model repo being scanned can't plant a module that hijacks the scanner.
  write_file "$SCAN_MODEL" 0755 <<EOF
#!/bin/sh
# sgs-scan-model: scan model files for pickled code before loading them (secure-gpu-stack).
#   sgs-scan-model ./checkpoint.pt      sgs-scan-model ~/models/
#   sgs-scan-model --huggingface org/model   (any other picklescan option is passed through)
if [ \$# -eq 0 ]; then echo "usage: sgs-scan-model PATH | picklescan options" >&2; exit 2; fi
case "\$1" in -*) ;; *) set -- --path "\$@" ;; esac
exec python3 -I -c 'import sys; sys.path.insert(0, "$wheel"); from picklescan.cli import main; sys.exit(main())' "\$@"
EOF
  ok "sgs-scan-model installed (picklescan 1.0.4, checksum-verified)"
}

check_package_sources() {
  local insecure
  insecure=$(grep -rhsE '^[^#]*(trusted=yes|allow-insecure=yes|allow-weak=yes)|^[^#]*Trusted:\s*yes' \
    /etc/apt/sources.list /etc/apt/sources.list.d/ || true)
  if [[ -n $insecure ]]; then
    warn "apt sources that skip signature checks (anyone on the network path could swap packages):"
    printf '    %s\n' "$insecure" >&2
  else
    ok "every apt source is signature-verified"
  fi
}
