#!/usr/bin/env bash
# iterate.sh: one round of the local fix-and-measure loop, from the repo root:
#   sync repo -> install on the test VM -> audit -> external scan -> report
#
#   tests/lima/iterate.sh                      # fast round (no Trivy)
#   tests/lima/iterate.sh --trivy              # include the vulnerability scan
#   tests/lima/iterate.sh --only updates,gpu   # install only these modules
#   tests/lima/iterate.sh --rebaseline         # re-audit the stock VM too
#
# Needs the VMs from create_vm.sh: sgs-stock (never hardened) and sgs-test (ubuntu
# already enrolled, since enrollment needs a terminal). Report: audit/results/vm/report.html
set -Eeuo pipefail

repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
out=$repo/audit/results/vm
stock=sgs-stock target=sgs-test
trivy=--no-trivy only=() rebaseline=0

while (($#)); do
  case $1 in
    --trivy) trivy="" ;;
    --only) only=(--only "${2:?--only needs a value}"); shift ;;
    --rebaseline) rebaseline=1 ;;
    -h|--help) sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 1 ;;
  esac
  shift
done

vm_ip() { limactl shell "$1" -- ip -4 -br addr show lima0 | awk '{ print $3 }' | cut -d/ -f1; }

sync_repo() {  # copy the working tree (uncommitted edits included) to /opt in the VM
  local tmp
  tmp=$(mktemp -d)
  rsync -a --exclude .git --exclude audit/results --exclude tests/lima/.keys "$repo/" "$tmp/secure-gpu-stack/"
  limactl copy -r "$tmp/secure-gpu-stack" "$1:/tmp/" >/dev/null
  limactl shell "$1" -- sudo bash -c 'rm -rf /opt/secure-gpu-stack && cp -r /tmp/secure-gpu-stack /opt/ && rm -rf /tmp/secure-gpu-stack'
  rm -rf "$tmp"
}

audit_vm() {  # audit_vm VM LABEL [run_audit options]: demo services up, audit, fetch, scan from here
  local vm=$1 label=$2
  shift 2
  echo "== auditing $vm as '$label'"
  limactl shell "$vm" -- sudo bash -c "cd /opt/secure-gpu-stack \
    && ./audit/demo_services.sh start >/dev/null \
    && rm -rf audit/results/$label \
    && ./audit/run_audit.sh $label --out /opt/secure-gpu-stack/audit/results/$label $* 2>&1 | grep -E '✗|!' || true"
  rm -rf "${out:?}/$label"
  mkdir -p "$out"
  limactl copy -r "$vm:/opt/secure-gpu-stack/audit/results/$label" "$out/" >/dev/null
  python3 "$repo/audit/external_scan.py" "$(vm_ip "$vm")" --timeout 2 --out "$out/$label/external.json" >/dev/null
  # The scan's SSH probe counts as a failed login; a few rounds would get this machine
  # banned by fail2ban (working as intended), so clear test bans after each round.
  limactl shell "$vm" -- sudo fail2ban-client unban --all >/dev/null 2>&1 || true
}

if ((rebaseline)) || [[ ! -f $out/before/meta.txt ]]; then
  sync_repo "$stock"
  audit_vm "$stock" before "$trivy"
fi

echo "== installing on $target ${only[*]}"
sync_repo "$target"
limactl shell "$target" -- sudo bash -c "cd /opt/secure-gpu-stack && SUDO_USER=ubuntu ./install.sh ${only[*]} 2>&1 | grep -E '✓|!|✗'"

audit_vm "$target" after "$trivy"
python3 "$repo/audit/report.py" "$out/after"
python3 "$repo/audit/report.py" "$out/before" "$out/after" -o "$out/report" >/dev/null
echo
echo "report: $out/report.html"
