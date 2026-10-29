#!/usr/bin/env bash
# Secure GPU Stack: hardens a Lambda Cloud (Ubuntu + Lambda Stack) GPU instance.
#
#   sudo ./install.sh                 # run every module
#   sudo ./install.sh --dry-run       # show what would change, change nothing
#   sudo ./install.sh --only ssh-mfa  # run selected modules (comma-separated)
#   ./install.sh --list               # list modules
#
# Safe to re-run: modules only change what differs from the desired state.
set -Eeuo pipefail

SGS_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export SGS_ROOT
# shellcheck source=lib/common.sh
source "$SGS_ROOT/lib/common.sh"

usage() {
  sed -n '2,9p' "$0" | sed 's/^# \{0,1\}//'
  cat <<'EOF'

Options:
  --dry-run        print intended changes without applying them
  --only LIST      run only these modules, e.g. --only ssh-mfa,firewall
  --skip LIST      run all modules except these
  --user NAME      admin account to enroll for SSH MFA (default: $SUDO_USER or ubuntu)
  --list           list available modules and exit
  -h, --help       show this help
EOF
}

module_name() { basename "$1" .sh | sed 's/^[0-9]*-//'; }

in_list() {  # in_list NAME "a,b,c"
  [[ ",$2," == *",$1,"* ]]
}

only="" skip=""
SGS_USER=${SUDO_USER:-}
[[ -z $SGS_USER || $SGS_USER == root ]] && SGS_USER=ubuntu

while (($#)); do
  case $1 in
    --dry-run) SGS_DRY_RUN=1 ;;
    --only) only=${2:?--only needs a value}; shift ;;
    --skip) skip=${2:?--skip needs a value}; shift ;;
    --user) SGS_USER=${2:?--user needs a value}; shift ;;
    --list)
      for m in "$SGS_ROOT"/modules/*.sh; do
        printf '  %-14s %s\n' "$(module_name "$m")" "$(sed -n '1s/^# [^:]*: //p' "$m")"
      done
      exit 0 ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; die "unknown option: $1" ;;
  esac
  shift
done
export SGS_DRY_RUN SGS_USER

require_root
require_ubuntu

if ! is_dry; then
  install -d -m 0700 "$SGS_STATE_DIR" "$SGS_BACKUP_DIR"
  install -d -m 0750 "$SGS_LOG_DIR"
  exec > >(tee -a "$SGS_LOG_DIR/install.log") 2>&1
fi

log "Secure GPU Stack starting $(date -Is) (dry-run=$SGS_DRY_RUN, admin user=$SGS_USER)"

for m in "$SGS_ROOT"/modules/*.sh; do
  name=$(module_name "$m")
  [[ -n $only ]] && ! in_list "$name" "$only" && continue
  [[ -n $skip ]] && in_list "$name" "$skip" && continue
  # Each module runs in its own bash process: errexit stays in force inside it
  # (bash ignores `set -e` in a subshell that is followed by `||`).
  SGS_MODULE=$name bash -Eeuo pipefail -c \
    'source "$SGS_ROOT/lib/common.sh"; source "$1"; module_main' _ "$m" \
    || die "module '$name' failed; earlier modules were applied, nothing after it ran"
done

log "done. Run ./audit/run_audit.sh to measure the result."
