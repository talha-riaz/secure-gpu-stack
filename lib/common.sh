# Shared helpers for install.sh and the modules. Sourced, not executed.
# shellcheck disable=SC2034  # variables here are used by the files that source this one

SGS_STATE_DIR=/var/lib/secure-gpu-stack
SGS_BACKUP_DIR=$SGS_STATE_DIR/backups
SGS_LOG_DIR=/var/log/secure-gpu-stack
: "${SGS_DRY_RUN:=0}"
: "${SGS_MODULE:=sgs}"

log()  { printf '\033[1;34m[%s]\033[0m %s\n' "$SGS_MODULE" "$*"; }
ok()   { printf '\033[1;32m[%s] ✓\033[0m %s\n' "$SGS_MODULE" "$*"; }
warn() { printf '\033[1;33m[%s] !\033[0m %s\n' "$SGS_MODULE" "$*" >&2; }
die()  { printf '\033[1;31m[%s] ✗\033[0m %s\n' "$SGS_MODULE" "$*" >&2; exit 1; }

is_dry() { [[ $SGS_DRY_RUN == 1 ]]; }

# run CMD...: execute, or just print it in dry-run mode.
run() {
  if is_dry; then
    printf '  [dry-run]'; printf ' %q' "$@"; printf '\n'
  else
    "$@"
  fi
}

require_root() {
  [[ $EUID -eq 0 ]] || die "must run as root (use sudo)"
}

require_ubuntu() {
  [[ -r /etc/os-release ]] || die "cannot read /etc/os-release"
  # shellcheck source=/dev/null
  . /etc/os-release
  [[ ${ID:-} == ubuntu ]] || die "only Ubuntu is supported (found ${ID:-unknown})"
  case ${VERSION_ID:-} in
    22.04|24.04) ;;
    *) warn "untested Ubuntu version ${VERSION_ID:-unknown}; continuing" ;;
  esac
}

apt_update_once() {
  [[ -n ${SGS_APT_UPDATED:-} ]] && return 0
  run env DEBIAN_FRONTEND=noninteractive apt-get update -q
  SGS_APT_UPDATED=1
}

apt_install() {
  apt_update_once
  run env DEBIAN_FRONTEND=noninteractive apt-get install -y -q --no-install-recommends "$@"
}

# backup_file PATH: copy PATH into the backup dir (timestamped) before we change it.
backup_file() {
  local path=$1 dest
  [[ -e $path ]] || return 0
  dest="$SGS_BACKUP_DIR$path.$(date +%Y%m%d-%H%M%S)"
  run mkdir -p "$(dirname "$dest")"
  run cp -a "$path" "$dest"
}

# write_file PATH MODE [OWNER:GROUP] < content
# Writes only when the content differs, backing up the previous version.
# In dry-run mode prints a diff instead.
write_file() {
  local path=$1 mode=$2 owner=${3:-root:root} tmp
  tmp=$(mktemp)
  cat >"$tmp"
  if [[ -f $path ]] && cmp -s "$tmp" "$path"; then
    rm -f "$tmp"
    return 0
  fi
  if is_dry; then
    log "would write $path"
    diff -u "$( [[ -f $path ]] && echo "$path" || echo /dev/null )" "$tmp" \
      | awk 'NR <= 40 { print substr($0, 1, 160) } END { if (NR > 40) printf "  ... (%d more diff lines)\n", NR - 40 }' || true
    rm -f "$tmp"
    return 0
  fi
  backup_file "$path"
  install -D -m "$mode" -o "${owner%%:*}" -g "${owner##*:}" "$tmp" "$path"
  rm -f "$tmp"
}

# home_of USER: print the user's home directory.
home_of() {
  getent passwd "$1" | cut -d: -f6
}
