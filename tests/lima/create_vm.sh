#!/usr/bin/env bash
# create_vm.sh: create a local Ubuntu 22.04 VM (Lima, macOS/Linux) standing in for a Lambda instance.
#
#   tests/lima/create_vm.sh sgs-stock    # untouched baseline for the "before" audit
#   tests/lima/create_vm.sh sgs-test     # box to install secure-gpu-stack on
#
# Each VM gets an 'ubuntu' admin with a throwaway test key (tests/lima/.keys/, git-ignored),
# Docker (Lambda Stack ships it), a NAT address the host can reach directly so test traffic
# really crosses the VM's firewall, no automatic port forwarding, and no shared folders.
#
# TEST HARNESS ONLY: Lima manages the VM over SSH as your local user, so that one account
# is exempted from MFA by a Match block, or Lima would lose control of its own VM. This
# never exists outside these VMs, and the audit reports it as an MFA-exempt account,
# which doubles as a test that the exempt-account check works.
set -Eeuo pipefail

name=${1:?usage: create_vm.sh NAME}
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
keys=$here/.keys
install -d -m 0700 "$keys"
[[ -f $keys/test_key ]] || ssh-keygen -q -t ed25519 -N "" -C sgs-vm-test -f "$keys/test_key"

cfg=$(mktemp -d)/$name.yaml
cat >"$cfg" <<EOF
base: template:ubuntu-22.04
cpus: 2
memory: 2GiB
disk: 10GiB
networks:
  - vzNAT: true
portForwards:
  - {guestIP: 0.0.0.0, guestIPMustBeZero: false, guestPortRange: [1, 65535], proto: any, ignore: true}
  - {guestIP: 127.0.0.1, guestPortRange: [1, 65535], proto: any, ignore: true}
provision:
  - mode: system
    script: |
      #!/bin/bash
      set -eux
      id ubuntu || useradd -m -s /bin/bash -G sudo ubuntu
      echo 'ubuntu ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/90-ubuntu
      install -d -m 700 -o ubuntu -g ubuntu /home/ubuntu/.ssh
      echo '$(cat "$keys/test_key.pub")' > /home/ubuntu/.ssh/authorized_keys
      chown ubuntu:ubuntu /home/ubuntu/.ssh/authorized_keys
      apt-get update -q
      DEBIAN_FRONTEND=noninteractive apt-get install -y -q docker.io
      cat > /etc/ssh/sshd_config.d/01-lima-test-harness.conf <<'CONF'
      Match User $USER
          AuthenticationMethods publickey
          MaxSessions 10
          AllowTcpForwarding yes
      CONF
EOF

limactl start --name="$name" --tty=false --mount-none "$cfg"
ip=$(limactl shell "$name" -- ip -4 -br addr show lima0 | awk '{ print $3 }' | cut -d/ -f1)
echo
echo "VM '$name' is ready at $ip"
echo "  shell (Lima account):  limactl shell $name"
echo "  SSH as ubuntu:         ssh -i $keys/test_key -o IdentitiesOnly=yes ubuntu@$ip"
echo "  copy the repo in:      limactl copy -r . $name:/tmp/secure-gpu-stack"
