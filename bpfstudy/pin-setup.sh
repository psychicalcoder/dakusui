#!/bin/sh
# Spike 3 setup. Run with sudo: mounts a bpffs that the invoking user owns,
# the one-time root step pinning would add to an install.
#
#   sudo sh pin-setup.sh       mount
#   sudo sh pin-setup.sh down  unmount
set -u
U=${SUDO_UID:?run this with sudo}
G=${SUDO_GID:?run this with sudo}
D=/run/dakusui-spike/bpf

if [ "${1:-up}" = down ]; then
	umount "$D" && rmdir "$D" && echo "unmounted $D"
	exit
fi

mkdir -p "$D"
if grep -q " $D " /proc/mounts; then
	echo "already mounted at $D"
	grep " $D " /proc/mounts
	exit
fi
if mount -t bpf -o "uid=$U,gid=$G,mode=0700" bpffs "$D" 2>/dev/null; then
	echo "Q1 PASS: bpffs takes uid=, gid=, and mode="
elif mount -t bpf -o mode=0700 bpffs "$D" && chown "$U:$G" "$D"; then
	echo "Q1 FAIL: bpffs refused uid=/gid=; mounted with mode= and chowned its root"
else
	echo "Q1 FAIL: could not give the user a bpffs"
	exit 1
fi
ls -ld "$D"
grep " $D " /proc/mounts
