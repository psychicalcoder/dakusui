# Install

Dakusui needs root for three things: to grant the binary its capabilities,
to keep unprivileged BPF off, and to mount a bpffs for each user. Running it needs no root. (ADR 0005, ADR 0008, spec 0001 R9)

Check first that the kernel lists `bpf` as an active LSM:

    cat /sys/kernel/security/lsm

If it does not, add `bpf` to the `lsm=` boot parameter.

## 1. The binaries

Build, then copy both binaries to one directory on a file system mounted
without `nosuid`. The helper starts `dakusui-agent` from its own directory.

    make build
    sudo install -m 0755 build/dakusui build/dakusui-agent /usr/local/bin/
    sudo setcap cap_bpf,cap_perfmon=ep /usr/local/bin/dakusui

Run `setcap` again after every copy: writing a file drops its capabilities.

## 2. Unprivileged BPF

The pins sit in a directory the user owns. Only `kernel.unprivileged_bpf_disabled`
keeps a confined command from opening them, so it must be 1 or 2:

    cat /proc/sys/kernel/unprivileged_bpf_disabled

Most distributions set it already. If yours does not:

    echo kernel.unprivileged_bpf_disabled=2 | sudo tee /etc/sysctl.d/50-dakusui.conf
    sudo sysctl -p /etc/sysctl.d/50-dakusui.conf

## 3. A bpffs for each user

Each user needs a bpffs mounted at `/run/dakusui/<uid>`, owned by that user,
with mode 0700. `/run` is empty at each boot, so the system must make
`/run/dakusui` and the mount at boot. How depends on the init system. The
mount itself looks like this, with `1000` as the user's uid and group id:

    mount -t bpf -o uid=1000,gid=1000,mode=0700 bpffs /run/dakusui/1000

## Check

The mount must show as `bpf`, owned by the user, mode `drwx------`:

    grep /run/dakusui /proc/mounts
    ls -ld /run/dakusui/$(id -u)

`dakusui` checks all of this at start, and names the step that is missing.
From the source tree, `make attach-check` runs the kernel checks.

## Uninstall

Remove the binaries and the lines above. Pins live in `/run`, so a reboot
clears them. Until then, `dakusui` clears the pins of a session whose helper
is gone when it next starts.
