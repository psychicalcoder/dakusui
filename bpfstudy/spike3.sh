#!/bin/sh
# Spike 3: does enforcement outlive its loader? Run `sudo sh pin-setup.sh`
# first, then `make run3`. Each case starts ./pin, which confines a victim
# that keeps trying to read SANDBOX/secret (denied) and SANDBOX/ok (allowed).
# Then it SIGKILLs the loader and reads the victim's log for one second more.
set -u
DIR=${PIN_DIR:-/run/dakusui-spike/bpf}

# Lines in FILE that start with PREFIX.
count() { grep -c "^$1" "$2"; }

run() {
	mode=$1
	sb=$(mktemp -d /tmp/pin-sandbox.XXXXXX)
	echo secret >"$sb/secret"
	echo ok >"$sb/ok"
	./pin "$mode" "$DIR" "$sb" >"$sb/out" 2>&1 &
	loader=$!
	i=0
	while ! grep -q '^ready' "$sb/out" && [ $i -lt 100 ]; do
		sleep 0.05
		i=$((i + 1))
	done
	echo "== $mode"
	grep '^pin ' "$sb/out" | sed 's/^/   /'
	if ! grep -q '^ready' "$sb/out"; then
		echo "   loader failed:"
		sed 's/^/   /' "$sb/out"
		kill -9 "$loader" 2>/dev/null
		rm -rf "$sb"
		return
	fi
	victim=$(sed -n 's/^ready //p' "$sb/out")
	sleep 0.5
	before=$(wc -l <"$sb/log")
	kill -9 "$loader"
	wait "$loader" 2>/dev/null
	sleep 1
	kill -9 "$victim" 2>/dev/null
	head -n "$before" "$sb/log" >"$sb/pre"
	tail -n "+$((before + 1))" "$sb/log" >"$sb/post"
	echo "   before the kill: $(wc -l <"$sb/pre") tries, secret read $(count 1 "$sb/pre"), ok read $(count '.1' "$sb/pre")"
	echo "   after the kill:  $(wc -l <"$sb/post") tries, secret read $(count 1 "$sb/post"), ok read $(count '.1' "$sb/post")"
	case $mode in
	nopin)
		if [ "$(count 1 "$sb/post")" -gt 0 ]; then
			first=$(grep -n '^1' "$sb/post" | head -n 1 | cut -d: -f1)
			echo "   HOLE CONFIRMED: without pins the victim read the secret once the loader died"
			echo "   the hooks held for $((first - 1)) tries after the kill before they detached"
		else
			echo "   no hole seen: the victim never read the secret"
		fi ;;
	pin)
		# Every try must keep the policy: secret denied, ok read.
		if [ "$(count 1 "$sb/pre")" -eq 0 ] && [ "$(count 1 "$sb/post")" -eq 0 ] &&
			[ "$(count '.1' "$sb/pre")" -eq "$(wc -l <"$sb/pre")" ] &&
			[ "$(count '.1' "$sb/post")" -eq "$(wc -l <"$sb/post")" ]; then
			echo "   Q3 PASS: the policy still held after the loader died"
		else
			echo "   Q3 FAIL"
		fi ;;
	alive)
		# The first tries after kill() may race the loader's exit; report them.
		late=$(head -n 20 "$sb/post" | grep -c '^.1')
		if [ "$(count '.1' "$sb/pre")" -gt 0 ] && [ "$(count '.1' "$sb/post")" -le "$late" ] &&
			[ "$(tail -n 20 "$sb/post" | grep -c '^.1')" -eq 0 ]; then
			echo "   Q4 PASS: the hook denied once the loader was gone ($late reads in the first 20 tries after kill)"
		else
			echo "   Q4 FAIL"
		fi ;;
	esac
	rm -f "$DIR"/* 2>/dev/null # unpin, which detaches the hooks
	rm -rf "$sb"
}

if ! [ -d "$DIR" ] || ! [ -w "$DIR" ]; then
	echo "no writable bpffs at $DIR: run 'sudo sh pin-setup.sh' first"
	exit 1
fi
run nopin
run pin
run alive
