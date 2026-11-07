#!/bin/sh
# T15 (R11, part of A8): the binaries take no SBCL option that runs code.
# Each try passes an option that would print MARKER if SBCL honored it.
# Needs no capabilities: the options would act before main runs.
set -u

dir=$(mktemp -d)
trap 'rm -rf "$dir"' EXIT
printf '(write-line "MARKER")\n(sb-ext:exit)\n' > "$dir/marker.lisp"
eval='(progn (write-line "MARKER") (sb-ext:exit))'
core=$(sbcl --noinform --non-interactive \
	--eval '(write-string (namestring sb-ext:*core-pathname*))' 2>/dev/null)
failed=0

try() {
	out=$("$@" </dev/null 2>&1)
	case $out in
	*MARKER* | "SBCL "*)
		echo "FAIL $*"
		failed=1
		;;
	*) echo "ok   $*" ;;
	esac
}

for bin in build/dakusui build/dakusui-agent; do
	try "$bin" --eval "$eval"
	try "$bin" --non-interactive --eval "$eval"
	try "$bin" --load "$dir/marker.lisp"
	try "$bin" --script "$dir/marker.lisp"
	try "$bin" --userinit "$dir/marker.lisp"
	try "$bin" --core "$core" --non-interactive --eval "$eval"
	try "$bin" --end-runtime-options --eval "$eval"
	try "$bin" --version
	try env SBCL_HOME="$dir" "$bin" --eval "$eval"
done

exit $failed
