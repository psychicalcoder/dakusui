#!/bin/sh
# make attach-check, once the check binaries hold their capabilities. Needs
# the bpffs at /run/dakusui/<uid> (ADR 0008).
#
# 1. build/attach-check: T8 through T14, T28, T30, and T31 for itself.
# 2. The real helper with the check agent, the acceptance harness (T21):
#    A1 through A18, the first half of A19, the random-policy test (T22), and
#    the torn-walk test (T23), spec 0003 A3, A4, and A6 through the bash
#    tool, and spec 0003 A9 and A10 through the test MCP server. The helper gets an API key and BASH_ENV, which
#    no command may see. A6 kills the helper, so its exit code says nothing:
#    the agent's last line does.
# 3. The real helper again: its start must end A19's victim (T30), and its
#    normal exit must unpin its session and end a nohup'd command (T31).
# 4. A copy of the real helper and agent, with a test provider: spec 0002
#    A11 and whole turns, confined (test/agent-check.py).
set -u
report=build/check/report
pins=/run/dakusui/$(id -u)

build/attach-check || exit 1

{ env OPENAI_API_KEY=attach-check BASH_ENV=/nonexistent build/check/dakusui; true; } |
	tee "$report"
grep -q '^check-agent passed' "$report" || exit 1

victims=$(sed -n 's/^victim //p' "$report")
if [ -z "$victims" ]; then
	echo "attach-check: the check agent named no A19 victim"
	exit 1
fi
env DAKUSUI_CHECK_VICTIMS="$victims" build/check/dakusui >"$report.2"
code=$?
cat "$report.2"
grep -q '^check-agent passed' "$report.2" && [ "$code" -eq 0 ] || exit 1

helper=$(sed -n 's/^helper //p' "$report.2")
nohup_pid=$(sed -n 's/^nohup //p' "$report.2")
if ls "$pins" | grep -q "^$helper-"; then
	echo "FAIL T31: the helper's session is still pinned after a normal exit"
	exit 1
fi
# Gone, or a zombie that init has yet to reap.
if [ -e "/proc/$nohup_pid" ] && ! sed 's/.*) //' "/proc/$nohup_pid/stat" | grep -q '^Z'; then
	echo "FAIL T31: the nohup'd command outlived the helper's normal exit"
	exit 1
fi
echo "ok   T31 a normal exit left no pins and ended the nohup'd command"

python3 test/agent-check.py build/check/real/dakusui-agent --helper build/check/real/dakusui || exit 1
echo "attach-check: every check passed"
