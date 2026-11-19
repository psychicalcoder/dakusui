#!/usr/bin/env python3
"""Spec 0002 A11, and whole turns, with the built agent and a test provider.

make agent-check runs build/dakusui-agent under a stand-in helper: one end of
a socketpair on the agent's fd 3, answering {"ok":true} to every request. No
kernel and no privilege are needed, so commands run unconfined, and the
script asks only for echo.

With --helper PATH, the real helper starts the agent instead, so the same
cases run confined. make attach-check does that with a copy of the real
helper and agent.

HOME is a temp directory with a configuration file, so the user's own file
plays no part. Spec 0004: a role and a rule set from the command line, the
start-up listing, saving, and two agents saving to one set at once (A11).

Spec 0005: the test provider also plays the judge. The configuration gives
the judge role its own model name, so the server tells the judge's requests
from the agent's. Outside auto mode a bash call asks on stdin, so the checks
answer y.

Spec 0003 T7: a second home names two MCP servers, one whose command does
not exist and the test server test/mcp-server.py. The checks look for the
warning, the server's tools in the model's request, a call's result, and
that no server outlives the agent.
"""

import http.server
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading

KEY = "sk-secret"
SPAWN = threading.Lock()


JUDGE_MODEL = "judge-model"
MCP_SERVER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "mcp-server.py")


def live_servers():
    """The pids of live processes, not zombies, that run MCP_SERVER."""
    pids = []
    for pid in filter(str.isdigit, os.listdir("/proc")):
        try:
            with open("/proc/%s/cmdline" % pid, "rb") as f:
                cmdline = f.read()
            with open("/proc/%s/stat" % pid) as f:
                state = f.read().rsplit(")", 1)[1].split()[0]
        except OSError:
            continue
        if MCP_SERVER.encode() in cmdline and state not in ("Z", "X"):
            pids.append(pid)
    return pids


class Provider(http.server.ThreadingHTTPServer):
    """A chat completions server on a loopback port. It gives the scripted
    answers in order, then repeats the last, and keeps each request. A
    request for JUDGE_MODEL gets the judge's answers and is kept apart."""

    def __init__(self):
        super().__init__(("127.0.0.1", 0), Handler)
        self.script()
        threading.Thread(target=self.serve_forever, daemon=True).start()

    def script(self, *answers, judge=None):
        self.answers = list(answers)
        self.requests = []
        self.judge_answers = list(judge or [verdict(False, "no verdict scripted")])
        self.judge_requests = []

    @property
    def url(self):
        return "http://127.0.0.1:%d/v1" % self.server_address[1]


class Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))))
        server = self.server
        judging = body.get("model") == JUDGE_MODEL
        requests = server.judge_requests if judging else server.requests
        answers = server.judge_answers if judging else server.answers
        requests.append(
            {"path": self.path, "auth": self.headers.get("Authorization"),
             "body": body})
        status, answer = answers[0]
        if len(answers) > 1:
            answers.pop(0)
        data = json.dumps(answer).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass


def reply(text=None, calls=()):
    message = {"role": "assistant", "content": text}
    if calls:
        message["tool_calls"] = [
            {"id": ident, "type": "function",
             "function": {"name": name, "arguments": json.dumps(args)}}
            for ident, name, args in calls]
    return 200, {"choices": [{"index": 0, "message": message}]}


def verdict(allow, reason):
    """The judge's reply: its JSON object, in prose, as a model may give it."""
    return reply("Verdict: " + json.dumps({"allow": allow, "reason": reason}))


def stand_in(sock):
    """Answer every request line on SOCK with ok, until the agent closes."""
    with sock, sock.makefile("rwb") as f:
        for _ in f:
            f.write(b'{"ok":true}\n')
            f.flush()


def run(agent, helper, args, env, cwd, stdin=b""):
    """Run the agent, under HELPER or the stand-in. Return (code, output)."""
    if helper:
        p = subprocess.run([helper] + args, input=stdin, stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT, env=env, cwd=cwd, timeout=120)
        return p.returncode, p.stdout.decode(errors="replace")
    ours, theirs = socket.socketpair()
    threading.Thread(target=stand_in, args=(ours,), daemon=True).start()
    in_r, in_w = os.pipe()
    out_r, out_w = os.pipe()
    actions = [(os.POSIX_SPAWN_DUP2, in_r, 0), (os.POSIX_SPAWN_DUP2, out_w, 1),
               (os.POSIX_SPAWN_DUP2, out_w, 2), (os.POSIX_SPAWN_DUP2, theirs.fileno(), 3)]
    # The working directory belongs to the whole process.
    with SPAWN:
        old = os.getcwd()
        os.chdir(cwd)
        try:
            pid = os.posix_spawn(agent, [agent] + args, env, file_actions=actions)
        finally:
            os.chdir(old)
    for fd in (in_r, out_w):
        os.close(fd)
    theirs.close()
    os.write(in_w, stdin)
    os.close(in_w)
    chunks = []
    while True:
        chunk = os.read(out_r, 65536)
        if not chunk:
            break
        chunks.append(chunk)
    os.close(out_r)
    _, status = os.waitpid(pid, 0)
    return os.waitstatus_to_exitcode(status), b"".join(chunks).decode(errors="replace")


def main():
    helper = None
    if len(sys.argv) == 4 and sys.argv[2] == "--helper":
        helper = os.path.abspath(sys.argv[3])
    elif len(sys.argv) != 2:
        sys.exit("usage: agent-check.py AGENT [--helper HELPER]")
    agent = os.path.abspath(sys.argv[1])
    provider = Provider()
    failed = []
    leaks = []

    with tempfile.TemporaryDirectory() as base:
        base = os.path.realpath(base)
        project = os.path.join(base, "p")
        state = os.path.join(base, "state")
        home = os.path.join(base, "home")
        rules = os.path.join(project, ".dakusui", "rules")
        os.makedirs(rules)
        os.makedirs(os.path.join(home, ".config", "dakusui"))
        with open(os.path.join(home, ".config", "dakusui", "config.json"), "w") as f:
            json.dump({"roles": {"tester": {"model": "role-model", "base_url": provider.url,
                                            "api_key_env": "OPENAI_API_KEY"},
                                 "judge": {"model": JUDGE_MODEL}}}, f)
        mcp_home = os.path.join(base, "mcp-home")
        os.makedirs(os.path.join(mcp_home, ".config", "dakusui"))
        with open(os.path.join(mcp_home, ".config", "dakusui", "config.json"), "w") as f:
            json.dump({"roles": {"judge": {"model": JUDGE_MODEL}},
                       "mcp": {"gone": {"command": "/nonexistent/dakusui-mcp-server"},
                               "test": {"command": "exec python3 -I '%s'" % MCP_SERVER}}},
                      f)
        secret = os.path.join(base, "secret")
        with open(os.path.join(rules, "strict"), "w") as f:
            f.write("# from agent-check\n\ndeny read,write %s\n" % secret)
        env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"),
               "HOME": home,
               "XDG_STATE_HOME": state,
               "OPENAI_BASE_URL": provider.url,
               "OPENAI_MODEL": "test-model",
               "OPENAI_API_KEY": KEY}

        def check(label, passed, output):
            print(("ok   " if passed else "FAIL ") + label)
            if not passed:
                failed.append(label)
                print("  " + output.replace("\n", "\n  "))

        def agent_run(args, stdin=b"", home=home):
            code, output = run(agent, helper, args, dict(env, HOME=home), project, stdin)
            log = os.path.join(state, "dakusui", "denials.log")
            logged = open(log).read() if os.path.exists(log) else ""
            # R10: the key reaches the provider, and nothing else.
            if KEY in output or KEY in logged:
                leaks.append(output)
            return code, output

        provider.script(reply("hello"))
        code, output = agent_run(["-p", "hi"])
        sent = provider.requests[0] if provider.requests else {}
        messages = sent.get("body", {}).get("messages", [])
        check("A11 dakusui -p hi shows the reply and exits 0",
              code == 0 and "hello" in output, output)
        check("0004 R9 the start-up listing shows the empty default set",
              'The rule set "default":\n  (none)' in output, output)
        check("A1 the request carries the model, the system prompt, and the message",
              sent.get("path") == "/v1/chat/completions"
              and sent.get("auth") == "Bearer " + KEY
              and sent["body"].get("model") == "test-model"
              and [m["role"] for m in messages] == ["system", "user"]
              and project in messages[0]["content"]
              and messages[1]["content"] == "hi",
              json.dumps(sent, indent=1).replace(KEY, "[key]"))

        provider.script((401, {"error": {"message": "bad key " + KEY}}))
        code, output = agent_run(["-p", "hi"])
        check("A11 a failing provider exits 1 and names the status",
              code == 1 and "401" in output and "bad key [key]" in output, output)

        provider.script(reply(calls=[("c1", "bash", {"command": "echo one"})]), reply("done"))
        code, output = agent_run(["-p", "run echo"], b"y\n")
        second = provider.requests[1]["body"]["messages"] if len(provider.requests) > 1 else []
        check("A2, 0005 A1 a bash call asks, runs on y, and the next request carries its result",
              code == 0 and "[bash]" in output and "Run? [y/n]" in output and "done" in output
              and second[-1] == {"role": "tool", "tool_call_id": "c1", "content": "one"}
              and not provider.judge_requests,
              output)

        def tool_result(requests):
            """The content of the last message of the second request."""
            if len(requests) < 2:
                return None
            return requests[1]["body"]["messages"][-1].get("content")

        provider.script(reply(calls=[("c1", "bash", {"command": "echo allowed-run"})]),
                        reply("done"), judge=(verdict(True, "asked for"),))
        code, output = agent_run(["--auto", "-p", "run the allowed echo"])
        judged = provider.judge_requests[0]["body"] if provider.judge_requests else {}
        asked = "".join(m.get("content") or "" for m in judged.get("messages", []))
        check("0005 A3 in auto mode the judge allows a command, and it runs unasked",
              code == 0 and "Run? [y/n]" not in output
              and tool_result(provider.requests) == "allowed-run"
              and len(provider.judge_requests) == 1
              and provider.judge_requests[0]["auth"] == "Bearer " + KEY,
              output)
        check("0005 A4, A7 the judge sees the user's message and the command, and no tools",
              "run the allowed echo" in asked and "echo allowed-run" in asked
              and "tools" not in judged,
              json.dumps(judged, indent=1))

        marker = os.path.join(project, "blocked-ran")
        provider.script(reply(calls=[("c1", "bash", {"command": "touch %s" % marker})]),
                        reply("done"), judge=(verdict(False, "sends the key away"),))
        code, output = agent_run(["--auto", "-p", "run the blocked touch"])
        reason = "blocked by the judge: sends the key away"
        check("0005 A3 in auto mode the judge blocks a command, and the model and the terminal see why",
              code == 0 and not os.path.exists(marker) and reason in output
              and tool_result(provider.requests) == reason
              and len(provider.judge_requests) == 1,
              output)

        provider.script(reply("never"))
        code, output = agent_run(["--auto"], b"/auto\n/auto off\n/auto\n")
        check("0005 A6 --auto starts auto mode, and /auto off turns it off",
              code == 0 and "Auto mode is on" in output
              and output.index("Auto mode is on") < output.index("Auto mode is off")
              and not provider.requests, output)

        provider.script(reply("hello"))
        code, output = agent_run([], b"/policy\n/deny read /nope\nhi\n")
        check("R1 the prompt runs commands and turns until the end of input",
              code == 0 and "The default rules:" in output
              and "added rule 1: deny read /nope" in output and "hello" in output
              and len(provider.requests) == 1, output)

        check("0004 A9 /deny saves the rule to the default set",
              open(os.path.join(rules, "default")).read() == "deny read /nope\n",
              output)

        provider.script(reply("hello"))
        code, output = agent_run(["--role", "tester", "--rules", "strict", "-p", "hi"])
        sent = provider.requests[0] if provider.requests else {}
        check("0004 A5, A8 --role and --rules pick the model and the set, and the set is shown",
              code == 0 and "hello" in output
              and ('The rule set "strict":\n  1 deny read,write %s' % secret) in output
              and sent.get("body", {}).get("model") == "role-model"
              and sent.get("auth") == "Bearer " + KEY,
              output)

        provider.script(reply("never"))
        code, output = agent_run(["--role", "nosuch", "-p", "hi"])
        check("0004 A4 an unknown role stops before any request and names the role",
              code == 1 and '"nosuch"' in output and not provider.requests, output)

        code, output = agent_run(["--rules", "../x", "-p", "hi"])
        check("0004 A7 a bad set name stops before any request",
              code == 1 and "bad rule set name" in output and not provider.requests, output)

        # A11: two agents add 100 rules each to one set at once.
        results = {}

        def add_rules(tag):
            lines = "".join("/deny read /p/%s%d\n" % (tag, i) for i in range(100))
            results[tag] = agent_run(["--rules", "shared"], lines.encode())

        threads = [threading.Thread(target=add_rules, args=(tag,)) for tag in ("a", "b")]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        shared = os.path.join(rules, "shared")
        saved = open(shared).read().split("\n") if os.path.exists(shared) else []
        wanted = {"deny read /p/%s%d" % (tag, i) for tag in ("a", "b") for i in range(100)}
        check("0004 A11 two agents saving to one set lose no rule",
              all(code == 0 for code, _ in results.values())
              and saved[-1] == "" and len(saved) == 201 and set(saved[:-1]) == wanted,
              "\n".join(out for _, out in results.values())[-2000:])

        provider.script(reply(calls=[("c1", "test__echo", {"text": "hi"})]),
                        reply("done"), judge=(verdict(True, "asked for"),))
        code, output = agent_run(["--auto", "-p", "echo hi"], home=mcp_home)
        sent = provider.requests[0]["body"] if provider.requests else {}
        names = [t["function"]["name"] for t in sent.get("tools", [])]
        check("0003 A1, A10 a server that fails is skipped with a warning, and the "
              "tool list is the built-in tools, then the server's",
              'the MCP server "gone" ended before it answered initialize; skipping it' in output
              and names[:3] == ["bash", "show_policy", "test__echo"]
              and "test__read" in names,
              output + "\n" + json.dumps(names))
        check("0003 A8 a call to test__echo returns hi",
              code == 0 and tool_result(provider.requests) == "hi"
              and len(provider.judge_requests) == 1, output)
        left = live_servers()
        check("0003 the agent stops its MCP servers when it exits", not left, " ".join(left))

        provider.script(reply(calls=[("c1", "test__echo", {"text": "typed"})]), reply("done"))
        code, output = agent_run(["-p", "echo typed"], b"y\n", home=mcp_home)
        check("0003 A8, 0005 A1 a call to an MCP tool asks, and runs on y",
              code == 0 and "Run? [y/n]" in output
              and tool_result(provider.requests) == "typed", output)
        code, output = agent_run([], b"hi\n", home=mcp_home)
        left = live_servers()
        check("0003 the agent stops its MCP servers at the end of input", not left, " ".join(left))

        code, output = agent_run(["-x"])
        check("R11 an unknown argument is refused", code == 1 and "usage" in output, output)
        check("A10 no output or log holds the key", not leaks, "\n".join(leaks))

    if failed:
        print("agent-check: failed %d checks" % len(failed))
        sys.exit(1)
    print("agent-check: every check passed")


if __name__ == "__main__":
    main()
