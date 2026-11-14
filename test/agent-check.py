#!/usr/bin/env python3
"""Spec 0002 A11, and whole turns, with the built agent and a test provider.

make agent-check runs build/dakusui-agent under a stand-in helper: one end of
a socketpair on the agent's fd 3, answering {"ok":true} to every request. No
kernel and no privilege are needed, so commands run unconfined, and the
script asks only for echo.

With --helper PATH, the real helper starts the agent instead, so the same
cases run confined. make attach-check does that with a copy of the real
helper and agent.
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


class Provider(http.server.ThreadingHTTPServer):
    """A chat completions server on a loopback port. It gives the scripted
    answers in order, then repeats the last, and keeps each request."""

    def __init__(self):
        super().__init__(("127.0.0.1", 0), Handler)
        self.answers = []
        self.requests = []
        threading.Thread(target=self.serve_forever, daemon=True).start()

    def script(self, *answers):
        self.answers = list(answers)
        self.requests = []

    @property
    def url(self):
        return "http://127.0.0.1:%d/v1" % self.server_address[1]


class Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        server = self.server
        server.requests.append(
            {"path": self.path, "auth": self.headers.get("Authorization"),
             "body": json.loads(body)})
        status, answer = server.answers[0]
        if len(server.answers) > 1:
            server.answers.pop(0)
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
        os.mkdir(project)
        env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"),
               "HOME": os.environ.get("HOME", base),
               "XDG_STATE_HOME": state,
               "OPENAI_BASE_URL": provider.url,
               "OPENAI_MODEL": "test-model",
               "OPENAI_API_KEY": KEY}

        def check(label, passed, output):
            print(("ok   " if passed else "FAIL ") + label)
            if not passed:
                failed.append(label)
                print("  " + output.replace("\n", "\n  "))

        def agent_run(args, stdin=b""):
            code, output = run(agent, helper, args, env, project, stdin)
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
        code, output = agent_run(["-p", "run echo"])
        second = provider.requests[1]["body"]["messages"] if len(provider.requests) > 1 else []
        check("A2 a bash call runs, and the next request carries its result",
              code == 0 and "[bash]" in output and "done" in output
              and second[-1] == {"role": "tool", "tool_call_id": "c1", "content": "one"},
              output)

        provider.script(reply("hello"))
        code, output = agent_run([], b"/policy\n/deny read /nope\nhi\n")
        check("R1 the prompt runs commands and turns until the end of input",
              code == 0 and "The default rules:" in output
              and "added rule 1: deny read /nope" in output and "hello" in output
              and len(provider.requests) == 1, output)

        code, output = agent_run(["-x"])
        check("R11 an unknown argument is refused", code == 1 and "usage" in output, output)
        check("A10 no output or log holds the key", not leaks, "\n".join(leaks))

    if failed:
        print("agent-check: failed %d checks" % len(failed))
        sys.exit(1)
    print("agent-check: every check passed")


if __name__ == "__main__":
    main()
