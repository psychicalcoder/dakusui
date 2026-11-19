"""A scripted MCP server for the unit tests in test/mcp.ct and test/wiring.ct,
for test/agent-check.py, and for the check agent (spec 0003 T6, T7).

It speaks JSON-RPC 2.0, one message per line, on stdin and stdout. It lists
its tools in two pages, and refuses tools/list until it has the
notifications/initialized notice. Before each tools/call answer it sends a
notice, a line that is not JSON, and an answer to another id.

Tools: echo returns its text; fail reports an error in two text items;
exit ends the server unanswered; hang never answers; read opens the file at
its path and says how many characters it read, or why it could not. It
never returns what it read.

An argument changes the script: "hang" never answers initialize, "refuse"
answers it with an error, "odd" adds a tool whose name has a space, and
"endless" gives a next page of tools forever. The server writes no file,
and ends when stdin closes.
"""

import json
import sys

MODE = sys.argv[1] if len(sys.argv) > 1 else ""

TOOLS = [
    {"name": "echo", "description": "Echo the text.",
     "inputSchema": {"type": "object", "properties": {"text": {"type": "string"}},
                     "required": ["text"]}},
    {"name": "fail", "description": "Report an error.",
     "inputSchema": {"type": "object"}},
    {"name": "exit", "description": "End the server."},
    {"name": "hang", "description": "Never answer.",
     "inputSchema": {"type": "object"}},
    {"name": "read", "description": "Read the file at the path.",
     "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}},
                     "required": ["path"]}},
]

ODD = {"name": "has space", "description": "A name no model server takes."}


def send(message):
    sys.stdout.write(json.dumps(message) + "\n")
    sys.stdout.flush()


def answer(id, result):
    send({"jsonrpc": "2.0", "id": id, "result": result})


def refuse(id, message):
    send({"jsonrpc": "2.0", "id": id, "error": {"code": -32602, "message": message}})


def call(id, name, arguments):
    send({"jsonrpc": "2.0", "method": "notifications/message",
          "params": {"level": "info", "data": "working"}})
    sys.stdout.write("not json\n")
    send({"jsonrpc": "2.0", "id": "other", "result": {}})
    if name == "echo":
        answer(id, {"content": [{"type": "text", "text": arguments.get("text", "")}]})
    elif name == "fail":
        answer(id, {"content": [{"type": "text", "text": "bad"},
                                {"type": "image", "data": "", "mimeType": "image/png"},
                                {"type": "text", "text": "input"}],
                    "isError": True})
    elif name == "exit":
        sys.exit(0)
    elif name == "hang":
        pass
    elif name == "read":
        try:
            with open(arguments.get("path", "")) as f:
                text = "read %d characters" % len(f.read())
            answer(id, {"content": [{"type": "text", "text": text}]})
        except OSError as e:
            answer(id, {"content": [{"type": "text", "text": str(e)}], "isError": True})
    else:
        refuse(id, "unknown tool: " + str(name))


initialized = False
for line in sys.stdin:
    message = json.loads(line)
    method = message.get("method")
    params = message.get("params") or {}
    if "id" not in message:
        if method == "notifications/initialized":
            initialized = True
        continue
    id = message["id"]
    if method == "initialize":
        if MODE == "hang":
            continue
        if MODE == "refuse":
            refuse(id, "not today")
            continue
        answer(id, {"protocolVersion": params.get("protocolVersion"),
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "test", "version": "0"}})
    elif method == "tools/list":
        if not initialized:
            refuse(id, "not initialized")
        elif MODE == "endless":
            answer(id, {"tools": [], "nextCursor": "more"})
        elif params.get("cursor") == "page2":
            answer(id, {"tools": TOOLS[2:]})
        else:
            first = TOOLS[:2] + ([ODD] if MODE == "odd" else [])
            answer(id, {"tools": first, "nextCursor": "page2"})
    elif method == "tools/call":
        call(id, params.get("name"), params.get("arguments") or {})
    else:
        refuse(id, "unknown method: " + str(method))
