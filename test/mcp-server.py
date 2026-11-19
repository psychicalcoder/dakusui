"""A scripted MCP server for the unit tests in test/mcp.ct (spec 0003 T6).

It speaks JSON-RPC 2.0, one message per line, on stdin and stdout. It lists
its tools in two pages, and refuses tools/list until it has the
notifications/initialized notice. Before each tools/call answer it sends a
notice, a line that is not JSON, and an answer to another id.

Tools: echo returns its text; fail reports an error in two text items;
exit ends the server unanswered; hang never answers.

An argument spoils initialize: "hang" never answers it, "refuse" answers
with an error. The server touches no file, and ends when stdin closes.
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
]


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
        elif params.get("cursor") == "page2":
            answer(id, {"tools": TOOLS[2:]})
        else:
            answer(id, {"tools": TOOLS[:2], "nextCursor": "page2"})
    elif method == "tools/call":
        call(id, params.get("name"), params.get("arguments") or {})
    else:
        refuse(id, "unknown method: " + str(method))
