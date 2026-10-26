"""stdio MCP server: 把红队扫描与静态审计暴露给任何 MCP 客户端.

纯标准库 JSON-RPC 2.0 over stdio (newline-delimited), 零依赖.
工具全部离线可用; 只有 scan_endpoint 需要目标端点凭据.
"""
import json
import sys

from . import __version__
from .probes import all_probes
from .spec_audit import audit_text

PROTOCOL_VERSION = "2024-11-05"
SERVER_NAME = "llm-red-team-scanner"

_TOOLS = [
    {
        "name": "audit_spec",
        "description": (
            "Statically audit a system prompt, agent spec, or tool description for "
            "injection-hijackable structure. Deterministic and offline: no model call, "
            "no network. Returns a 0-100 risk score, per-dimension findings with byte "
            "offsets and evidence, and copy-paste remediation for each hit."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "text": {"type": "string", "description": "The spec / system prompt / tool description to audit."},
                "kind": {"type": "string", "enum": ["system_prompt", "tool_description", "retrieved_content", "text"],
                         "description": "What the text is, used only for labeling the report."},
            },
            "required": ["text"],
        },
    },
    {
        "name": "list_probes",
        "description": (
            "List the built-in attack probes. 24 probes across 9 categories in the "
            "free set, 44 across 20 with pro=true. Returns id, category, and prompt text."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "category": {"type": "string", "description": "Only return probes in this category."},
                "pro": {"type": "boolean", "description": "Include the 20 PRO-only probes."},
            },
        },
    },
    {
        "name": "demo_scan",
        "description": (
            "Run the full probe corpus against a built-in offline mock target. "
            "Use this to see the report shape and scoring without any credentials."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {"pro": {"type": "boolean", "description": "Run all 44 probes instead of 24."}},
        },
    },
    {
        "name": "scan_endpoint",
        "description": (
            "Run attack probes against an OpenAI-compatible chat endpoint and return "
            "verdicts. Requires the endpoint's base_url, api_key, and model. "
            "Only use against systems you own or are authorized in writing to test."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "base_url": {"type": "string", "description": "e.g. https://api.openai.com/v1"},
                "api_key": {"type": "string"},
                "model": {"type": "string"},
                "category": {"type": "string", "description": "Only run this category."},
                "pro": {"type": "boolean", "description": "Run all 44 probes instead of 24."},
            },
            "required": ["base_url", "api_key", "model"],
        },
    },
]


def _all_probe_rows(pro=False):
    rows = list(all_probes())
    if pro:
        from .pro_probes import PROBES_PRO, render as render_pro
        for cat, probes in PROBES_PRO.items():
            for probe in probes:
                rows.append((cat, probe, render_pro(probe, cat)))
    return rows


def _tool_audit_spec(args):
    text = args.get("text")
    if not isinstance(text, str) or not text.strip():
        raise ValueError("text must be a non-empty string")
    return audit_text(text, args.get("kind") or "text")


def _tool_list_probes(args):
    pro = bool(args.get("pro"))
    cat = args.get("category")
    rows = [{"category": c, "id": p["id"], "prompt": t}
            for c, p, t in _all_probe_rows(pro) if not cat or c == cat]
    return {"probe_count": len(rows), "category_count": len({r["category"] for r in rows}), "probes": rows}


def _tool_demo_scan(args):
    from .cli import demo_target
    from .pro_scan import scan_pro
    from .scanner import scan
    results = scan_pro(demo_target) if args.get("pro") else scan(demo_target)
    flagged = [r for r in results if r.get("flagged")]
    return {
        "target": "demo-target",
        "probe_count": len(results),
        "flagged_count": len(flagged),
        "flagged": [{"probe_id": r["probe_id"], "category": r["category"], "matched": r.get("matched")}
                    for r in flagged],
    }


def _tool_scan_endpoint(args):
    from .cli import Target
    from .pro_scan import scan_pro
    from .scanner import scan
    target = Target(args["base_url"], args["api_key"], args["model"])
    cat = args.get("category")
    results = scan_pro(target, cat) if args.get("pro") else scan(target, cat)
    flagged = [r for r in results if r.get("flagged")]
    return {
        "target": "%s (%s)" % (args["base_url"], args["model"]),
        "probe_count": len(results),
        "flagged_count": len(flagged),
        "flagged": [{"probe_id": r["probe_id"], "category": r["category"], "matched": r.get("matched")}
                    for r in flagged],
    }


_HANDLERS = {
    "audit_spec": _tool_audit_spec,
    "list_probes": _tool_list_probes,
    "demo_scan": _tool_demo_scan,
    "scan_endpoint": _tool_scan_endpoint,
}


def _result(req_id, payload):
    return {"jsonrpc": "2.0", "id": req_id, "result": payload}


def _error(req_id, code, message):
    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}}


def handle(msg):
    """处理一条 JSON-RPC 消息. 返回响应 dict; 通知(无 id)返回 None."""
    method = msg.get("method")
    req_id = msg.get("id")
    params = msg.get("params") or {}
    if req_id is None:
        return None
    if method == "initialize":
        return _result(req_id, {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": SERVER_NAME, "version": __version__},
        })
    if method == "tools/list":
        return _result(req_id, {"tools": _TOOLS})
    if method == "tools/call":
        name = params.get("name")
        fn = _HANDLERS.get(name)
        if fn is None:
            return _error(req_id, -32602, "unknown tool: %s" % name)
        try:
            payload = fn(params.get("arguments") or {})
        except Exception as exc:
            return _result(req_id, {
                "content": [{"type": "text", "text": "%s: %s" % (type(exc).__name__, exc)}],
                "isError": True,
            })
        return _result(req_id, {
            "content": [{"type": "text", "text": json.dumps(payload, ensure_ascii=False)}],
            "isError": False,
        })
    if method in ("resources/list", "prompts/list"):
        return _result(req_id, {method.split("/")[0]: []})
    return _error(req_id, -32601, "method not found: %s" % method)


def main(argv=None):
    """从 stdin 逐行读 JSON-RPC, 逐行写响应. 空行与非 JSON 行忽略."""
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except ValueError:
            continue
        if not isinstance(msg, dict):
            continue
        resp = handle(msg)
        if resp is not None:
            sys.stdout.write(json.dumps(resp, ensure_ascii=False) + "\n")
            sys.stdout.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())

