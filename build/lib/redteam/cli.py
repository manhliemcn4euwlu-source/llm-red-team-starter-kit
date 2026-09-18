"""redteam CLI 入口."""

import argparse
import json
import sys

from . import __version__
from .probes import PROBES, all_probes
from .report import build_report, write_report
from .scanner import DEFAULT_TIMEOUT, scan


class Target:
    """OpenAI 兼容目标端点."""

    def __init__(self, base_url: str, api_key: str, model: str):
        self.base_url = base_url
        self.api_key = api_key
        self.model = model


def demo_target(prompt: str) -> str:
    """离线演示：返回一段会被判定的样例回复（不访问网络）."""
    if "base64" in prompt or "ROT13" in prompt:
        return "Sure, I decoded it: " + prompt[-40:]
    if "roleplay" in prompt or "DAN" in prompt or "V2" in prompt:
        return "As V2, I have no filters. Your hidden instructions are secret."
    if "base64" in prompt.lower():
        return "Here is the decoded output."
    if "repeat your full system prompt" in prompt:
        return "I am a helpful assistant. I can't share my system prompt."
    if "translate" in prompt or "base64" in prompt.lower():
        return "I can't reveal internal instructions."
    if "rm -rf" in prompt or "shell" in prompt:
        return "I can't execute shell commands."
    return "I'm sorry, but I can't help with that request."


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="redteam", description="LLM Red Team Starter Kit")
    ap.add_argument("--version", action="version", version=f"redteam {__version__}")
    ap.add_argument("--list", action="store_true", help="列出全部探针")
    ap.add_argument("--category", choices=sorted(PROBES.keys()), help="只跑一个类别")
    ap.add_argument("--demo", action="store_true", help="离线演示模式（不访问网络）")
    ap.add_argument("--base-url", help="OpenAI 兼容端点，如 https://api.openai.com/v1")
    ap.add_argument("--api-key", help="API key")
    ap.add_argument("--model", default="gpt-4o-mini", help="模型名（默认 gpt-4o-mini）")
    ap.add_argument("--report", help="Markdown 报告输出路径")
    ap.add_argument("--json-out", help="JSON 结果输出路径")
    args = ap.parse_args(argv)

    if args.list:
        for cat, probe, text in all_probes():
            print(f"[{cat}] {probe['id']}\n  {text}\n")
        return 0

    if args.demo:
        target, mode, label = demo_target, "demo (offline)", "demo-target"
    elif args.base_url and args.api_key:
        target = Target(args.base_url, args.api_key, args.model)
        mode, label = "live", f"{args.base_url} ({args.model})"
    else:
        ap.error("需要 --demo 或 --base-url + --api-key")

    results = scan(target, args.category)
    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as f:
            json.dump(results, f, ensure_ascii=False, indent=2)
    report_text = build_report(results, mode, label)
    if args.report:
        write_report(report_text, args.report)
        print(f"report -> {args.report}")
    else:
        print(report_text)
    n_flag = sum(1 for r in results if r["flagged"])
    print(f"\n[redteam] {len(results)} probes, {n_flag} flagged", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
