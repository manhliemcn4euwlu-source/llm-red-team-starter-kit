"""Markdown 扫描报告生成."""

import datetime

from . import manifest as _manifest
from .probes import PROBES
from . import __version__


def build_report(results: list, mode: str, target_label: str) -> str:
    """生成 Markdown 报告文本."""
    total = len(results)
    flagged = [r for r in results if r["flagged"]]
    n_flagged = len(flagged)
    rate = (100.0 * n_flagged / total) if total else 0.0
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")

    lines = [
        "# LLM Red Team Report",
        "",
        f"- Generated: {now}",
        f"- Mode: {mode}",
        f"- Target: {target_label}",
        f"- Probes run: {total}",
        f"- Flagged responses: {n_flagged} ({rate:.1f}%)",
        "",
        "## Summary by Category",
        "",
        "| Category | Probes | Flagged |", "| --- | --- | --- |",
    ]
    for cat in sorted({r["category"] for r in results}):
        cat_r = [r for r in results if r["category"] == cat]
        cat_f = sum(1 for r in cat_r if r["flagged"])
        lines.append(f"| {cat} | {len(cat_r)} | {cat_f} |")

    lines += ["", "## Flagged Probes (needs review)", ""]
    if flagged:
        for r in flagged:
            lines += [
                f"### {r['probe_id']} ({r['category']})",
                "",
                f"- Matched signal: `{r['matched']}`",
                "- Prompt:", "  ```", r["prompt"], "  ```",
                "- Response:", "  ```", r["response"][:2000], "  ```",
                "",
            ]
    else:
        lines += ["No probes were flagged. The target refused or deflected every attack.", ""]

    lines += ["## All Probes", "", "| Probe | Category | Flagged |", "| --- | --- | --- |"]
    for r in results:
        lines.append(f"| {r['probe_id']} | {r['category']} | {'YES' if r['flagged'] else 'no'} |")
    lines += ["", "## Reproducibility", "",
              _manifest.repro_manifest(results, PROBES, __version__, target_label, now),
              "", "*Flagged = heuristic keyword match; always review before drawing conclusions.",
              "*Local/greedy targets are not bitwise-deterministic across runs; the repro manifest lets an independent reviewer re-run the same corpus+probes+target and compare verdicts.*"]
    return "\n".join(lines)


def write_report(text: str, path: str) -> str:
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)
    return path
