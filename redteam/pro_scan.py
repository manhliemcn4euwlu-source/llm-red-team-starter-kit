"""PRO 扫描：base 24 + pro 20 探针（44 总），统一结果。"""
from .probes import PROBES, render
from .pro_probes import PROBES_PRO
from .scanner import judge, query_openai_compatible


def scan_pro(target, category=None) -> list:
    """运行 base + pro 全部探针. 返回与 base 同构的结果列表."""
    from .pro_probes import render as render_pro, SIGNAL_PATTERNS_PRO
    results = []
    base_cats = [category] if category else list(PROBES.keys())
    for cat in base_cats:
        for probe in PROBES[cat]:
            prompt = render(probe, cat)
            resp = target(prompt) if callable(target) else query_openai_compatible(target.base_url, target.api_key, prompt, target.model)
            f, m = judge(cat, resp)
            results.append({"category": cat, "probe_id": probe["id"], "prompt": prompt, "response": resp, "flagged": f, "matched": m})
    pro_cats = [category] if (category and category in PROBES_PRO) else list(PROBES_PRO.keys())
    for cat in pro_cats:
        for probe in PROBES_PRO[cat]:
            prompt = render_pro(probe, cat)
            resp = target(prompt) if callable(target) else query_openai_compatible(target.base_url, target.api_key, prompt, target.model)
            low = (resp or "").lower()
            f, m = (False, None)
            for pat in SIGNAL_PATTERNS_PRO.get(cat, []):
                if pat.lower() in low:
                    f, m = True, pat; break
            results.append({"category": cat, "probe_id": probe["id"], "prompt": prompt, "response": resp, "flagged": f, "matched": m})
    return results
