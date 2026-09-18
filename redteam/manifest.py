"""Repro manifest: 让独立复核者核对"同引擎同探针库同配置"的可复现清单.
零依赖. 引擎版本 + 探针库指纹 + 精确探针集 + 目标 + 复现哈希.
同一 corpus+probes+target+config 的两次运行, verdict 可比较(本地贪心非逐位确定, 见报告边界说明)."""
import hashlib
import json


def corpus_sha(probes, n=12):
    """探针库指纹: 对 {类别: [探针id]} 做规范 sha256 截断."""
    canon = json.dumps({k: [p.get("id") for p in v] for k, v in probes.items()},
                       sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canon.encode("utf-8")).hexdigest()[:n]


def base_corpus_sha(n=12):
    from .probes import PROBES
    return corpus_sha(PROBES, n)


def repro_manifest(results, probes, version, target_label, generated_ts=""):
    """返回一行可复现清单文本."""
    ids = sorted(r.get("probe_id") for r in results)
    payload = json.dumps({"engine": "redteam/" + version, "corpus": corpus_sha(probes),
                          "probes": ids, "target": target_label},
                         sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    h = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]
    return ("Repro manifest - engine redteam/" + version +
            " | probe-corpus sha256:" + corpus_sha(probes) +
            " | probes(" + str(len(ids)) + "): " + ", ".join(ids) +
            " | target: " + target_label +
            (" | generated " + generated_ts if generated_ts else "") +
            " | repro-hash " + h +
            "  (same corpus+probes+target+config => comparable verdict)")
