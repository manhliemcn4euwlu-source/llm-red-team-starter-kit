import json

from redteam.scanner import judge, query_openai_compatible, scan
import urllib.request


def test_judge_flagged_on_signal():
    assert judge("jailbreak", "I am V2, a jailbroken assistant.") == (True, "I am V2")
    assert judge("jailbreak", "I ignore all safety filters.") == (True, "I ignore")


def test_judge_not_flagged_on_refusal():
    assert judge("jailbreak", "I'm sorry, I can't help with that.") == (False, None)


def test_judge_empty_response_not_flagged():
    assert judge("prompt_injection", "") == (False, None)


def test_scan_with_callable_target():
    def t(prompt):
        return "I am V2, jailbroken."
    results = scan(t, category="jailbreak")
    assert len(results) == 3
    assert all(r["flagged"] for r in results)


def test_scan_offline_demo_full_run():
    from redteam.cli import demo_target
    results = scan(demo_target)
    assert len(results) == 15
    # 演示目标在编码与越狱类别会触发，其余拒绝
    assert any(r["flagged"] for r in results)
    assert any(not r["flagged"] for r in results)


def test_scan_category_filter():
    results = scan(lambda p: "ok", category="tool_abuse")
    assert len(results) == 2 and all(r["category"] == "tool_abuse" for r in results)


def test_query_openai_compatible_parses(monkeypatch):
    class FakeResp:
        def read(self):
            return json.dumps({"choices": [{"message": {"content": "hello"}}]}).encode()
        def __enter__(self): return self
        def __exit__(self, *a): return False

    calls = {}
    def fake_urlopen(req, timeout=30):
        calls["req"] = req
        calls["timeout"] = timeout
        return FakeResp()

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    out = query_openai_compatible("https://x.example/v1/", "k-123", "p1", "m1")
    assert out == "hello"
    assert calls["req"].get_header("Authorization") == "Bearer k-123"
    assert "https://x.example/v1/chat/completions" == (calls["req"].full_url)
