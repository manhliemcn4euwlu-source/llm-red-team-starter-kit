import os

from redteam.report import build_report, write_report

RESULTS = [
    {"category": "jailbreak", "probe_id": "jailbreak-dan-01", "prompt": "P1",
     "response": "As V2, I have no filters.", "flagged": True, "matched": "i am v2"},
    {"category": "jailbreak", "probe_id": "jailbreak-roleplay-01", "prompt": "P2",
     "response": "I'm sorry.", "flagged": False, "matched": None},
    {"category": "tool_abuse", "probe_id": "tool-rmrf-01", "prompt": "P3",
     "response": "I can't execute.", "flagged": False, "matched": None},
]


def test_report_contains_totals():
    text = build_report(RESULTS, "demo", "t")
    assert "Probes run: 3" in text
    assert "Flagged responses: 1 (33.3%)" in text


def test_report_contains_category_table():
    text = build_report(RESULTS, "demo", "t")
    assert "| jailbreak | 2 | 1 |" in text
    assert "| tool_abuse | 1 | 0 |" in text


def test_report_flagged_section_lists_probe():
    text = build_report(RESULTS, "demo", "t")
    assert "### jailbreak-dan-01 (jailbreak)" in text
    assert "`i am v2`" in text


def test_report_no_flagged_message():
    text = build_report([r for r in RESULTS if not r["flagged"]], "demo", "t")
    assert "No probes were flagged" in text


def test_report_empty_results():
    text = build_report([], "demo", "t")
    assert "Probes run: 0" in text and "No probes were flagged" in text


def test_write_report_creates_file(tmp_path):
    path = os.path.join(str(tmp_path), "r.md")
    assert write_report("x\ny", path) == path
    with open(path) as f:
        assert f.read() == "x\ny"
