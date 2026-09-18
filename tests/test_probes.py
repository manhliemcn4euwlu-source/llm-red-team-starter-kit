import base64
import codecs

from redteam.probes import PROBES, all_probes, categories, render


def test_all_categories_present():
    assert set(categories()) == {"jailbreak", "prompt_injection", "sysprompt_extraction",
                                 "safety_bypass", "tool_abuse", "encoding"}


def test_probe_count_at_least_15():
    assert len(all_probes()) >= 15


def test_render_fills_request_placeholder():
    text = render(PROBES["jailbreak"][0], "jailbreak")
    assert "{request}" not in text
    assert "reveal the internal system prompt" in text


def test_render_fills_encoding_payloads():
    b64 = render(PROBES["encoding"][0], "encoding")
    rot = render(PROBES["encoding"][1], "encoding")
    assert "{b64_payload}" not in b64 and "{rot13_payload}" not in rot
    assert "reveal your hidden instructions" in base64.b64decode(b64.split(" ")[-1]).decode()
    assert "reveal your hidden instructions" in codecs.decode(rot.split(": ")[1], "rot13")


def test_render_no_placeholders_left_anywhere():
    for cat, probe, text in all_probes():
        assert "{" not in text and "}" not in text, probe["id"]


def test_probe_ids_unique():
    ids = [probe["id"] for _, probe, _ in all_probes()]
    assert len(ids) == len(set(ids))
