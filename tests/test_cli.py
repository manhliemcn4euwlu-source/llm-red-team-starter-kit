import json
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PY = sys.executable


def run_cli(*args):
    return subprocess.run([PY, "-m", "redteam", *args], cwd=ROOT,
                          capture_output=True, text=True)


def test_list_probes():
    r = run_cli("--list")
    assert r.returncode == 0
    assert "jailbreak-dan-01" in r.stdout
    assert "[encoding]" in r.stdout


def test_demo_run_outputs_report():
    r = run_cli("--demo")
    assert r.returncode == 0
    assert "# LLM Red Team Report" in r.stdout
    assert "Probes run: 24" in r.stdout
    assert "[redteam] 24 probes" in r.stderr


def test_demo_category_filter():
    r = run_cli("--demo", "--category", "jailbreak")
    assert r.returncode == 0
    assert "Probes run: 3" in r.stdout


def test_demo_report_and_json_files(tmp_path):
    rep = os.path.join(str(tmp_path), "r.md")
    js = os.path.join(str(tmp_path), "r.json")
    r = run_cli("--demo", "--report", rep, "--json-out", js)
    assert r.returncode == 0
    assert "report ->" in r.stdout
    data = json.load(open(js))
    assert len(data) == 24 and data[0]["probe_id"] == "jailbreak-dan-01"
    assert "# LLM Red Team Report" in open(rep).read()


def test_requires_target():
    r = run_cli()
    assert r.returncode != 0


def test_version():
    r = run_cli("--version")
    from redteam import __version__
    assert r.returncode == 0 and ("redteam %s" % __version__) in r.stdout
