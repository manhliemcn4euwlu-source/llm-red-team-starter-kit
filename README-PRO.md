# LLM Red-Team Starter Kit — PRO

Paid tier: everything in the free kit plus 20 additional attack vectors,
risk scoring with CI gate, per-class remediation, and brandable reports.

> Authorized security testing only. Test only systems you own or have written permission to test.

## What PRO adds (over the free kit)
- 20 extra probes (11 new categories) -> 35 total across 17 categories
- Risk score 0-100 with LOW/MEDIUM/HIGH/CRITICAL bands
- CI gate: exit code 2 when risk exceeds your threshold (pipeline-blocking)
- Per-class remediation guidance in every report
- Brandable reports (default "RedTeam PRO")
- Multilingual injection set (EN/ES/ZH/AR)

New PRO categories:
multi_turn_drift / indirect_injection / cross_language / encoding_ext /
persona_stacking / refusal_escalation / tool_chain / sycophancy_boost /
data_exfil / social_engineering / context_overflow

## Quick start
```bash
unzip llm-red-team-starter-kit-PRO.zip
cd llm-red-team-starter-kit
python3 -m redteam --list          # all 35 probes
python3 -m redteam --demo --pro     # offline demo, 35 probes + risk score
python3 -m redteam --base-url https://api.openai.com/v1 \
  --api-key YOUR_KEY --model gpt-4o-mini --pro --report report.md
python3 -m pytest tests/ -q         # 25 tests, offline
```

## CI integration (gate your pipeline)
Shell (any CI):
```bash
# args: BASE_URL API_KEY MODEL MAX_RISK REPORT_OUT (empty URL = offline self-check)
bash ci/redteam_ci.sh "$BASE_URL" "$API_KEY" "$MODEL" 60 report.md
# exit 0 = pass, exit 2 = risk above threshold -> fail the build
```
GitHub Actions: .github/workflows/redteam.yml runs the same gate on push/PR
and uploads the report as an artifact. Set secrets LLM_API_KEY / vars LLM_MODEL
to scan a live endpoint, leave empty for the offline self-check.

## Report sample (PRO)
- Probes run: 35, Flagged: 3 (8.6%)
- Risk score: 22/100 (LOW)
- Summary by Category table (17 rows)
- Remediation (per flagged class) with actionable fixes

## What stays the same
- Zero dependencies, pure Python 3.8+ stdlib, works with any OpenAI-compatible
  endpoint (OpenAI / OpenRouter / Ollama / vLLM / self-hosted)
- Heuristic signal matching + human-review flags; we do not make the call for you
- MIT license, same as the free kit

## License
MIT. See LICENSE.
