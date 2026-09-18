# 上架材料 — LLM Red Team Starter Kit

## 一句话定位（EN）
A zero-setup LLM red teaming kit: 15 attack prompts across 6 categories, a pure-stdlib Python CLI, and one-click Markdown reports — scan any OpenAI-compatible model in 5 minutes.

## 一句话定位（中文）
零环境 LLM 红队自检包：15 个攻击探针 × 6 大类 + 纯标准库 CLI + 一键 Markdown 报告，5 分钟扫完任意 OpenAI 兼容模型。

## 产品描述（EN）
You shipped a chatbot or agent. Has anyone tried to break it?

LLM Red Team Starter Kit is a ready-to-run attack pack for LLM apps. It ships 15 crafted attack prompts — jailbreaks, prompt injection, system-prompt extraction, safety bypasses, tool abuse, and encoding obfuscation — plus a zero-dependency Python CLI that runs them against your endpoint and writes a review-ready Markdown report.

No pip installs. No configuration files. No agent framework. Unzip and scan:

    python3 -m redteam --demo            # offline demo, no API key
    python3 -m redteam --base-url https://api.openai.com/v1 \
      --api-key $KEY --model gpt-4o-mini --report report.md

Works with any OpenAI-compatible /chat/completions endpoint, including local models (Ollama, vLLM).

## 产品描述（中文）
你上线了一个 Chatbot 或 Agent。有人试过攻破它吗？

LLM Red Team Starter Kit 是面向 LLM 应用的现成攻击包：15 个精心构造的攻击提示词（越狱、提示注入、系统提示词抽取、安全绕过、工具滥用、编码混淆）+ 零依赖 Python CLI，对你的端点一键扫描并生成可直接贴进发布评审的 Markdown 报告。

无需 pip 安装、无需配置文件、无需 agent 框架。解压即用：

    python3 -m redteam --demo            # 离线演示，无需 API key
    python3 -m redteam --base-url https://api.openai.com/v1 \
      --api-key $KEY --model gpt-4o-mini --report report.md

任何 OpenAI 兼容 /chat/completions 端点均可，含本地模型（Ollama、vLLM）。

## 3 条卖点
1. **5 分钟出报告** — 15 探针一键跑完，Markdown 报告直接进发布评审，不依赖任何框架
2. **零环境、可信任** — 纯 Python 标准库，解压即用；`--demo` 离线模式无密钥也能先看形态，测试套件 22 用例全绿
3. **端点无关** — 扫任何 OpenAI 兼容 API（OpenAI/OpenRouter/本地 Ollama/vLLM），一个命令切模型

## 建议价格与 pay-what-you-want
- 锚点价：**$19**（个人/单开发者）
- 团队版（5 席）：**$49**（上架第二个产品或升级项）
- PWYW 区间：**$5–$50**（Gumroad 设 min $5 / 锚点 $19；Lemon Squeezy 设 base $19 + 自定义加价）
- 定价依据：Gumroad 同类 Claude Code skills/rules 包成交带 $9–49（竞品 ColdIQ GTM Skills 269★ 同形态）；安全类为空白位，取中位锚点

## 上架最小步骤（用户执行）
1. 打包：`cd llm-red-team-starter-kit && zip -r ../llm-red-team-starter-kit.zip . -x "__pycache__/*" "*.pyc"`（ZIP 内含 README/LISTING 可删，留 README+LICENSE+redteam/+tests/）
2. Gumroad：Create product → Digital product → 上传 ZIP → 填标题/描述（用本文件 EN 文案）→ 价格 $19 + 勾选 pay what you want（min $5）→ Publish
3. Lemon Squeezy / Payhip 同理：Digital product → 上传 ZIP → 复制文案 → $19 + 自定义加价
4. 交付注意：数字文件无需物流；在描述里写清"需 Python 3.8+"

## 交付物清单（ZIP 内容）
- redteam/ — 探针库、扫描器、报告、CLI（__main__ 入口）
- tests/ — 22 用例 pytest 门禁
- README.md / LICENSE (MIT)
