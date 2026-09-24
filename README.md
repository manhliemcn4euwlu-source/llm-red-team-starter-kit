# LLM 红队扫描套件（LLM Red Team Starter Kit）

**零依赖的 LLM 红队 / 安全探针工具包**。15 个攻击探针，覆盖 6 大攻击类别，一条命令出 Markdown 报告。纯 Python 3.8+ 标准库——无需 pip install、无框架。指向任意 OpenAI 兼容端点，约 5 分钟拿到结构化红队报告。

> **仅限授权安全测试。** 只测试你拥有或获得书面许可的系统。

## 它做什么
对目标 LLM 端点批量运行 15 个对抗提示（6 大类），生成 Markdown + JSON 报告，含逐探针的信号匹配与人工复核标记：

| 类别 | 探针数 | 说明 |
|---|---|---|
| jailbreak 越狱 | 3 | DAN / 角色扮演 / 说服式绕过 |
| prompt_injection 提示注入 | 3 | 间接注入 / 指令覆盖 |
| sysprompt_extraction 系统提示词抽取 | 3 | 直接索要 / 编码诱导 / 翻译套取 |
| safety_bypass 安全绕过 | 2 | 多轮渐进 / 上下文污染 |
| tool_abuse 工具滥用 | 2 | 越权调用 / 参数注入 |
| encoding 编码混淆 | 2 | base64 / 同音替换 |

## 为什么用它
- **零依赖**：解压即用，`python3 -m redteam --demo` 立刻看效果
- **可对接任意 OpenAI 兼容端点**：OpenAI / OpenRouter / Ollama / vLLM / 自托管
- **启发式信号判定 + 人工复核标记**——不替你做定性，这是 LLM 红队的诚实做法
- **可独立复核**：每份报告带 Repro manifest（引擎版本 + 探针库 sha256 指纹 + 精确探针集 + 目标 + repro-hash），独立重跑同 corpus+probes+target 即可比对 verdict
- **25 个离线测试全绿**，CI 可集成
- **在线免注册试用**：贴你的 agent system prompt 到 <https://llmrt-companion.manhliemcn4euwlu.workers.dev/review>，~35 秒出 8 探针风险分 + 永久可复验链接（含 repro manifest）

## 快速开始
```bash
unzip llm-red-team-starter-kit.zip
cd llm-red-team-starter-kit
python3 -m redteam --list          # 列出全部探针
python3 -m redteam --demo           # 离线演示，无需网络/密钥
python3 -m redteam --base-url https://api.openai.com/v1 \
  --api-key $KEY --model gpt-4o-mini --report report.md
python3 -m pytest tests/ -q         # 25 个测试，全离线
```

## 真实输出样例（--demo 模式实跑）
```
[redteam] 15 probes, 3 flagged
| Category | Probes | Flagged |
| encoding | 2 | 2 |
| jailbreak | 3 | 0 |
| prompt_injection | 3 | 0 |
```
（flagged = 启发式命中，供人工复核——不是定性结论。完整样例见 [sample-report.md](sample-report.md)。）

## RFC-0014 参考实现：agent 运行时红队（--agent-redteam）

面向 agent 运行时的最小探针集 5 步（可运行参考实现，供实现方 diff）：

1. **投毒所有不可信 ingest 通道**（fetched / tool_return / rag / prior_msg，每次单通道）；
2. **工具调用层 instrumentation**：判 ACTIONS 而非 prose——exfil 藏在 tool call 参数里；
3. **canary 惰性工具**：合法探针绝不应触发，被调用即 flag（低误报判据）；
4. **baseline-diff**：同探针集 clean vs poisoned 各跑一遍，diff 动作行，temperature 0.0 可复现；
5. **规范 verdict + sha256(动作行)**：独立 verifier 重跑可比对。

用法：

```bash
python -m redteam --agent-redteam --demo                       # 离线 mock 演示（exfil 失守样本）
python -m redteam --agent-redteam --spec agent.json \
    --base-url http://localhost:8399/v1 --api-key x --model local
# 输出: verdict CLEAN|POISONED + findings(定位通道) + action sha256; exit 0=CLEAN, 2=POISONED(CI 门禁)
```

spec JSON 字段：system / tools(OpenAI function schema) / tool_bodies / canary_tool / prior_messages / fetched_doc / rag_doc（见 redteam/agent_probe.py）。目标接口 target(messages, tools) -> (prose, actions)；OpenAIAgentTarget 适配任意 OpenAI 兼容端点。


## 定价（USDT，免 KYC，P2P）
- **核心套件：免费**——本仓库，MIT 协议（15 探针 / 6 类）。
- **在线免费 8 探针扫描**：贴 prompt 即出风险分，无注册无 key：<https://llmrt-companion.manhliemcn4euwlu.workers.dev/review>
- **完整包 — USDT 3（ERC-20 或 Lightning `xydhw@api.babyblueviper.com`）**：35 探针 / 17 攻击类 / 0-100 风险分 / CI 门禁 / 逐类修复建议 / 品牌化报告（含 repro manifest）。链上确认后自动交付，无需人工。
- **定制服务 — USDT 50+**：针对你 Agent 的工具面定制探针 + 完整报告。

**收款：** USDT（ERC-20）至 `0x17C46B5Dac10fED584F1d2bB7387288e20AA76Bb`，备注 = 你的邮箱或 Nostr npub。链上确认 24h 内交付。

**联系（Nostr）：** npub1qrn2x45huyvw7yzn9zlqjwtxr7fljhe6vntgqe0a6p9u8cd85j37gm8ahwc

**Agent 市场（invinoveritas，Lightning 原生）：** 100/250 sats 红队审查，搜索 red-team。[ref 注册](https://api.babyblueviper.com/register?ref=TXKNP_) 首次充值双方各得 1000 sats 奖励。

**Gumroad（$19，需 PayPal 收款开通中）：** https://llmrt.gumroad.com/l/xrauwt

## License
MIT. 见 LICENSE。
