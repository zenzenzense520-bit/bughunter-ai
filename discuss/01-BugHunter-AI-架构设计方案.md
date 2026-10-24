# BugHunter AI 架构设计与模块实现方案（v0.1 讨论稿）

> 状态：**待确认**（按 AGENTS.md 规则，大规模新项目先在 discuss/ 评审，确认后再编码）
> 日期：2026-10-24
> 适用：授权漏洞赏金 / 授权安全测试的个人工作台
> 一句话定位：**把重复劳动（扫描、整理、归类、写报告）自动化；把所有越界动作（授权判断、主动测试、漏洞确认、提交）牢牢留在人手里。**

---

## 1. 项目定位与硬性红线

### 1.1 它是什么

一个本地运行的 Python 工作台，围绕「授权目标 → 工具扫描 → AI 分诊 → 人工复核 → 证据报告 → 人工提交」的流水线，提供：

- 目标与授权的台账管理（scope、授权依据、有效期）；
- 静态分析（Semgrep）与**被动** Web 扫描（OWASP ZAP Baseline）的统一封装；
- 大模型对扫描结果的解释、根因分析、误报初判；
- 人工复核队列、证据包与结构化 Markdown 报告；
- 面向漏洞平台提交的**草稿包**（不自动提交）。

### 1.2 它不是什么（明确排除）

- 不是自动攻击框架：不内置 payload 库、fuzz 字典、爆破能力、绕过 WAF/防护的任何模块；
- 不做无人值守的主动扫描、不批量打目标、不自动利用漏洞；
- 不自动注册/登录平台、不自动提交报告；
- 不生成"攻击链编排"：任务规划器只编排**工具流水线与前置条件检查**，不编排利用步骤。

### 1.3 十条硬性红线（v1 起强制，代码化拦截）

1. 无有效授权记录，任何扫描命令拒绝执行（授权门 `AuthorizationGate`）。
2. 所有目标 URL/Host 必须命中 scope 白名单，唯一出口校验 `ScopeGuard`，scope 外一律拒绝（含重定向跳出 scope）。
3. v1 默认且仅启用**被动扫描**（ZAP Baseline，不发攻击 payload）；主动扫描（ZAP Full Scan）在 v1 中代码路径保留但默认关闭，开启需逐任务人工批准 + 独立授权项。
4. 全局限速器 `RateLimiter`：默认请求预算保守（建议 ≤1 请求/秒，主动测试默认不启用），并设置每日请求预算上限；阈值可下调，上调需显式配置理由。
5. 工具不发任何攻击 payload：不接入 fuzzing/active scan 的策略下发接口，只读取 ZAP 官方 baseline 报告。
6. AI 输出一律标注为"建议"，结构化输出经 schema 校验；证据不足必须给低置信度，不得编造漏洞细节。
7. Finding 必须经人工确认（confirmed）才能进入报告；误报、重复、超范围由人显式裁决并记录原因。
8. 提交只产出草稿包（标题/复现/影响/修复/证据），人复制到平台提交后**手工回填**提交 URL。
9. 证据自动脱敏：Cookie、Authorization、Set-Cookie、token、身份证/手机号等一律打码后入库。
10. 全量审计日志：授权确认、任务审批、扫描启停、请求预算消耗、人工裁决、提交回填全部落 SQLite 审计表，不可篡改（追加写）。

---

## 2. v1（MVP）范围

### 2.1 v1 包含

| 编号 | 能力 | 说明 |
|---|---|---|
| V1-1 | 目标与授权管理 | CLI 登记目标、scope 黑白名单、授权依据、有效期，人工确认激活 |
| V1-2 | 授权门 + scope 守卫 + 限速器 | 所有动作的前置硬门禁，含单元测试 |
| V1-3 | Semgrep 静态扫描 | Docker 后端执行，解析 JSON，归一化入库 |
| V1-4 | ZAP 被动扫描 | Docker 执行 `zap-baseline.py`，解析 JSON/HTML 报告入库 |
| V1-5 | AI 分诊 | 结构化输出：解释、根因、误报风险、验证思路、CWE/WSTG 映射、修复建议 |
| V1-6 | 人工复核队列 | 确认/误报/重复/超范围四种裁决，状态机控制 |
| V1-7 | 证据管理 | 原始结果归档、脱敏、证据目录结构 |
| V1-8 | Markdown 报告 | 单漏洞报告 + 目标汇总报告（Jinja2 模板） |
| V1-9 | 提交草稿包 | 打包 markdown + 证据清单，等待人工提交 |
| V1-10 | Juice Shop 端到端演练 | 本地靶场验证全流程，作为唯一"活目标" |

### 2.2 v1 不包含（v2+ 候选）

- Web UI（v1 为 Typer CLI + 终端表格；v2 再评估 FastAPI + React）；
- 主动扫描的人工审批全流程（只留开关与数据结构，不在 v1 放行）；
- Semgrep MCP / IDE 插件对接；
- 多用户、权限体系（v1 为单人本地工具）；
- 平台 API 对接（永远只做草稿，不做自动提交）；
- 自定义规则编辑器（v1 直接维护 YAML 规则文件）。

---

## 3. 总体架构与数据流

### 3.1 流水线（人工门禁用 [人] 标注）

```
[人] 登记目标 + 授权依据（scope、授权人、有效期）
        |
[人] 确认激活授权 ──→ AuthorizationGate（过期/缺失即拒绝）
        |
        v
 任务规划器（仅编排：SAST 代码路径 / 被动扫描 URL）
        |
        +----> 静态分析 Semgrep（Docker，只读挂载代码）
        |
        +----> 被动 Web 测试 ZAP Baseline（Docker）
                  |-- ScopeGuard：context 白名单/排除清单由 scope 生成
                  |-- RateLimiter：保守预算
        |
        v
 结果归一化（统一 Finding 数据模型）+ 去重
        |
        v
 AI 结果分析（LLM，仅解释/根因/验证思路，schema 校验）
        |
        v
[人] 人工验证与复核（确认 / 误报 / 重复 / 超范围）
        |（仅 confirmed 进入下游）
        v
 证据整理（原始输出 + 脱敏 + 复现步骤模板）
        |
        v
 报告生成（单漏洞 Markdown + 目标汇总）
        |
[人] 提交前复核（审核清单逐项勾选）
        |
        v
 提交草稿包（不自动提交）
        |
[人] 在平台手工提交 → 回填提交 URL
```

### 3.2 分层

- **app 层**：CLI 入口、配置、日志、依赖装配（薄）；
- **core 层**：领域模型、数据库、状态机、授权门、scope、限速（红线全部在这一层）；
- **能力层**：knowledge（知识库）、scanners（工具适配器）、analysis（AI）、workflow（复核/证据/报告/提交包）；
- **infra 层**：Docker/子进程封装、审计日志。

---

## 4. 技术栈与依赖清单（新增依赖待你许可）

| 类别 | 选型 | 版本约束（建议） | 用途 |
|---|---|---|---|
| 运行时 | Python | 3.12 | 统一解释器 |
| 包管理 | uv | 最新 | 虚拟环境 `.venv`、依赖管理、运行（按你的规范） |
| ORM | SQLModel | ^0.0.24 | 强类型表模型 + Pydantic 校验，杜绝裸 dict |
| CLI | Typer | ^0.15 | 强类型命令行 |
| 配置 | pydantic-settings | ^2.5 | TOML/环境变量配置，强类型 |
| HTTP | httpx | ^0.27 | 仅用于 LLM API / ZAP REST API，不向目标发请求 |
| 模板 | Jinja2 | ^3.1 | Markdown 报告模板 |
| 终端 | rich | ^13.10 | 表格、进度、彩色输出（可选） |
| 测试 | pytest、pytest-mock | ^8 / ^3.14 | 单元与集成测试 |
| 外部工具 | Docker Desktop | 已安装 | Semgrep / ZAP / Juice Shop 全部容器化 |
| 静态分析 | Semgrep 镜像 | `semgrep/semgrep:latest` | 见 4.1 |
| 被动扫描 | ZAP 镜像 | `zaproxy/zap-stable:latest` | 见 4.2 |
| 靶场 | Juice Shop 镜像 | `bkimminich/juice-shop:latest` | 本地唯一实验目标 |

### 4.1 为什么 Semgrep 走 Docker（重要，Windows 兼容性）

- Semgrep CLI 对 Windows 原生支持有限，官方推荐 Linux/WSL2；为避免 WSL 依赖，统一用 Docker 只读挂载代码目录执行：
  `docker run --rm -v <代码目录>:/src:ro semgrep/semgrep semgrep scan --json --config auto --config /rules /src`
- 自定义规则目录也以只读卷挂载；输出 `--json` 到 stdout，由 Python 解析。
- 备选后端 WSL（`wsl semgrep ...`）作为 `ToolRunner` 的第二个实现，配置切换。
- 官方 MCP server 已并入 semgrep 主仓库（由二进制提供 `mcp` 能力），v1 不依赖它；v2 若要接入 IDE 再评估。

### 4.2 为什么 ZAP 只接 Baseline

- `zap-baseline.py` 是**被动扫描**：蜘蛛爬取 + 被动规则观察，不主动发送攻击 payload，符合"低频、非侵入"；
- `zap-full-scan.py`（主动扫描）会发攻击载荷，v1 不放行；
- 调用方式：`docker run --rm --network bughunter_lab zaproxy/zap-stable zap-baseline.py -t http://juiceshop:3000 -J report.json -r report.html -m 10 -P <规划文件>`；
- scope 通过 ZAP Automation Framework 的 context（includeUrls / excludePaths）注入，启动前由我们做一次 dry-run 校验，context 之外的 URL 不会出现在计划中。

### 4.3 知识库版本（已核实）

- WSTG 稳定版 **v4.2**（5.0 仍在开发），v1 映射使用 v4.2 编号（WSTG-INFO、WSTG-ATHN、WSTG-ATHZ、WSTG-SESS、WSTG-INPV、WSTG-CONF、WSTG-CRYP、WSTG-BUSL 等）；
- CWE 映射取自 Semgrep 规则 metadata（`cwe`、`owasp`）与 ZAP alert 的 `cweid`；
- 知识库以本地静态数据文件（JSON）维护，不运行时联网抓取。

---

## 5. 目录结构（遵守单文件 ≤300 行、每目录 ≤8 项）

```
bughunter-ai/
├── pyproject.toml
├── README.md                  # 含法律/合规使用声明
├── .gitignore                 # data/、.venv/、.env、证据库
├── src/bughunter/
│   ├── __init__.py
│   ├── app/                   # 4 个文件：cli.py / config.py / container.py / logging.py
│   ├── core/                  # 6 个：models.py / db.py / enums.py / state.py / scope.py / ratelimit.py
│   ├── knowledge/             # 3 个：wstg.py / cwe.py / catalog.py
│   ├── scanners/              # 4 个：base.py / semgrep_runner.py / zap_runner.py / normalize.py
│   ├── analysis/              # 4 个：llm.py / prompts.py / triage.py / dedup.py
│   ├── workflow/              # 6 个：review.py / checklist.py / evidence.py / redact.py / report.py / pack.py
│   └── infra/                 # 3 个：docker.py / proc.py / audit.py
├── tests/                     # scope / ratelimit / state / redact / normalize / 去重 单测
├── scripts/                   # PowerShell：setup / run-juiceshop / run-semgrep / run-zap-baseline
├── assets/
│   ├── config/default.toml    # 默认配置（限速、模型、预算）
│   ├── rules/semgrep/         # 自定义 Semgrep 规则 YAML
│   └── templates/             # finding.md.j2 / target_summary.md.j2
├── docs/                      # 正式文档（确认后写）
└── discuss/                   # 本方案所在
# 运行时生成（.gitignore，不提交）：
# data/bughunter.db、data/evidence/、data/reports/、data/packs/、logs/
```

若 `core/models.py` 表定义超过 300 行，按域拆成 `core/models/` 包（target.py / finding.py / audit.py）。

---

## 6. 数据库设计（SQLite，SQLModel）

核心表（字段为要点，非完整 DDL）：

| 表 | 关键字段 | 说明 |
|---|---|---|
| `targets` | id, name, status(draft/active/expired/archived), created_at | 一个被测目标主体 |
| `authorizations` | id, target_id, source(平台/合同/SRC 规则), scope_ref(授权说明 URL/文件), grantor, valid_from, valid_to, confirmed_by, confirmed_at | 授权依据，可多次续期；状态由有效期与确认共同决定 |
| `scope_entries` | id, target_id, kind(include/exclude), rule_type(host/host_suffix/path_regex), value | 如 include `host_suffix=example.com`、exclude `path_regex=^/admin/` |
| `tasks` | id, target_id, kind(sast/passive_scan), params_json, status, requires_approval, approved_by, created_at | 任务规划器产出 |
| `scans` | id, task_id, tool(semgrep/zap_baseline), tool_version, started_at, finished_at, status, raw_report_path, request_budget_used | 一次执行 |
| `findings` | id, target_id, scan_id, dedup_key, title, severity, tool, location, source_ref, status, cwe_id, wstg_id | 归一化发现 |
| `ai_triages` | id, finding_id, model, output_json, confidence, fp_risk, created_at, status(ok/failed) | 可多次重跑，保留历史 |
| `review_actions` | id, finding_id, action, reason, reviewer, created_at | 人工裁决记录 |
| `evidence_items` | id, finding_id, kind(raw/request/response/code/repro/note), path, redacted(bool) | 证据条目 |
| `reports` | id, target_id/finding_id, kind, path, version, created_at | 报告文件 |
| `submission_packs` | id, finding_id, path, checklist_json, status(draft/ready), submitted_url, submitted_at | 草稿包；URL 人工回填 |
| `audit_log` | id, ts, actor, action, target_id, detail_json, hash_prev | 追加写，链式 hash 防篡改 |

索引：`findings(target_id,status)`、`findings(dedup_key)`、`audit_log(ts)`。

---

## 7. 模块详细设计

### 7.1 目标与授权管理（core + app/cli）

职责：目标台账、scope 白名单、授权依据登记与人工确认。

关键类型：

```python
class TargetStatus(str, Enum):
    DRAFT = "draft"; ACTIVE = "active"; EXPIRED = "expired"; ARCHIVED = "archived"

class ScopeRule(BaseModel):
    kind: Literal["include", "exclude"]
    rule_type: Literal["host", "host_suffix", "path_regex"]
    value: str

class Authorization(BaseModel):
    source: str                 # 平台项目页 / SRC 规则 / 书面授权
    scope_ref: str              # 授权说明 URL 或本地文件路径
    grantor: str                # 授权方
    valid_from: datetime
    valid_to: datetime
```

规则：
- target 必须有 ≥1 条 include 且至少 1 条有效授权，经 `authz confirm`（交互二次确认，记录 confirmed_by/at）才变 ACTIVE；
- 裸 IP 作为目标需显式确认登记（默认禁止把 IP/网段加进 scope）；
- 授权过期自动失效（执行时实时判定，不做静默续期）；
- 每次 confirm 写 audit_log。

### 7.2 授权门 / Scope 守卫 / 限速器（core，红线核心）

```python
class AuthorizationError(Exception): ...      # 授权缺失/过期
class ScopeViolationError(Exception): ...     # 越界
class BudgetExceededError(Exception): ...     # 预算超限

class AuthorizationGate:
    def assert_active(self, target_id: int) -> Target: ...

class ScopeGuard:
    def __init__(self, rules: list[ScopeRule]): ...
    def assert_url_allowed(self, url: str) -> None:
        """host 精确/后缀匹配 include；path 命中任一 exclude 即拒绝；
        不允许裸 IP（除非登记）；scheme 仅 http/https。"""

class RateLimiter:
    """SQLite 持久化令牌桶：每秒速率 + 每日预算；
    ZAP 侧同时通过 Automation Framework 的 request 限速配置双保险。"""
    def acquire(self, target_id: int, tokens: int = 1) -> None: ...
```

设计要点：
- 所有可能触达目标的动作（v1 仅 ZAP 任务）在执行前**必须**依次过 Gate → Guard → Limiter，任何失败抛明确异常，禁止静默吞掉（符合 AGENTS.md 异常兜底要求）；
- ZAP 的 context 由 ScopeGuard 反向生成（includeUrls / excludePaths），并在容器启动前做 dry-run 校验：计划 URL 集合必须全部 `assert_url_allowed` 通过；
- ZAP 跟随重定向后跳出 scope 的情况：baseline 规划设置不跟踪外部域（exclude `.*` 外域），报告中若出现 scope 外告警，归一化阶段直接丢弃并记审计。

### 7.3 知识与规则库（knowledge + assets）

- `wstg.py`：WSTG v4.2 分类与编号表（本地 JSON 加载），提供 `from_cwe(cwe_id) -> [wstg_id]` 的保守映射（多对多，不确定就留空，不猜）；
- `catalog.py`：Semgrep 规则目录索引（规则 id、语言、严重级、CWE/OWASP metadata）；
- `assets/rules/semgrep/`：先维护 8~12 条高价值自定义规则（Python/JS/TS）：
  - SQL 字符串拼接、`eval`/`exec`、`subprocess shell=True`、硬编码密钥、
  - `innerHTML`/`dangerouslySetInnerHTML`、`document.write`、弱随机数、`verify=False`、
  - 反序列化（pickle/yaml.load）、CORS 反射任意 Origin；
- 规则只做**检测**，不包含任何攻击性内容。

### 7.4 任务规划（scanners/base + app 层）

- v1 不做"智能攻击规划"。规划器只做两件事：
  1. 把用户输入的「代码路径 / 目标 URL」转换为 Task（强类型 params）；
  2. 检查前置条件：target 已激活、scope 覆盖、（被动扫描）URL 可达性由用户自行保证；
- 主动类任务 `requires_approval=True`，v1 直接拒绝创建（返回"v1 未启用"），保留枚举与状态位。

```python
class TaskKind(str, Enum):
    SAST = "sast"
    PASSIVE_SCAN = "passive_scan"
    ACTIVE_SCAN = "active_scan"   # v1 保留，不放行
```

### 7.5 静态分析适配器（scanners/semgrep_runner.py）

- `ToolRunner` 接口：`run(task, gate, guard, limiter) -> RawScanResult`；
- Docker 实现：`infra/docker.py` 封装 `docker run --rm`（只读挂载、内存/超时限制、网络默认关闭——SAST 不需要联网）；
- 命令：`semgrep scan --json --config auto --config /rules/custom /src`；
- 失败处理：非零退出、超时、JSON 解析失败分别抛出明确异常，记录 stderr 摘要；
- 解析：`results[].check_id / path / start.line / extra.message / extra.severity / extra.metadata(cwe,owasp,references)` → 归一化 Finding；
- 网络：SAST 容器 `--network none`，杜绝代码扫描过程外联。

### 7.6 被动 Web 测试适配器（scanners/zap_runner.py）

- 仅封装 `zap-baseline.py`：
  - 生成 Automation Framework context（scope include/exclude）；
  - 参数：`-t <url>`、`-m <超时分钟>`、`-J/-r` 报告输出、`-P` 规划文件；
  - 爬取深度与线程使用保守默认（建议 depth 5、线程 2，具体写入配置）；
- 容器接入专用 docker network `bughunter_lab`，与 Juice Shop 同网络，**只对靶场/授权目标开放**；
- 解析 `report.json` 的 `site[].alerts[]`：pluginid、alert、riskcode、cweid、url、param、evidence（evidence 进入脱敏）；
- 归一化时丢弃 scope 外 host、丢弃 informational 重复项（保留统计）；
- 主动扫描：函数存在但内部第一行 `raise FeatureDisabledError("v1 未启用主动扫描")`。

### 7.7 AI 结果分析（analysis/）

**LLM 客户端**
- 仅通过 httpx 调用 OpenAI 兼容接口（`base_url` + `api_key` 从环境变量读取，不入库、不进日志）；
- 兼容本地 Ollama（`http://127.0.0.1:11434/v1`）；
- 超时、重试（上限 2 次）、JSON 解析失败显式标记 `triage_failed`，不产生伪结论。

**结构化输出（Pydantic 校验）**

```python
class AiTriageResult(BaseModel):
    summary: str
    root_cause: str
    false_positive_risk: Literal["low", "medium", "high"]
    confidence: Literal["low", "medium", "high"]
    verification_steps: list[str]   # 给人执行的验证步骤，只描述观察与判断
    cwe_id: str | None
    wstg_id: list[str]
    remediation: str
    needs_human_input: bool
    rationale: str                  # 必须引用证据中的事实，不允许臆测
```

**提示词红线（prompts.py 固化）**
- 只能基于给定证据分析；证据不足必须 `confidence=low` 且 `needs_human_input=true`；
- 不生成攻击 payload、不写利用代码、不提供绕过防护建议；
- `verification_steps` 只描述"在授权范围内如何人工观察/确认"（如查看某处响应头、核对某段代码的数据流）；
- 不允许把被动告警直接定性为"可利用漏洞"，必须说明条件。

**去重（dedup.py）**
- 归一化生成 `dedup_key`：`tool + rule_id + 规范化 location + 参数名`；
- 同目标内重复直接归并，跨工具同类问题（如 CWE 相同 + 同一 URL/文件）标记为"疑似重复"交人工裁决。

### 7.8 人工验证与复核（workflow/review.py + checklist.py）

- 复核队列命令：列出 `pending_review`，支持逐条查看证据、AI 分诊、原始报告；
- 四种裁决（必须填理由）：
  - `confirm`：确认有效；
  - `mark_false_positive`：误报（选原因：工具规则不适用/数据流不可达/触发条件不存在/其他）；
  - `mark_duplicate`：重复（关联到哪个 finding）；
  - `mark_out_of_scope`：超范围或不符合平台规则；
- 只有 `confirmed` 可进入报告生成；
- 提交前复核清单（checklist，逐项勾选后才能生成 pack）：
  1. 授权覆盖该目标与该测试方式；
  2. 漏洞在授权时间内发现；
  3. 复现步骤已亲自验证、无破坏性操作；
  4. 证据已脱敏（无 Cookie/Token/他人数据）；
  5. 未包含自动扫描原始噪声；
  6.  severity 与影响描述一致、无夸大；
  7. 报告不含其他厂商/平台内部信息；
  8. 未重复提交（查重平台历史）。

### 7.9 证据管理（workflow/evidence.py + redact.py）

证据目录：

```
data/evidence/<target_id>/<finding_id>/
├── source.json        # 工具原始输出（该条相关片段）
├── code_snippet       # SAST：代码片段（含上下文行号）
├── request.txt        # DAST：脱敏请求（v1 被动扫描通常没有攻击请求）
├── response.txt       # 脱敏响应摘要（截断，默认上限 4KB）
├── repro_steps.md     # 人工补全的复现步骤
└── notes.md           # 人工备注
```

- 脱敏规则：`Cookie`、`Authorization`、`Set-Cookie`、`X-Api-Key`、`token`、JWT、手机号、身份证号、邮箱（可选）；正则 + 头部名双重处理，打码为 `[REDACTED]`；
- 入库前自动跑一次脱敏自检，命中敏感模式则阻止该证据标记为 `redacted=True`；
- 原始报告（ZAP/Semgrep JSON）整体存 `data/raw/`，不进入提交包。

### 7.10 报告生成（workflow/report.py）

- Jinja2 两份模板：
  - **单漏洞报告**：标题、风险等级（附依据，不硬算 CVSS）、CWE/WSTG、受影响位置、漏洞描述、前提条件、人工复现步骤（已验证版）、证据清单、修复建议、参考链接；
  - **目标汇总报告**：授权信息与范围声明、测试方法与工具版本、统计（去重后）、发现清单（含误报统计与测试局限性）；
- 报告强制带声明："本测试在授权范围内以低频被动方式进行，结论已经人工复核"；
- 每次生成 version 递增，不覆盖历史。

### 7.11 提交草稿包（workflow/pack.py）

- 打包内容：单漏洞报告 markdown + 证据文件子集（仅已脱敏）+ 平台提交字段建议（标题/严重级/类别）；
- 状态：`draft → ready（清单全勾选）→ submitted（人工回填 URL）`；
- 不内置任何平台登录/HTTP 提交代码；`submit mark --url` 只记录结果。

---

## 8. Finding 状态机（core/state.py）

```
new
 └─> ai_triaged            （AI 分诊成功；失败则保持 new + 标记 triage_failed）
      └─> pending_review
           ├─ confirmed ─> report_drafted ─> report_reviewed ─> pack_ready ─> submitted*
           ├─ false_positive（终态，记录原因）
           ├─ duplicate（终态，关联原 finding）
           └─ out_of_scope（终态，记录原因）
   * submitted 只能由人手工回填 URL 后进入
```

- 所有逆向/跨态跳转由状态机白名单控制，非法跳转抛异常；
- 终态 finding 不可被 AI 再次分诊覆盖；
- 每次状态迁移写 audit_log。

---

## 9. CLI 命令设计（Typer）

```
bughunter target add | list | show | archive
bughunter authz add | confirm | show        # confirm 为交互二次确认
bughunter scope add-include | add-exclude | list
bughunter scan sast --target T --path P [--config auto]
bughunter scan passive --target T --url U   # 唯一放行的 Web 扫描
bughunter task list
bughunter finding list | show | triage      # triage 可重跑，保留历史
bughunter review queue
bughunter review confirm | false-positive | duplicate | out-of-scope <id>
bughunter evidence list | show | add-note
bughunter report finding <id> | summary <target>
bughunter pack build <id> | checklist <id> | mark-submitted <id> --url
bughunter audit tail                        # 查看审计日志
```

首次运行显示合规声明（仅用于授权测试、使用者自行承担法律责任），需确认一次后写入本地配置。

---

## 10. 配置（assets/config/default.toml，要点）

```toml
[llm]
base_url = "https://api.openai.com/v1"   # 可改 Ollama / 其他兼容服务
model = "gpt-4o-mini"
api_key_env = "BUGHUNTER_LLM_API_KEY"    # 只从环境变量读
timeout_sec = 30
max_retries = 2

[ratelimit]
requests_per_sec = 1.0        # 保守值，仅作用于被动扫描过程
daily_budget = 500            # 每目标每日请求预算
zap_spider_depth = 5
zap_threads = 2

[scan]
active_scan_enabled = false  # v1 硬关闭，配置项改 true 也会被代码拒绝
semgrep_backend = "docker"   # docker | wsl
zap_network = "bughunter_lab"

[evidence]
response_max_bytes = 4096
```

---

## 11. 测试策略

1. **单元测试（pytest，不依赖 Docker）**
   - ScopeGuard：域后缀匹配、path 排除、裸 IP 拒绝、重定向越界、scheme 限制；
   - RateLimiter：速率与日预算、持久化恢复；
   - state：合法/非法状态迁移；
   - redact：各类头部/正则脱敏、自检拦截；
   - normalize：Semgrep/ZAP 样例 JSON（随仓库放脱敏小样例）解析；
   - dedup：key 生成与疑似重复判定。
2. **工具集成测试（需 Docker，默认标记 `@pytest.mark.docker`，手动运行）**
   - Semgrep 对故意含漏洞的测试代码目录（tests/fixtures/vuln_app）扫描；
   - ZAP Baseline 对本地 Juice Shop 跑，断言：scope 外告警被丢弃、报告入库、预算有记录。
3. **端到端演练（Juice Shop 为唯一活目标）**
   - `scripts/run-juiceshop.ps1` 起靶场 → 登记 target（host=`juiceshop` 或 `127.0.0.1`）→
     授权确认 → SAST（用 Juice Shop 源码可选）→ 被动扫描 → AI 分诊 → 人工裁决 → 报告 → 草稿包。
4. 红线自检：测试用例显式尝试"无授权扫描 / scope 外 URL / 主动扫描"，断言全部被拒。

---

## 12. 里程碑与实施顺序

| 里程碑 | 内容 | 验收 |
|---|---|---|
| M0 脚手架 | uv init、pyproject、目录、日志、配置、DB 建表 | `bughunter --help` 可用；空库初始化 |
| M1 红线地基 | target/authz/scope/ratelimit/audit + 单测 | 无授权/越界/预算超限 100% 被拒；测试全绿 |
| M2 SAST | Semgrep Docker runner、归一化、自定义规则 | vuln_app 可检出预置问题并入库 |
| M3 AI 分诊 | LLM 客户端、schema 校验、去重、复核队列 | 样例 finding 输出结构化分诊；失败路径可观测 |
| M4 证据与报告 | 证据目录、脱敏、两份模板、报告版本 | 生成脱敏完整报告；敏感模式自检拦截 |
| M5 被动 DAST | ZAP Baseline、context 注入、Juice Shop E2E | 端到端跑通；scope 外告警被丢弃 |
| M6 收尾 | 草稿包 + 提交清单、README 合规声明、文档 | 红线自检清单全过；v1.0 |

建议每个 M 一个分支（`feat/m1-authz-gate` 等），按你的 Git 规范走 dev。

---

## 13. 待你确认的决策点

1. **v1 形态**：推荐 Typer CLI（最快验证流程正确性），Web UI 放 v2。是否同意？
2. **Semgrep 后端**：推荐 Docker（你本机已有 Docker Desktop，WSL 曾有过环境问题记录），是否同意？
3. **LLM 提供方**：用哪个？OpenAI 兼容接口可无缝切换（DeepSeek / 智谱 / 本地 Ollama 等），请给 base_url 与模型名；API Key 只走环境变量。
4. **依赖清单（第 4 节）**：是否许可安装？有无需要去掉的包（如 rich）？
5. **确认后我从 M0 + M1 开始**：先把脚手架和红线地基（授权门/scope/限速/审计）做出来给你验，再推进后续模块。

---

## 附：关键参考资料（已核实，2026-10）

- Semgrep 官方：`https://github.com/semgrep/semgrep`；MCP 已并入主仓库，插件文档 `https://ai.semgrep.dev/docs/mcp`
- Semgrep 规则仓库：`https://github.com/semgrep/semgrep-rules`
- ZAP Automation Framework：`https://www.zaproxy.org/docs/automate/automation-framework/`；Docker 脚本 `https://www.zaproxy.org/docs/docker/`
- OWASP WSTG 稳定版 v4.2：`https://owasp.org/www-project-web-security-testing-guide/stable/`
- Juice Shop：`https://github.com/juice-shop/juice-shop`
