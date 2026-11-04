# M2 交付说明：Semgrep SAST 静态分析

> 日期：2026-11-04
> 状态：已完成并通过验证
> 对应方案：`discuss/01-BugHunter-AI-架构设计方案.md` 第 12 节里程碑 M2

## 一、完成内容

### 数据模型与状态机

| 组件 | 文件 | 能力 |
|---|---|---|
| 枚举扩展 | `core/enums.py` | TaskKind / TaskStatus / ScanStatus / Tool / Severity / FindingStatus，新增 5 个审计动作 |
| 三张新表 | `core/models.py` | Task（任务）、Scan（一次扫描）、Finding（归一化发现，含多索引） |
| Finding 状态机 | `core/state.py` | 白名单迁移 `ALLOWED_TRANSITIONS`、终态集合、`assert_transition` 拒绝非法跳转 |
| 异常分类 | `core/errors.py` | ToolUnavailableError、ScannerError、IllegalTransitionError 集中管理 |

### 扫描能力层（`scanners/`）

| 文件 | 职责 |
|---|---|
| `base.py` | NormalizedFinding / ScanStats / RawScanResult（pydantic 强类型）、ToolRunner 抽象基类 |
| `normalize.py` | Semgrep JSON 归一化、severity 映射、CWE/OWASP 提取、路径与规则 id 规范化、dedup_key |
| `semgrep_runner.py` | 离线 Docker 执行 Semgrep，挂载 /src、/rules，`--network none` |
| `service.py` | SastConfig + ScanService 端到端编排：授权门 → 建任务/扫描 → 执行 → 落原始报告 → 去重入库 |
| `infra/docker.py` | Mount / ContainerResult / DockerClient，subprocess 调 docker CLI（不引 SDK） |

### 规则与样例

- 12 条自定义规则：`assets/rules/semgrep/python-security.yml`（8 条）、`javascript-security.yml`（4 条）；
- 漏洞样例工程 `tests/fixtures/vuln_app/`：vuln.py、vuln.js、component.jsx；
- CLI：`scan sast`、`scan list`、`scan show`、`scan active`（主动扫描永远拒绝）。

## 二、验证结果

- 单元测试 **58 项全部通过**（docker 标记默认 skip），覆盖归一化、状态机、runner（FakeDocker）、service（FakeRunner）、CLI 红线拒绝路径；
- 真实 Docker 集成测试（`--run-docker`，手动触发）：**1 项通过**，12 条规则全部命中、共 13 个发现（hardcoded-secret 命中两行）；
- 真实 CLI 端到端冒烟（非 mock）：
  - 首次扫描：13 个新增 finding、0 错误，原始报告写 `data/raw/semgrep_scan_1.json`；
  - 二次扫描：0 新增、13 重复归并，验证 dedup 白名单；
  - `scan list` / `scan show` 字段正确（severity、repo-relative 路径、canonical 规则 id、status=new）；
- 代码规范：最大源文件 216 行（上限 300）；目录文件数 core 8、commands 7、scanners 5、infra 3、app 5（上限 8）；全量强类型、无裸 dict/any、异常显式分类不静默吞。

## 三、红线在代码中的强制点（不可绕过）

1. SAST 仍先过 `AuthorizationGate.assert_ready_for_scan()`，无有效授权一律拒绝；
2. 容器 `--network none` 完全禁网，代码与规则两个挂载均只读（`:ro`），`--metrics=off`；
3. **仅使用本地自定义规则 `/rules`，禁用 `--config auto`**（auto 需联网拉 registry，与禁网冲突）；
4. `scan active` 先写 `ACTIVE_SCAN_BLOCKED` 审计再抛 FeatureDisabledError，主动扫描分支不可用；
5. 扫描失败时 Task/Scan 置 failed 并先 commit 审计再抛出，失败记录不丢失；
6. SAST 不经过 RateLimiter（容器禁网、不触达目标系统）；目标侧请求限速在 M5 接入。

## 四、关键设计决策

1. **离线优先于方案原文**：M1 文档曾写 `--config auto`，实现时确认 auto 需联网，与 `--network none` 冲突，以红线为准改为仅本地规则，并在代码注释固化；
2. **规则 id 归一化**：以目录方式加载规则时 Semgrep 给 check_id 加 `rules.` 前缀（如 `rules.bughunter.python.eval-exec`），`canonical_rule_id()` 用正则提取 `bughunter.*` 恢复 YAML 中声明的原始 id，第三方规则原样保留；
3. **分层不反向依赖**：初版 service 引用了 app 层配置，改为在 scanners 层定义 SastConfig dataclass，由 app 层注入；
4. **目录约束重构**：为避免 `core/` 超过 8 文件，将 M1 的 `db.py` 并入 `models.py`，3 处引用同步修改；
5. **退出码容错**：Semgrep 退出码 0/1/4 只要 stdout 是合法 JSON 即解析（4 表示部分文件 parse skip），无 JSON 才抛 ScannerError。

## 五、下一步（M3）

- 本机 `ollama pull qwen2.5:7b`（当前仅有 cloud 模型）；
- AI 分诊模块：对 status=new 的 finding 调用本地 Ollama，输出置信度、根因、验证思路；
- 分诊结果驱动 Finding 状态机迁移（new → ai_triaged / triage_failed），仍不自动确认。

## 六、已知边界

- Semgrep 仅做静态分析，不能替代 Web 渗透测试，也不保证发现全部漏洞；
- 当前 `data/bughunter.db` 复用 M1 库（目标 1 juice-shop-lab，已补确认一条新授权），新表由 create_all 幂等补建，可删 `data/` 重置；
- 仓库尚未加 LICENSE（pyproject 标 Proprietary），需要 MIT 时再补。
