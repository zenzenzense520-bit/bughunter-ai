# BugHunter AI

授权漏洞赏金 / 授权安全测试的本地工作台。围绕「授权目标 → 工具扫描 → AI 分诊 → 人工复核 → 证据报告 → 人工提交」流水线，把重复劳动自动化，把越界动作留给人。

## 合规声明（使用前必读）

- 本工具仅可用于**你获得明确书面授权**的目标（漏洞平台项目范围、SRC 规则、合同授权等）。
- 禁止对未授权目标使用；使用者自行承担全部法律责任。
- v1 仅提供：Semgrep 静态分析、ZAP **被动**基线扫描（zap-baseline，不发送攻击 payload）、AI 结果解释、人工复核与报告整理。
- 本工具不包含绕过安全控制、批量利用、自动提交等能力；主动扫描在 v1 中硬关闭。

## 环境要求

- Windows + PowerShell 7
- [uv](https://docs.astral.sh/uv/)（Python 包管理）
- Docker Desktop（运行 Semgrep、ZAP、Juice Shop 容器）
- Ollama（本地大模型，OpenAI 兼容接口 `http://127.0.0.1:11434/v1`）

## 快速开始

```powershell
# 1. 初始化环境（创建 .venv、安装依赖、data/logs 目录）
./scripts/setup.ps1

# 2. 运行测试
./scripts/run-tests.ps1

# 3. 查看命令
./scripts/run-cli.ps1 --help
```

## 典型流程

```powershell
# 登记目标
bughunter target add --name "juice-shop-local"
# 登记授权（平台项目页 / 授权文件、授权方、有效期）
bughunter authz add --target 1 --source "local-lab" --scope-ref "N/A" --grantor "self" --valid-from 2026-10-24T00:00:00 --valid-to 2026-10-31T00:00:00
# 配置 scope（仅白名单内 host 可被测试）
bughunter scope add-include --target 1 --rule-type host --value 127.0.0.1
# 交互确认激活（二次确认）
bughunter authz confirm --target 1
```

## 目录

```
src/bughunter/
  app/       CLI、配置、日志、依赖装配
  core/      领域模型、DB、授权门、ScopeGuard、限速器（红线）
  infra/     审计日志（后续：Docker/子进程封装）
  scanners/  Semgrep / ZAP 适配器（M2/M5）
  analysis/  AI 分诊（M3）
  workflow/  复核、证据、报告、提交包（M4+）
assets/      默认配置、Semgrep 规则、报告模板
data/        运行时数据（数据库、证据、报告，已 gitignore）
logs/        运行日志（已 gitignore）
discuss/     架构方案讨论
docs/        正式文档
```

## 安全红线

无有效授权拒绝执行；scope 外 URL 一律拒绝；主动扫描 v1 关闭；请求限速与每日预算；证据脱敏后入库；人工确认才能进报告；提交只产出草稿包；全部敏感动作写链式审计日志。

设计方案见 `discuss/01-BugHunter-AI-架构设计方案.md`。
