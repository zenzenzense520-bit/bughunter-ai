# Run a real Semgrep SAST scan against the bundled vulnerable app (demo).
# Usage: ./scripts/run-semgrep.ps1 [target-id]  (default target id = 1)
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root
$env:UV_CACHE_DIR = "D:\Downloads\bughunter-uv-cache"
$target = if ($args.Count -gt 0) { $args[0] } else { "1" }
$code = Join-Path $root "tests\fixtures\vuln_app"
uv run bughunter scan sast -t $target -p $code
if ($LASTEXITCODE -ne 0) { throw "semgrep scan failed" }
