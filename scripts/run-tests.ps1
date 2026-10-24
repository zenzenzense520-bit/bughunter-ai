# Run the test suite.
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root
$env:UV_CACHE_DIR = "D:\Downloads\bughunter-uv-cache"
uv run pytest $args
if ($LASTEXITCODE -ne 0) { throw "tests failed" }
