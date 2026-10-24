# Run the BugHunter CLI, e.g. ./scripts/run-cli.ps1 --help
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root
$env:UV_CACHE_DIR = "D:\Downloads\bughunter-uv-cache"
uv run bughunter $args
