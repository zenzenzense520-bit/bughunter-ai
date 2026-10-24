# BugHunter AI environment setup (Windows PowerShell 7)
# Creates .venv, installs dependencies, prepares runtime dirs.
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

# Keep uv cache and temp on D: drive (per machine preference).
$env:UV_CACHE_DIR = "D:\Downloads\bughunter-uv-cache"
$env:TEMP = "D:\Downloads\bughunter-tmp"
$env:TMP = "D:\Downloads\bughunter-tmp"
New-Item -ItemType Directory -Force -Path $env:UV_CACHE_DIR, $env:TEMP | Out-Null

Write-Host "[SETUP] uv sync (this may take a few minutes)..."
uv sync
if ($LASTEXITCODE -ne 0) { throw "uv sync failed" }

New-Item -ItemType Directory -Force -Path (Join-Path $root "data"), (Join-Path $root "logs") | Out-Null

Write-Host "[CHECK] uv:      $(uv --version)"
Write-Host "[CHECK] docker:  $(docker --version 2>$null)"
Write-Host "[CHECK] ollama:  $(ollama --version 2>$null)"
Write-Host "[OK] setup complete. Next: ./scripts/run-tests.ps1"
