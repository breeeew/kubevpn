#!/usr/bin/env pwsh
# Local equivalent of the CI checks: formatting, lints, tests.
$ErrorActionPreference = 'Stop'
Set-Location (Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path))

Write-Host '== cargo fmt ==' -ForegroundColor Cyan
cargo fmt --all --check
if ($LASTEXITCODE -ne 0) { exit 1 }

Write-Host '== cargo clippy ==' -ForegroundColor Cyan
cargo clippy --all-targets -- -D warnings
if ($LASTEXITCODE -ne 0) { exit 1 }

Write-Host '== cargo test ==' -ForegroundColor Cyan
cargo test
if ($LASTEXITCODE -ne 0) { exit 1 }

Write-Host 'all checks passed' -ForegroundColor Green
