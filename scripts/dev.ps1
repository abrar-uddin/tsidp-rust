# Run cargo (or any command) inside the project's dev container.
#   .\scripts\dev.ps1 cargo test
#   .\scripts\dev.ps1 cargo build --release
#   .\scripts\dev.ps1 bash
# Uses the same image and cache volumes as .devcontainer/devcontainer.json.
param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Cmd)
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$image = "rust:1-bookworm"
if (-not $Cmd -or $Cmd.Count -eq 0) { $Cmd = @("cargo", "build") }
docker volume create tsidp-rust-cargo-registry | Out-Null
docker volume create tsidp-rust-target | Out-Null
$tty = if ([Environment]::UserInteractive -and -not [Console]::IsInputRedirected) { "-it" } else { "-i" }
docker run --rm $tty `
  -v "${root}:/workspace" `
  -v tsidp-rust-cargo-registry:/usr/local/cargo/registry `
  -v tsidp-rust-target:/workspace/target `
  -w /workspace `
  -e CARGO_TERM_COLOR=always `
  $image @Cmd
exit $LASTEXITCODE
