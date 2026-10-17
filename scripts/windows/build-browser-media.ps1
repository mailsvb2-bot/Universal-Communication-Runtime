# Build UCR's pinned, public browser media assets from the checked-out revision.
# No signer secrets, Join grants or user keys are bundled by this script.
$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$root = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
Set-Location $root

function Invoke-UcrNative {
    param([string]$Program, [string[]]$Arguments)
    & $Program @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$Program exited with code $LASTEXITCODE"
    }
}
foreach ($command in @("cargo", "rustup", "npm.cmd")) {
    if (-not (Get-Command $command -ErrorAction SilentlyContinue)) {
        throw "Missing build tool: $command"
    }
}
$wasmBindgen = Get-Command "wasm-bindgen" -ErrorAction SilentlyContinue
$version = ""
if ($wasmBindgen) {
    $version = (& wasm-bindgen --version | Out-String).Trim()
}
if ($version -ne "wasm-bindgen 0.2.128") {
    Invoke-UcrNative "cargo" @("install", "wasm-bindgen-cli", "--version", "0.2.128", "--locked", "--force")
}
Invoke-UcrNative "rustup" @("target", "add", "wasm32-unknown-unknown")
Invoke-UcrNative "cargo" @(
    "build", "--locked", "--release", "--manifest-path", "crates/ucr-endpoint-wasm/Cargo.toml",
    "--target", "wasm32-unknown-unknown"
)
$wasmDir = Join-Path $root "crates\ucr-realtime-web\static\endpoint-wasm"
$mediaDir = Join-Path $root "crates\ucr-realtime-web\static\endpoint-media"
New-Item -ItemType Directory -Path $wasmDir -Force | Out-Null
New-Item -ItemType Directory -Path $mediaDir -Force | Out-Null
$wasmSource = Join-Path $root "crates\ucr-endpoint-wasm\target\wasm32-unknown-unknown\release\ucr_endpoint_wasm.wasm"
Invoke-UcrNative "wasm-bindgen" @($wasmSource, "--target", "web", "--out-dir", $wasmDir, "--out-name", "ucr_endpoint_wasm")
Invoke-UcrNative "npm.cmd" @(
    "exec", "--yes", "--package=esbuild@0.25.5", "--", "esbuild",
    "sdk/typescript/src/reference_browser_media_installer.ts",
    "--bundle", "--platform=browser", "--format=esm", "--target=es2022",
    "--outfile=crates/ucr-realtime-web/static/endpoint-media/reference_browser_media_installer.js"
)
foreach ($asset in @(
    (Join-Path $wasmDir "ucr_endpoint_wasm.js"),
    (Join-Path $wasmDir "ucr_endpoint_wasm_bg.wasm"),
    (Join-Path $mediaDir "reference_browser_media_installer.js")
)) {
    if (-not (Test-Path -LiteralPath $asset -PathType Leaf)) {
        throw "Browser asset missing: $asset"
    }
    if ((Get-Item -LiteralPath $asset).Length -le 0) {
        throw "Browser asset empty: $asset"
    }
}
Write-Host "UCR_BROWSER_MEDIA_READY"
Write-Host "Generated browser media is local and gitignored; restart the gateway after updating its code."
