$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
Set-Location $repo
Write-Host '[UCR] Unified local launcher — realtime + web (not yet live call proof)'
$vc = 'C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat'
$db = Join-Path $env:LOCALAPPDATA 'UCR-Local-Test\runtime.sqlite'
$secretFile = Join-Path $env:LOCALAPPDATA 'UCR-Local-Test\join-signing.dpapi'
if (!(Test-Path $vc)) { throw "Missing VC tools: $vc" }
if (!(Test-Path 'C:\UCR-OpenSSL\include\openssl\ssl.h')) { throw 'OpenSSL headers missing: C:\UCR-OpenSSL' }
if (!(Test-Path $db)) { throw "Existing database missing: $db" }
if (!(Test-Path 'crates\ucr-realtime-web\static\endpoint-media\reference_browser_media_installer.js')) { throw 'Browser media missing; run build-browser-media.ps1' }
$vcLines = & cmd.exe /d /s /c ('call "' + $vc + '" >nul && set')
if ($LASTEXITCODE -ne 0) { throw 'VC x64 initialization failed' }
foreach ($line in $vcLines) {
  $idx = $line.IndexOf('=')
  if ($idx -gt 0) { [Environment]::SetEnvironmentVariable($line.Substring(0,$idx),$line.Substring($idx+1),'Process') }
}
$env:OPENSSL_DIR='C:\UCR-OpenSSL'
$env:OPENSSL_STATIC='1'
$env:OPENSSL_NO_VENDOR='1'
$env:CARGO_INCREMENTAL='0'
$env:CARGO_BUILD_JOBS='1'
$env:CARGO_PROFILE_DEV_DEBUG='0'
$env:UCR_BROWSER_REALTIME_GATEWAY_ENABLED='true'
$env:UCR_REALTIME_GRPC_UPSTREAM='http://127.0.0.1:50051'
if (!(Test-Path $secretFile)) {
  $bytes = New-Object byte[] 32
  $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
  try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
  $sealed = [Security.Cryptography.ProtectedData]::Protect($bytes,$null,[Security.Cryptography.DataProtectionScope]::CurrentUser)
  [IO.File]::WriteAllBytes($secretFile,$sealed)
  [Array]::Clear($bytes,0,$bytes.Length)
}
$sealedBytes = [IO.File]::ReadAllBytes($secretFile)
$keyBytes = [Security.Cryptography.ProtectedData]::Unprotect($sealedBytes,$null,[Security.Cryptography.DataProtectionScope]::CurrentUser)
if ($keyBytes.Length -ne 32) { throw 'Persisted Join secret has wrong length' }
$env:UCR_REALTIME_JOIN_KEY_HEX = -join ($keyBytes | ForEach-Object { $_.ToString('x2') })
[Array]::Clear($keyBytes,0,$keyBytes.Length)
Write-Host '[UCR] Stopping previous UCR-only processes, if any...'
Get-Process 'ucr-runtime','ucr-realtime-web' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction Stop
Write-Host '[UCR] Compiling runtime and web with incremental disabled...'
& cargo build -p ucr-runtime -p ucr-realtime-web --locked
if ($LASTEXITCODE -ne 0) { throw 'Build failed; refusing stale binaries' }
$rt = Join-Path $repo 'target\debug\ucr-runtime.exe'
$gw = Join-Path $repo 'target\debug\ucr-realtime-web.exe'
if (!(Test-Path $rt) -or !(Test-Path $gw)) { throw 'Missing compiled executable(s)' }
Write-Host '[UCR] Starting realtime runtime...'
$runtimeArgs = @('serve-realtime','--database',$db,'--bind','127.0.0.1:50051','--operator-bind','127.0.0.1:50052','--join-base-url','https://127.0.0.1')
$runtime = Start-Process -FilePath $rt -ArgumentList $runtimeArgs -WorkingDirectory $repo -PassThru
Start-Sleep -Seconds 4
$runtime.Refresh()
if ($runtime.HasExited) { throw "Realtime runtime exited with code $($runtime.ExitCode); inspect its window/log" }
Write-Host '[UCR] Starting gateway...'
$gateway = Start-Process -FilePath $gw -WorkingDirectory $repo -PassThru
Start-Sleep -Seconds 4
$gateway.Refresh()
if ($gateway.HasExited) { throw "Gateway exited with code $($gateway.ExitCode); verify realtime gRPC" }
try {
  $resp = Invoke-WebRequest -Uri 'http://127.0.0.1:8080/healthz' -UseBasicParsing -TimeoutSec 5
  if ($resp.StatusCode -ne 200) { throw 'Unhealthy gateway' }
} catch { throw "Gateway health failed: $_" }
Write-Host '[UCR] Runtime and gateway running. Opening browser.'
Start-Process 'http://127.0.0.1:8080/start'
Write-Host '[UCR] WARNING: local bootstrap only. HTTPS/BFF/tenant/ICE/E2EE two-person call remains to be configured.'
