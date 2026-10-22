# Diagnostic supervisor for UCR Windows local HTTPS call. No credentials/media payload capture.
param([string]$RepositoryRoot = '')
$ErrorActionPreference = 'Stop'
if ($RepositoryRoot) { $root=(Resolve-Path -LiteralPath $RepositoryRoot).Path }
else { $root=(Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path }
Set-Location $root
$state=Join-Path $env:LOCALAPPDATA 'UCR-Local-Test'
$logs=Join-Path $state 'logs'
$session=Join-Path $state ('diagnostics-'+(Get-Date -Format 'yyyyMMdd-HHmmss'))
New-Item -ItemType Directory -Path $session -Force | Out-Null
$transcript=Join-Path $session 'console.log'
$launcher=Join-Path $root 'scripts\windows\start-local-first-party-https.ps1'
if (!(Test-Path -LiteralPath $launcher)) { throw "Missing launcher: $launcher" }
function Redact([string]$line) {
    $line=[regex]::Replace($line,'(?i)(authorization|cookie|set-cookie|password|secret|token|bearer|private.key|join.key|signing.key)\s*[:=]\s*[^\s,;}]+','$1=[REDACTED]')
    $line=[regex]::Replace($line,'(?i)(https?://[^\s#]+)#\S+','$1#[REDACTED]')
    return $line
}
function Hint([string]$line) {
    $s=$line.ToLowerInvariant()
    if ($s -match 'media_codec_failure|audioencoder|audiodecoder|videoencoder|videodecoder|webcodecs') { return 'sdk/typescript/src/browser_webcodecs_media.ts + sdk/typescript/src/canonical_browser_media_factory.ts' }
    if ($s -match 'websocket|webrtc|ice|sdp|peerconnection|connecting') { return 'crates/ucr-realtime-web/static/client.html + crates/ucr-realtime-web/src/main.rs + crates/ucr-api-grpc/src/realtime_service.rs' }
    if ($s -match 'first.party|bootstrap|signup|login|session|csrf') { return 'crates/ucr-runtime/src/first_party_web.rs + crates/ucr-realtime-web/src/main.rs' }
    if ($s -match 'mls|encrypt|decrypt|epoch|admission') { return 'sdk/typescript/src/endpoint_e2ee.ts + crates/ucr-runtime/src/first_party_media.rs' }
    if ($s -match 'sqlite|database|constraint') { return 'crates/ucr-runtime/src/main.rs + canonical SQLite owner (inspect stack trace)' }
    if ($s -match 'media/stream|webrtc/close|http 404') { return 'crates/ucr-realtime-web/static/client.html + crates/ucr-realtime-web/src/main.rs (route mismatch: inspect HTTP method/path)' }
    return $null
}
Start-Transcript -Path $transcript | Out-Null
try {
 Write-Host "UCR LIVE DIAGNOSTICS | $session" -ForegroundColor Cyan
 Write-Host 'This console prints launcher + runtime/web/edge logs with probable source-file hints.'
 Write-Host 'No tool can prove an exact offending source line from an HTTP status or a generic error code alone.'
 Write-Host 'Do NOT paste unredacted raw logs: they may contain credentials.'
 $out=Join-Path $session 'launcher.stdout.log'
 $err=Join-Path $session 'launcher.stderr.log'
 $pwsh=Join-Path $PSHOME 'powershell.exe'
 if (!(Test-Path -LiteralPath $pwsh)) { $pwsh=(Get-Command powershell.exe).Source }
 $argsList=@('-NoProfile','-ExecutionPolicy','Bypass','-File',('"' + $launcher + '"'),'-RepositoryRoot',('"' + $root + '"'),'-OpenSecondPersistentProfile')
 # Environment affects only Chrome launched by the launcher, not any existing Chrome process.
 $env:CHROME_LOG_FILE=Join-Path $session 'chrome.log'
 $process=Start-Process -FilePath $pwsh -ArgumentList $argsList -WorkingDirectory $root -PassThru -RedirectStandardOutput $out -RedirectStandardError $err
 $files=@($out,$err,(Join-Path $logs 'runtime.stdout.log'),(Join-Path $logs 'runtime.stderr.log'),(Join-Path $logs 'web.stdout.log'),(Join-Path $logs 'web.stderr.log'),(Join-Path $logs 'https-edge.stdout.log'),(Join-Path $logs 'https-edge.stderr.log'),$env:CHROME_LOG_FILE)
 $offsets=@{}; $lastHint=''
 Write-Host 'Diagnostic monitoring started; press Ctrl+C to stop monitoring (servers remain running).' -ForegroundColor Cyan
 while ($true) {
   foreach ($file in $files) {
     if (!(Test-Path -LiteralPath $file -PathType Leaf)) { continue }
     $item=Get-Item -LiteralPath $file -ErrorAction SilentlyContinue
     if (!$item) { continue }
     if (!$offsets.ContainsKey($file)) { $offsets[$file]=0L }
     $offset=[long]$offsets[$file]
     if ($item.Length -lt $offset) { $offset=0L }
     if ($item.Length -eq $offset) { continue }
     $handle=[IO.File]::Open($file,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite)
     try {
       [void]$handle.Seek($offset,[IO.SeekOrigin]::Begin)
       $reader=New-Object IO.StreamReader($handle,[Text.Encoding]::UTF8,$true,4096,$true)
       try {
         while (!$reader.EndOfStream) {
           $line=$reader.ReadLine()
           if ($null -eq $line) { break }
           $clean=Redact $line
           $name=[IO.Path]::GetFileName($file)
           if ($clean -match '(?i)error|fail|exception|panic|404|warn|codec|webrtc|ice|connection') {
             Write-Host "[$name] $clean" -ForegroundColor Yellow
             $hint=Hint $clean
             if ($hint -and $hint -ne $lastHint) { Write-Host "[SOURCE CANDIDATE] $hint" -ForegroundColor Magenta; $lastHint=$hint }
           } else { Write-Host "[$name] $clean" }
         }
       } finally { $reader.Dispose() }
       $offsets[$file]=$handle.Position
     } finally { $handle.Dispose() }
   }
   # The launcher intentionally exits after starting detached server processes.
   # A successful parent exit is NOT a diagnostic-session failure.
   if ($process.HasExited) {
      $process.Refresh()
      $exitCode = $process.ExitCode
      if ($null -ne $exitCode -and $exitCode -ne 0) {
         Write-Host "Launcher failed with exit code $exitCode. See $out and $err" -ForegroundColor Red
         break
      }
   }
   Start-Sleep -Milliseconds 500
 }
} finally { Stop-Transcript | Out-Null }
