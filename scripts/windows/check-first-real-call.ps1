# Read-only operational preflight. Does NOT claim live media or E2EE success.
param(
 [Parameter(Mandatory=$true)][string]$PublicOrigin,
 [string]$Gateway="http://127.0.0.1:8080",
 [int]$TimeoutSeconds=8
)
Set-StrictMode -Version Latest
$ErrorActionPreference="Stop"
$failures=New-Object System.Collections.Generic.List[string]
$root=(Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
function Report([string]$name,[bool]$ok,[string]$detail) {
 if($ok) { Write-Host ("PASS "+$name+" "+$detail) }
 else { Write-Host ("FAIL "+$name+" "+$detail); $script:failures.Add($name) }
}
function Get-Http([string]$url) {
 try { return Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec $TimeoutSeconds -MaximumRedirection 0 -ErrorAction Stop }
 catch { if($_.Exception.Response) { return $_.Exception.Response }; return $null }
}
function Status($response) { if($null -eq $response) { return 0 }; return [int]$response.StatusCode }
# Windows Server 2016 PowerShell/.NET may fail rustls HTTPS negotiation
# despite a healthy local edge. Use the same Git-for-Windows curl with explicit
# certificate verification as start-local-first-party-https.ps1.
$cert = Join-Path $env:LOCALAPPDATA 'UCR-Local-Test\localhost.crt.pem'
$curl = $null
foreach($candidate in @('C:\Program Files\Git\mingw64\bin\curl.exe','C:\Program Files\Git\usr\bin\curl.exe')) {
 if(Test-Path -LiteralPath $candidate -PathType Leaf) { $curl=$candidate; break }
}
if(!$curl) {
 $command=Get-Command curl.exe -ErrorAction SilentlyContinue
 if($command) { $curl=$command.Source }
}
function Get-Https([string]$url) {
 if(!$curl) { Write-Host 'HTTPS probe: curl.exe unavailable; install Git for Windows'; return @{StatusCode=0;Content=''} }
 if(!(Test-Path -LiteralPath $cert -PathType Leaf)) {
  Write-Host "HTTPS probe: trusted localhost certificate missing at $cert"
  return @{StatusCode=0;Content=''}
 }
 $temporary = [IO.Path]::GetTempFileName()
 try {
  $status = & $curl '--cacert' $cert '--silent' '--show-error' '--max-time' "$TimeoutSeconds" '--output' $temporary '--write-out' '%{http_code}' $url
  $exit = $LASTEXITCODE
  if($exit -ne 0 -or "$status" -notmatch '^[0-9]{3}$') {
   Write-Host "HTTPS probe TLS/connection failed (curl exit $exit): $url"
   return @{StatusCode=0;Content=''}
  }
  $body = ''
  if($url.EndsWith('/v1/first-party/bootstrap')) { $body=[IO.File]::ReadAllText($temporary) }
  return @{StatusCode=[int]$status;Content=$body}
 } finally {
  Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
 }
}
if($PublicOrigin -notmatch '^https://[a-zA-Z0-9.-]+(:[0-9]{1,5})?$') {
 throw "PublicOrigin must be an exact HTTPS origin without a path, credentials or query"
}
if($Gateway -notmatch '^http://(127\.0\.0\.1|localhost|\[::1\]):[0-9]{1,5}$') {
 throw "Gateway must be a loopback HTTP URL"
}
if($TimeoutSeconds -lt 1 -or $TimeoutSeconds -gt 30) { throw "Invalid TimeoutSeconds" }
$assetRoot=Join-Path $root "crates\ucr-realtime-web\static"
foreach($asset in @("endpoint-media\reference_browser_media_installer.js",
                     "endpoint-wasm\ucr_endpoint_wasm.js",
                     "endpoint-wasm\ucr_endpoint_wasm_bg.wasm")) {
 $path=Join-Path $assetRoot $asset
 $valid=Test-Path -LiteralPath $path -PathType Leaf
 if($valid) { $size=(Get-Item -LiteralPath $path).Length; $valid=$size -gt 0 -and $size -le 16777216 }
 Report ("asset:"+$asset) $valid "must be present from this exact revision"
}
$health=Get-Http ($Gateway+"/healthz")
Report "gateway-health" ((Status $health) -eq 200) ("HTTP "+(Status $health))
$ready=Get-Http ($Gateway+"/readyz")
Report "gateway-ready" ((Status $ready) -eq 200) ("HTTP "+(Status $ready))
$bootstrap=Get-Https ($PublicOrigin+"/v1/first-party/bootstrap")
$tenantValid=$false
if((Status $bootstrap) -eq 200) {
 try {
  $data=ConvertFrom-Json -InputObject $bootstrap.Content
  $tenantValid=($null -ne $data.tenantId -and $data.tenantId -is [string] -and $data.tenantId.Length -gt 0)
 } catch {}
}
Report "https-bootstrap-with-tenant" $tenantValid ("HTTP "+(Status $bootstrap))
$session=Get-Https ($PublicOrigin+"/v1/first-party/session")
Report "anonymous-session-denied" ((Status $session) -eq 401) ("HTTP "+(Status $session))
$start=Get-Https ($PublicOrigin+"/start")
Report "https-browser-entry" ((Status $start) -eq 200) ("HTTP "+(Status $start))
$wasm=Get-Https ($PublicOrigin+"/endpoint-wasm/ucr_endpoint_wasm_bg.wasm")
Report "https-wasm-served" ((Status $wasm) -eq 200) ("HTTP "+(Status $wasm))
if($failures.Count -gt 0) {
 Write-Host ("UCR_FIRST_REAL_CALL_PREFLIGHT_FAILED count="+$failures.Count)
 exit 2
}
Write-Host "UCR_FIRST_REAL_CALL_PREFLIGHT_OK"
Write-Host "Not a call proof. Next: two independently enrolled Devices, authorized Join, and real bidirectional E2EE A/V."
