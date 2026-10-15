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
$bootstrap=Get-Http ($PublicOrigin+"/v1/first-party/bootstrap")
$tenantValid=$false
if((Status $bootstrap) -eq 200) {
 try {
  $data=ConvertFrom-Json -InputObject $bootstrap.Content
  $tenantValid=($null -ne $data.tenantId -and $data.tenantId -is [string] -and $data.tenantId.Length -gt 0)
 } catch {}
}
Report "https-bootstrap-with-tenant" $tenantValid ("HTTP "+(Status $bootstrap))
$session=Get-Http ($PublicOrigin+"/v1/first-party/session")
Report "anonymous-session-denied" ((Status $session) -eq 401) ("HTTP "+(Status $session))
$start=Get-Http ($PublicOrigin+"/start")
Report "https-browser-entry" ((Status $start) -eq 200) ("HTTP "+(Status $start))
$wasm=Get-Http ($PublicOrigin+"/endpoint-wasm/ucr_endpoint_wasm_bg.wasm")
Report "https-wasm-served" ((Status $wasm) -eq 200) ("HTTP "+(Status $wasm))
if($failures.Count -gt 0) {
 Write-Host ("UCR_FIRST_REAL_CALL_PREFLIGHT_FAILED count="+$failures.Count)
 exit 2
}
Write-Host "UCR_FIRST_REAL_CALL_PREFLIGHT_OK"
Write-Host "Not a call proof. Next: two independently enrolled Devices, authorized Join, and real bidirectional E2EE A/V."
