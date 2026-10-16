# Local Windows first-party HTTPS smoke launcher; does not prove a two-person E2EE call.
# Keeps the existing canonical SQLite and in-process first-party BFF owner.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
Set-Location $root
$state = Join-Path $env:LOCALAPPDATA 'UCR-Local-Test'
$db = Join-Path $state 'runtime.sqlite'
$keyFile = Join-Path $state 'join-signing.dpapi'
$cert = Join-Path $state 'localhost.crt.pem'
$privateKey = Join-Path $state 'localhost.key.pem'
$origin = 'https://localhost:8443'
$vc = 'C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat'
$opensslRoot = 'C:\UCR-OpenSSL'
$logRoot = Join-Path $state 'logs'
New-Item -ItemType Directory -Force -Path $state,$logRoot | Out-Null

function Require-File([string]$file) {
    if (!(Test-Path -LiteralPath $file -PathType Leaf)) { throw "Required file missing: $file" }
}
function Require-Tool([string]$name) {
    if (!(Get-Command $name -ErrorAction SilentlyContinue)) { throw "Required tool missing: $name" }
}
function Invoke-Checked([string]$program,[string[]]$arguments) {
    & $program @arguments
    if ($LASTEXITCODE -ne 0) { throw "$program failed (exit $LASTEXITCODE)" }
}
function Http-Status([string]$uri) {
    try {
        $response = Invoke-WebRequest -Uri $uri -UseBasicParsing -TimeoutSec 5 -ErrorAction Stop
        return [int]$response.StatusCode
    } catch {
        if ($_.Exception.Response) { return [int]$_.Exception.Response.StatusCode }
        return 0
    }
}
function Start-Ucr([string]$exe,[string[]]$arguments,[string]$name) {
    $stdout = Join-Path $logRoot "$name.stdout.log"
    $stderr = Join-Path $logRoot "$name.stderr.log"
    $process = Start-Process -FilePath $exe -ArgumentList $arguments -WorkingDirectory $root -RedirectStandardOutput $stdout -RedirectStandardError $stderr -PassThru
    Start-Sleep -Seconds 2
    $process.Refresh()
    if ($process.HasExited) { throw "$name exited early. Read $stderr and $stdout" }
    Write-Host "STARTED $name PID=$($process.Id)"
    return $process
}

Require-File $vc
Require-File $db
Require-File (Join-Path $opensslRoot 'include\openssl\ssl.h')
foreach ($asset in @(
    'crates\ucr-realtime-web\static\endpoint-media\reference_browser_media_installer.js',
    'crates\ucr-realtime-web\static\endpoint-wasm\ucr_endpoint_wasm.js',
    'crates\ucr-realtime-web\static\endpoint-wasm\ucr_endpoint_wasm_bg.wasm'
)) { Require-File (Join-Path $root $asset) }
Require-Tool 'cargo'
$openssl = (Get-Command openssl.exe -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty Source)
if (!$openssl) {
    foreach ($candidate in @((Join-Path $opensslRoot 'bin\openssl.exe'),'C:\Program Files\Git\usr\bin\openssl.exe')) {
        if (Test-Path $candidate) { $openssl = $candidate; break }
    }
}
if (!$openssl) { throw 'OpenSSL executable not found; install OpenSSL CLI. No TLS security downgrade is permitted.' }

# Read the existing revision-matched local media files but never claim that presence proves live media.
if (!(Test-Path $cert) -or !(Test-Path $privateKey)) {
    Write-Host 'Generating a localhost-only development TLS certificate. NOT for production use.'
    Invoke-Checked $openssl @('req','-x509','-nodes','-newkey','rsa:3072','-sha256','-days','30','-keyout',$privateKey,'-out',$cert,'-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost,IP:127.0.0.1','-addext','basicConstraints=critical,CA:FALSE','-addext','extendedKeyUsage=serverAuth')
}
# Trust changes require an explicit user decision. A trust failure halts, not falls back to HTTP.
$thumbprint = (& $openssl x509 -in $cert -noout -fingerprint -sha256 | Out-String).Trim()
Write-Host "Local development certificate: $thumbprint"
$trusted = $false
try {
    $x509 = New-Object Security.Cryptography.X509Certificates.X509Certificate2($cert)
    $store = New-Object Security.Cryptography.X509Certificates.X509Store('Root','CurrentUser')
    $store.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
    try { $trusted = @($store.Certificates.Find([Security.Cryptography.X509Certificates.X509FindType]::FindByThumbprint,$x509.Thumbprint,$false)).Count -gt 0 }
    finally { $store.Close() }
} catch { throw "Certificate validation failed: $_" }
if (!$trusted) {
    $answer = Read-Host 'Trust this localhost test certificate for current Windows user? (type YES)'
    if ($answer -cne 'YES') { throw 'Certificate not trusted. Refusing to start insecure call UI.' }
    Invoke-Checked 'certutil.exe' @('-user','-addstore','Root',$cert)
}
# Match Visual C++ environment for cargo native media crates.
$vcLines = & cmd.exe /d /s /c ('call "' + $vc + '" >nul && set')
if ($LASTEXITCODE -ne 0) { throw 'VC x64 environment setup failed' }
foreach ($line in $vcLines) {
    $i=$line.IndexOf('=')
    if ($i -gt 0) { [Environment]::SetEnvironmentVariable($line.Substring(0,$i),$line.Substring($i+1),'Process') }
}
$env:OPENSSL_DIR = $opensslRoot
$env:OPENSSL_STATIC = '1'
$env:OPENSSL_NO_VENDOR = '1'
$env:CARGO_INCREMENTAL = '0'
$env:CARGO_BUILD_JOBS = '1'
$env:CARGO_PROFILE_DEV_DEBUG = '0'
Write-Host 'Building runtime + browser gateway + HTTPS edge from the currently checked-out revision...'
Invoke-Checked 'cargo' @('build','-p','ucr-runtime','-p','ucr-realtime-web','-p','ucr-https-edge','--locked')
$runtimeExe = Join-Path $root 'target\debug\ucr-runtime.exe'
$webExe = Join-Path $root 'target\debug\ucr-realtime-web.exe'
$edgeExe = Join-Path $root 'target\debug\ucr-https-edge.exe'
foreach ($exe in @($runtimeExe,$webExe,$edgeExe)) { Require-File $exe }

# Only stop UCR-owned binaries in this checkout; never kill unrelated listener processes.
foreach ($process in (Get-CimInstance Win32_Process | Where-Object { $_.Name -in @('ucr-runtime.exe','ucr-realtime-web.exe','ucr-https-edge.exe') })) {
    if ($process.ExecutablePath -and $process.ExecutablePath.StartsWith((Join-Path $root 'target\debug\'),[StringComparison]::OrdinalIgnoreCase)) {
        Stop-Process -Id $process.ProcessId -Force -ErrorAction Stop
    }
}
foreach ($port in @(50051,50052,8080,8081,8443)) {
    $listeners = @(Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue)
    if ($listeners.Count -gt 0) { throw "Port $port already occupied; refusing to take over an unrelated service" }
}
Add-Type -AssemblyName System.Security
if (!(Test-Path $keyFile)) {
    $bytes = New-Object byte[] 32
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
    try {
        $sealed = [Security.Cryptography.ProtectedData]::Protect($bytes,$null,[Security.Cryptography.DataProtectionScope]::CurrentUser)
        [IO.File]::WriteAllBytes($keyFile,$sealed)
    } finally { [Array]::Clear($bytes,0,$bytes.Length) }
}
$sealedBytes = [IO.File]::ReadAllBytes($keyFile)
$secret = [Security.Cryptography.ProtectedData]::Unprotect($sealedBytes,$null,[Security.Cryptography.DataProtectionScope]::CurrentUser)
if ($secret.Length -ne 32) { throw 'Invalid existing DPAPI Join key' }
$env:UCR_REALTIME_JOIN_KEY_HEX = -join ($secret | ForEach-Object { $_.ToString('x2') })
[Array]::Clear($secret,0,$secret.Length)

$env:UCR_BROWSER_REALTIME_GATEWAY_ENABLED = 'true'
$env:UCR_FIRST_PARTY_BIND = '127.0.0.1:8081'
$env:UCR_FIRST_PARTY_PUBLIC_ORIGIN = $origin
$env:UCR_FIRST_PARTY_SELF_SERVICE_TENANT = 'ucr-local-test'
$env:UCR_REALTIME_GRPC_UPSTREAM = 'http://127.0.0.1:50051'
$env:UCR_FIRST_PARTY_UPSTREAM = '127.0.0.1:8081'
$env:UCR_REALTIME_ALLOWED_ORIGINS = $origin
$env:UCR_HTTPS_EDGE_BIND = '127.0.0.1:8443'
$env:UCR_HTTPS_EDGE_UPSTREAM = '127.0.0.1:8080'
$env:UCR_HTTPS_EDGE_CERT_FILE = $cert
$env:UCR_HTTPS_EDGE_KEY_FILE = $privateKey
$launched = @()
try {
    $launched += Start-Ucr $runtimeExe @('serve-realtime','--database',$db,'--bind','127.0.0.1:50051','--operator-bind','127.0.0.1:50052','--join-base-url',$origin) 'runtime'
    $launched += Start-Ucr $webExe @() 'web'
    $launched += Start-Ucr $edgeExe @() 'https-edge'
    $ready = $false
    for ($i=0; $i -lt 20; $i++) {
        if ((Http-Status 'http://127.0.0.1:8080/readyz') -eq 200 -and
            (Http-Status "$origin/v1/first-party/bootstrap") -eq 200 -and
            (Http-Status "$origin/start") -eq 200) { $ready = $true; break }
        Start-Sleep -Seconds 2
    }
    if (!$ready) { throw "Readiness failed. Check $logRoot and /readyz; not claiming a working video call." }
    Write-Host 'UCR_LOCAL_HTTPS_FIRST_PARTY_READY'
    Write-Host "Open $origin/start"
    Start-Process "$origin/start"
    Write-Host 'Next test: create two independent trusted identities, accept Call, and verify actual E2EE bidirectional A/V.'
} catch {
    Write-Host "UCR local HTTPS startup failed: $_"
    foreach ($process in $launched) { if ($process -and !$process.HasExited) { Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue } }
    throw
}
