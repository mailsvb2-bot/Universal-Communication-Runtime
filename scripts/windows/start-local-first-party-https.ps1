# Local Windows first-party HTTPS smoke launcher; does not prove a two-person E2EE call.
param(
    [string]$RepositoryRoot = '',
    [switch]$OpenSecondPersistentProfile,
    [switch]$DebugBuild,
    [string]$PublicOrigin = '',
    [string]$PublicCertificate = '',
    [string]$PublicPrivateKey = '',
    [string]$PublicEdgeBind = '0.0.0.0:443',
    [string]$TurnUrl = '',
    [string]$TurnSecretFile = ''
)
# Keeps the existing canonical SQLite and in-process first-party BFF owner.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if ($RepositoryRoot) {
    $root = (Resolve-Path -LiteralPath $RepositoryRoot).Path
} else {
    $root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
}
if (!(Test-Path -LiteralPath (Join-Path $root 'Cargo.toml') -PathType Leaf) -or
    !(Test-Path -LiteralPath (Join-Path $root 'crates\ucr-realtime-web\static\start.html') -PathType Leaf)) {
    throw "Not a UCR repository root: $root. Pass -RepositoryRoot with the checked-out project path."
}
Set-Location $root
$state = Join-Path $env:LOCALAPPDATA 'UCR-Local-Test'
$db = Join-Path $state 'runtime.sqlite'
$keyFile = Join-Path $state 'join-signing.dpapi'
$cert = Join-Path $state 'localhost.crt.pem'
$privateKey = Join-Path $state 'localhost.key.pem'
# Optional public ingress uses this SAME canonical runtime and no alternate owner.
$remote = -not [string]::IsNullOrWhiteSpace($PublicOrigin)
$origin = 'https://localhost:8443'
if ($remote) {
    $parsed = $null
    if (-not [Uri]::TryCreate($PublicOrigin,[UriKind]::Absolute,[ref]$parsed) -or
        $parsed.Scheme -ne 'https' -or $parsed.Port -ne 443 -or
        $parsed.AbsolutePath -ne '/' -or $parsed.Query -or $parsed.Fragment -or
        $parsed.UserInfo -or $parsed.Host -eq 'localhost' -or
        $parsed.Host -notmatch '^[a-zA-Z0-9][a-zA-Z0-9.-]*[a-zA-Z0-9]$') {
        throw 'Public origin requires external HTTPS DNS on port 443, without path or credentials'
    }
    $ip = $null
    if ([Net.IPAddress]::TryParse($parsed.Host,[ref]$ip)) {
        throw 'Public origin must use DNS, not an IP literal'
    }
    if ($PublicEdgeBind -cnotmatch '^(0\.0\.0\.0|\[::\]):443$') {
        throw 'Public edge must bind TCP 443; internal APIs remain loopback'
    }
    if (!$PublicCertificate -or !$PublicPrivateKey -or
        !(Test-Path -LiteralPath $PublicCertificate -PathType Leaf) -or
        !(Test-Path -LiteralPath $PublicPrivateKey -PathType Leaf)) {
        throw 'Public TLS certificate and private key must already exist'
    }
    $turnMatch = [regex]::Match($TurnUrl, '^turns:([a-zA-Z0-9][a-zA-Z0-9.-]*[a-zA-Z0-9])(?::([0-9]{1,5}))?(\?transport=tcp)?$', [Text.RegularExpressions.RegexOptions]::IgnoreCase)
    if (!$turnMatch.Success -or !$TurnSecretFile -or
        !(Test-Path -LiteralPath $TurnSecretFile -PathType Leaf)) {
        throw 'Public mode requires external TURNS and existing TURN REST secret'
    }
    $turnHost = $turnMatch.Groups[1].Value
    if ($turnMatch.Groups[2].Success) {
        $turnPort = [int]$turnMatch.Groups[2].Value
        if ($turnPort -lt 1 -or $turnPort -gt 65535) { throw 'Invalid public TURN port' }
    }
    $turnIp = $null
    if ($turnHost -eq 'localhost' -or [Net.IPAddress]::TryParse($turnHost,[ref]$turnIp)) {
        throw 'Public TURN must use an external DNS hostname'
    }
    $origin = $parsed.AbsoluteUri.TrimEnd('/')
    $cert = (Resolve-Path -LiteralPath $PublicCertificate).Path
    $privateKey = (Resolve-Path -LiteralPath $PublicPrivateKey).Path
} elseif ($PublicCertificate -or $PublicPrivateKey -or $TurnUrl -or $TurnSecretFile) {
    throw 'External TLS/TURN parameters require -PublicOrigin'
}
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
# Windows Server 2016 PowerShell's .NET TLS client can omit the signature_algorithms
# extension required by rustls. Use Git-for-Windows curl with certificate verification
# instead of weakening the HTTPS edge or accepting any invalid certificate.
$curl = $null
foreach ($candidate in @('C:\Program Files\Git\mingw64\bin\curl.exe','C:\Program Files\Git\usr\bin\curl.exe')) {
    if (Test-Path -LiteralPath $candidate -PathType Leaf) { $curl = $candidate; break }
}
if (!$curl) {
    $installedCurl = Get-Command curl.exe -ErrorAction SilentlyContinue
    if ($installedCurl) { $curl = $installedCurl.Source }
}
if (!$curl) { throw 'curl.exe with modern TLS support is required to verify the local HTTPS edge (Git for Windows includes one).' }
function Https-Status([string]$uri) {
    # Public: normal CA/hostname validation. Local: pin development cert.
    # Never use -k/--insecure or install a public certificate as a local CA.
    $args = @('--silent','--show-error','--max-time','6','--output','NUL','--write-out','%{http_code}')
    if (!$remote) { $args = @('--cacert',$cert) + $args }
    $status = & $curl @args $uri
    if ($LASTEXITCODE -ne 0) { return 0 }
    $code = 0
    if ([int]::TryParse(($status | Out-String).Trim(),[ref]$code)) { return $code }
    return 0
}
function Start-Ucr([string]$exe,[string[]]$arguments,[string]$name) {
    $stdout = Join-Path $logRoot "$name.stdout.log"
    $stderr = Join-Path $logRoot "$name.stderr.log"
    $startParams = @{ FilePath=$exe; WorkingDirectory=$root; RedirectStandardOutput=$stdout; RedirectStandardError=$stderr; PassThru=$true }
    if ($arguments.Count -gt 0) { $startParams.ArgumentList = $arguments }
    $process = Start-Process @startParams
    Start-Sleep -Seconds 2
    $process.Refresh()
    if ($process.HasExited) { throw "$name exited early. Read $stderr and $stdout" }
    Write-Host "STARTED $name PID=$($process.Id)"
    return $process
}

Require-File $vc
Require-File (Join-Path $opensslRoot 'include\openssl\ssl.h')
Require-Tool 'cargo'
$openssl = (Get-Command openssl.exe -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty Source)
if (!$openssl) {
    foreach ($candidate in @((Join-Path $opensslRoot 'bin\openssl.exe'),'C:\Program Files\Git\usr\bin\openssl.exe')) {
        if (Test-Path $candidate) { $openssl = $candidate; break }
    }
}
if (!$openssl) { throw 'OpenSSL executable not found; install OpenSSL CLI. No TLS security downgrade is permitted.' }

# An expired/mismatched certificate is never reused. Check before trusting it.
# Rotate proactively with at least 24 hours remaining, to avoid dying mid-session.
$renewCertificate = !$remote -and (
    !(Test-Path -LiteralPath $cert -PathType Leaf) -or
    !(Test-Path -LiteralPath $privateKey -PathType Leaf)
)
if ($remote) {
    & $openssl 'x509' '-in' $cert '-noout' '-checkend' '86400' 2>$null | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Public TLS certificate expires within 24 hours or is invalid' }
    $certPublic = (& $openssl 'x509' '-in' $cert '-pubkey' '-noout' | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or !$certPublic) { throw 'Public TLS certificate public key unavailable' }
    $keyPublic = (& $openssl 'pkey' '-in' $privateKey '-pubout' | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or !$keyPublic -or $certPublic -cne $keyPublic) {
        throw 'Public TLS certificate/private key mismatch'
    }
    $hostCheck = (& $openssl 'x509' '-in' $cert '-noout' '-checkhost' $parsed.Host | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or $hostCheck -notmatch 'does match certificate') {
        throw 'Public TLS certificate hostname mismatch'
    }
} elseif (!$renewCertificate) {
    & $openssl 'x509' '-in' $cert '-noout' '-checkend' '86400' 2>$null | Out-Null
    if ($LASTEXITCODE -ne 0) { $renewCertificate = $true }
    if (!$renewCertificate) {
        $certPublic = (& $openssl 'x509' '-in' $cert '-pubkey' '-noout' | Out-String).Trim()
        $keyPublic = (& $openssl 'pkey' '-in' $privateKey '-pubout' | Out-String).Trim()
        if ($LASTEXITCODE -ne 0 -or !$certPublic -or $certPublic -ne $keyPublic) {
            $renewCertificate = $true
        }
    }
}
if ($renewCertificate) {
    Write-Host 'Generating a localhost-only development TLS certificate. NOT for production use.'
    # Some Windows OpenSSL distributions (notably Strawberry Perl) point at a
    # non-existent built-in openssl.cnf. Use an explicit, minimal certificate
    # profile so no machine-global OPENSSL_CONF or installation is required.
    $config = Join-Path $state 'localhost-openssl.cnf'
    $profile = @(
        '[req]',
        'prompt = no',
        'distinguished_name = subject',
        'x509_extensions = localhost_extensions',
        '[subject]',
        'CN = localhost',
        '[localhost_extensions]',
        'basicConstraints = critical,CA:FALSE',
        'keyUsage = critical,digitalSignature,keyEncipherment',
        'extendedKeyUsage = serverAuth',
        'subjectAltName = DNS:localhost,IP:127.0.0.1'
    )
    [IO.File]::WriteAllLines($config, [string[]]$profile, [Text.Encoding]::ASCII)
    # Generate replacements off-path; never leave a fresh key paired with an old certificate.
    $nextCert = Join-Path $state 'localhost.next.crt.pem'
    $nextKey = Join-Path $state 'localhost.next.key.pem'
    try {
        Invoke-Checked $openssl @('req','-x509','-nodes','-newkey','rsa:3072','-sha256','-days','30','-config',$config,'-extensions','localhost_extensions','-keyout',$nextKey,'-out',$nextCert)
        Move-Item -LiteralPath $nextKey -Destination $privateKey -Force
        Move-Item -LiteralPath $nextCert -Destination $cert -Force
    } finally {
        Remove-Item -LiteralPath $nextCert,$nextKey -Force -ErrorAction SilentlyContinue
    }
}
# Trust changes require an explicit user decision. A trust failure halts, not falls back to HTTP.
$thumbprint = (& $openssl x509 -in $cert -noout -fingerprint -sha256 | Out-String).Trim()
if ($remote) { Write-Host "Public certificate: $thumbprint" }
else { Write-Host "Local development certificate: $thumbprint" }
$trusted = $remote
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
# Stop only the previous UCR binaries in this checkout BEFORE cargo links new EXEs.
# On Windows an executing .exe is locked and link.exe fails with LNK1104.
# Only stop UCR-owned binaries in this checkout; never kill unrelated listener processes.
foreach ($process in (Get-CimInstance Win32_Process | Where-Object { $_.Name -in @('ucr-runtime.exe','ucr-realtime-web.exe','ucr-https-edge.exe') })) {
    if ($process.ExecutablePath -and ($process.ExecutablePath.StartsWith((Join-Path $root 'target\debug\'),[StringComparison]::OrdinalIgnoreCase) -or $process.ExecutablePath.StartsWith((Join-Path $root 'target\release\'),[StringComparison]::OrdinalIgnoreCase))) {
        Stop-Process -Id $process.ProcessId -Force -ErrorAction Stop
    }
}
$edgePort = if ($remote) { 443 } else { 8443 }
foreach ($port in @(50051,50052,8080,8081,$edgePort)) {
    $listeners = @(Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue)
    if ($listeners.Count -gt 0) { throw "Port $port already occupied; refusing to take over an unrelated service" }
}
Start-Sleep -Milliseconds 600
# Browser WASM and installer are generated, gitignored outputs. Their existence
# says nothing about source revision. Build BOTH from this checkout on every launch.
# The shared builder pins wasm-bindgen and esbuild and verifies nonempty outputs.
Require-Tool 'npm.cmd'
Write-Host 'Rebuilding revision-matched endpoint WASM and browser media...'
& (Join-Path $root 'scripts\windows\build-browser-media.ps1')
if (!$?) { throw 'Revision-matched browser media build failed' }
foreach ($asset in @(
    'crates\ucr-realtime-web\static\endpoint-media\reference_browser_media_installer.js',
    'crates\ucr-realtime-web\static\endpoint-wasm\ucr_endpoint_wasm.js',
    'crates\ucr-realtime-web\static\endpoint-wasm\ucr_endpoint_wasm_bg.wasm'
)) { Require-File (Join-Path $root $asset) }
Write-Host 'Building runtime + browser gateway + HTTPS edge from the currently checked-out revision...'
# Release by default to avoid slow unoptimized encrypted media forwarding.
$profileDir = if ($DebugBuild) { 'debug' } else { 'release' }
$cargoArgs = @('build','-p','ucr-runtime','-p','ucr-realtime-web','-p','ucr-https-edge','--locked')
if (!$DebugBuild) { $cargoArgs += '--release' }
Invoke-Checked 'cargo' $cargoArgs
$runtimeExe = Join-Path $root "target\$profileDir\ucr-runtime.exe"
$webExe = Join-Path $root "target\$profileDir\ucr-realtime-web.exe"
$edgeExe = Join-Path $root "target\$profileDir\ucr-https-edge.exe"
Write-Host 'NOTE: Windows Firewall may ask about ucr-runtime.exe (WebRTC UDP socket).'
Write-Host '      For same-host testing, permit only Private networks if needed.'
Write-Host '      A second LAN device may require allowing Private networks.'
foreach ($exe in @($runtimeExe,$webExe,$edgeExe)) { Require-File $exe }
# One-command first launch: initialize ONLY when no local database exists.
# Never overwrite an existing Identity, Contact, Device or Call database.
if (!(Test-Path -LiteralPath $db -PathType Leaf)) {
    Write-Host 'Initializing canonical local UCR SQLite database...'
    Invoke-Checked $runtimeExe @('init','--database',$db)
}
Require-File $db

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

if ($remote) {
    $turnBytes = [IO.File]::ReadAllBytes((Resolve-Path -LiteralPath $TurnSecretFile).Path)
    try {
        if ($turnBytes.Length -eq 32) {
            $turnHex = -join ($turnBytes | ForEach-Object { $_.ToString('x2') })
        } elseif ($turnBytes.Length -eq 64) {
            $turnHex = [Text.Encoding]::ASCII.GetString($turnBytes)
            if ($turnHex -cnotmatch '^[0-9a-fA-F]{64}$') {
                throw 'TURN secret must be 32 raw bytes or 64 hexadecimal digits'
            }
        } else {
            throw 'TURN secret must be 32 raw bytes or 64 hexadecimal digits'
        }
        $env:UCR_WEBRTC_TURN_URLS = $TurnUrl
        $env:UCR_WEBRTC_TURN_SECRET_HEX = $turnHex
        $env:UCR_WEBRTC_RELAY_ONLY = 'true'
    } finally {
        [Array]::Clear($turnBytes,0,$turnBytes.Length)
    }
} else {
    Remove-Item Env:UCR_WEBRTC_TURN_URLS,Env:UCR_WEBRTC_TURN_SECRET_HEX,Env:UCR_WEBRTC_RELAY_ONLY -ErrorAction SilentlyContinue
}

$env:UCR_BROWSER_REALTIME_GATEWAY_ENABLED = 'true'
$env:UCR_FIRST_PARTY_BIND = '127.0.0.1:8081'
$env:UCR_FIRST_PARTY_PUBLIC_ORIGIN = $origin
$env:UCR_FIRST_PARTY_SELF_SERVICE_TENANT = 'ucr-local-test'
$env:UCR_REALTIME_GRPC_UPSTREAM = 'http://127.0.0.1:50051'
$env:UCR_FIRST_PARTY_UPSTREAM = '127.0.0.1:8081'
$env:UCR_REALTIME_ALLOWED_ORIGINS = $origin
$env:UCR_HTTPS_EDGE_BIND = if ($remote) { $PublicEdgeBind } else { '127.0.0.1:8443' }
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
            (Https-Status "$origin/v1/first-party/bootstrap") -eq 200 -and
            (Https-Status "$origin/start") -eq 200) { $ready = $true; break }
        Start-Sleep -Seconds 2
    }
    if (!$ready) { throw "Readiness failed. Check $logRoot and /readyz; not claiming a working video call." }
    if ($remote) { Write-Host 'UCR_PUBLIC_HTTPS_EDGE_STARTED_NOT_A_CALL_PROOF' }
    else { Write-Host 'UCR_LOCAL_HTTPS_FIRST_PARTY_READY' }
    Write-Host "Open $origin/start"
    if (!$remote) { Start-Process "$origin/start" }
    if ($OpenSecondPersistentProfile -and !$remote) {
        & (Join-Path $root 'scripts\windows\open-second-persistent-chrome.ps1')
    }
    if ($remote) { Write-Host 'TURNS relay reachability, coturn REST secret parity and Android admission remain unverified.' }
    Write-Host 'Next test: create two independent trusted identities, accept Call, and verify actual E2EE bidirectional A/V.'
} catch {
    Write-Host "UCR local HTTPS startup failed: $_"
    foreach ($process in $launched) { if ($process -and !$process.HasExited) { Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue } }
    throw
}
