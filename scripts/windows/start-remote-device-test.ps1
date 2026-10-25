# Fail-closed preflight for Android-over-cellular UCR sessions.
# Does not expose localhost services, download tunnel clients, or modify the working local test.
[CmdletBinding()]
param(
    [string]$PublicOrigin,
    [string]$TurnUrl,
    [switch]$Json,
    [switch]$SelfTest
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Is-PrivateHost([string]$hostName) {
    $h = $hostName.ToLowerInvariant().TrimEnd('.')
    if ($h -eq 'localhost' -or $h -eq '0.0.0.0' -or $h -eq '::1' -or $h.EndsWith('.localhost') -or
        $h.EndsWith('.local') -or $h.EndsWith('.internal')) { return $true }
    $ip = $null
    if ([Net.IPAddress]::TryParse($h, [ref]$ip)) {
        $bytes = $ip.GetAddressBytes()
        if ($ip.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetworkV6) {
            # IPv4-mapped IPv6 loopback/private addresses must not bypass the
            # IPv4 exclusions (e.g. ::ffff:127.0.0.1 or ::ffff:10.0.0.1).
            if ($ip.IsIPv4MappedToIPv6) { return (Is-PrivateHost ($ip.MapToIPv4().ToString())) }
            return ($ip.IsIPv6LinkLocal -or $ip.IsIPv6SiteLocal -or
                $ip.IsIPv6Multicast -or $ip.Equals([Net.IPAddress]::IPv6Any) -or
                $ip.Equals([Net.IPAddress]::IPv6Loopback) -or
                (($bytes[0] -band 254) -eq 252))
        }
        return ($bytes[0] -eq 10 -or $bytes[0] -eq 127 -or $bytes[0] -eq 0 -or
            ($bytes[0] -eq 169 -and $bytes[1] -eq 254) -or
            ($bytes[0] -eq 172 -and $bytes[1] -ge 16 -and $bytes[1] -le 31) -or
            ($bytes[0] -eq 192 -and $bytes[1] -eq 168) -or
            ($bytes[0] -eq 100 -and $bytes[1] -ge 64 -and $bytes[1] -le 127))
    }
    return $false
}

# Repo-local security regression; does not contact any external host.
if ($SelfTest) {
    $cases = @(
        @{ Name = 'localhost'; Block = $true },
        @{ Name = '127.0.0.1'; Block = $true },
        @{ Name = '10.10.1.2'; Block = $true },
        @{ Name = '192.168.1.2'; Block = $true },
        @{ Name = '::1'; Block = $true },
        @{ Name = '::'; Block = $true },
        @{ Name = 'ff02::1'; Block = $true },
        @{ Name = '::ffff:127.0.0.1'; Block = $true },
        @{ Name = '::ffff:10.0.0.1'; Block = $true },
        @{ Name = 'fd00::1'; Block = $true },
        @{ Name = '8.8.8.8'; Block = $false },
        @{ Name = '2001:4860:4860::8888'; Block = $false },
        @{ Name = 'example.com'; Block = $false }
    )
    foreach ($case in $cases) {
        if ((Is-PrivateHost $case.Name) -ne $case.Block) {
            throw ('Remote preflight private-host regression: ' + $case.Name)
        }
    }
    # Execute the actual JSON/exit-code path in a fresh local PowerShell process.
    # A relative URI must never throw before reporting its structured blockers.
    $powershellExe = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
    foreach ($invalidOrigin in @('example.com', 'http://example.com', 'https://localhost')) {
        $raw = & $powershellExe -NoProfile -File $PSCommandPath -PublicOrigin $invalidOrigin -Json
        $exitCode = $LASTEXITCODE
        if ($exitCode -ne 2) { throw ('Remote preflight invalid-origin exit regression: ' + $invalidOrigin) }
        try { $report = $raw | Out-String | ConvertFrom-Json }
        catch { throw ('Remote preflight invalid-origin JSON regression: ' + $invalidOrigin) }
        $originErrors = @($report.blockers | Where-Object { $_ -like 'PUBLIC_HTTPS_ORIGIN_INVALID:*' })
        if ($report.ready -ne $false -or $null -ne $report.publicOrigin -or $originErrors.Count -ne 1) {
            throw ('Remote preflight invalid-origin blocker regression: ' + $invalidOrigin)
        }
    }
    Write-Output 'PASS: remote preflight private-host and invalid-origin JSON exclusions'
    exit 0
}

$blockers = New-Object 'System.Collections.Generic.List[string]'
$parsedOrigin = $null
if ([string]::IsNullOrWhiteSpace($PublicOrigin)) {
    $blockers.Add('PUBLIC_HTTPS_ORIGIN_MISSING: the existing UCR launcher is localhost-only.')
} else {
    try {
        $parsedOrigin = [Uri]$PublicOrigin
        if (!$parsedOrigin.IsAbsoluteUri -or $parsedOrigin.Scheme -ne 'https' -or
            $parsedOrigin.AbsolutePath -ne '/' -or $parsedOrigin.Query -or $parsedOrigin.Fragment -or
            !$parsedOrigin.IsDefaultPort -or !$parsedOrigin.UserInfo.Equals('') -or
            (Is-PrivateHost $parsedOrigin.Host)) {
            $blockers.Add('PUBLIC_HTTPS_ORIGIN_INVALID: require an external https://hostname origin with no path, credentials, or custom port.')
            $parsedOrigin = $null
        }
    } catch {
        $parsedOrigin = $null
        $blockers.Add('PUBLIC_HTTPS_ORIGIN_INVALID: not a valid absolute URI.')
    }
}
if ([string]::IsNullOrWhiteSpace($TurnUrl)) {
    $blockers.Add('TURN_RELAY_NOT_CONFIGURED: different mobile networks need a reachable ICE relay or verified publicly reachable media endpoint.')
} else {
    if ($TurnUrl -notmatch '^turns:[^/?#:@]+(:[0-9]{1,5})?(\?transport=tcp)?$') {
        $blockers.Add('TURN_RELAY_INVALID: use turns:hostname:port?transport=tcp, and provision credentials separately.')
    } elseif ($TurnUrl -match '^turns:([^:/?]+)' -and (Is-PrivateHost $Matches[1])) {
        $blockers.Add('TURN_RELAY_INVALID: relay host cannot be loopback or private.')
    }
}
# Domain + TURN configuration alone cannot prove that the BFF/Join advertised origin,
# relay credentials, firewall and actual ICE candidate pair work from Android.
$blockers.Add('REMOTE_END_TO_END_PROOF_MISSING: a public HTTPS page is not proof of a working authorized WebRTC media path.')
$result = [ordered]@{
    ready = $false
    publicOrigin = if ($parsedOrigin) { $parsedOrigin.GetLeftPart([UriPartial]::Authority) } else { $null }
    androidBrowserOnly = $true
    separateServerRequired = $false
    tests = @('Android HTTPS certificate and authenticated admission', 'Call Join origin/Device binding', 'ICE candidate pair and TURN consent', '30-minute bidirectional E2EE audio/video')
    blockers = @($blockers)
}
if ($Json) {
    $result | ConvertTo-Json -Depth 4
} else {
    Write-Host 'UCR Android-over-cellular preflight: NOT READY'
    foreach ($b in $blockers) { Write-Host ('BLOCKED: ' + $b) }
    Write-Host 'Local HTTPS test remains unchanged. Do not forward local BFF/registration ports publicly.'
}
exit 2
