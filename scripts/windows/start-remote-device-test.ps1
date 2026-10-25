# Fail-closed preflight for Android-over-cellular UCR sessions.
# Does not expose localhost services, download tunnel clients, or modify the working local test.
[CmdletBinding()]
param(
    [string]$PublicOrigin,
    [string]$TurnUrl,
    [switch]$Json
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
            return ($ip.IsIPv6LinkLocal -or $ip.IsIPv6SiteLocal -or $ip.Equals([Net.IPAddress]::IPv6Loopback) -or
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
        }
    } catch {
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
