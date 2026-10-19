# Persistent second browser identity for UCR. Existing normal Chrome remains person 1.
# Unlike Incognito, the second participant's protected browser Device key survives restarts.
$ErrorActionPreference = 'Stop'
$programFilesX86 = [Environment]::GetEnvironmentVariable('ProgramFiles(x86)')
$candidates = @(
  (Join-Path $env:ProgramFiles 'Google\Chrome\Application\chrome.exe'),
  (Join-Path $programFilesX86 'Google\Chrome\Application\chrome.exe'),
  (Join-Path $env:LOCALAPPDATA 'Google\Chrome\Application\chrome.exe')
)
$chrome = $candidates | Where-Object { $_ -and (Test-Path -LiteralPath $_ -PathType Leaf) } | Select-Object -First 1
if (!$chrome) { throw 'Google Chrome was not found. Use two persistent Chrome profiles manually.' }
$profileRoot = Join-Path $env:LOCALAPPDATA 'UCR-Local-Test\chrome-second-person'
New-Item -ItemType Directory -Force -Path $profileRoot | Out-Null
Write-Host "Persistent participant 2 browser profile: $profileRoot"
Start-Process -FilePath $chrome -ArgumentList @("--user-data-dir=`"$profileRoot`"",'--new-window','https://localhost:8443/start')
