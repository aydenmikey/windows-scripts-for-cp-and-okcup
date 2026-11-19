#requires -Version 5.1
[CmdletBinding()]
param([ValidateSet('Windows11','Server2022')][string]$Profile='Windows11')
$root=Split-Path -Parent $MyInvocation.MyCommand.Path
$config=Get-Content (Join-Path $root "Config\$Profile.json") -Raw | ConvertFrom-Json
$results=New-Object System.Collections.Generic.List[object]
function Check([string]$Name,[bool]$Passed,[string]$Observed) {
    $script:results.Add([pscustomobject]@{Check=$Name;Pass=$Passed;Observed=$Observed})
}
$accounts=net accounts | Out-String
$minimum=[regex]::Match($accounts,'Minimum password length:\s*(\d+)')
if($minimum.Success) { Check 'Minimum password length' ([int]$minimum.Groups[1].Value -ge [int]$config.MinimumPasswordLength) $minimum.Groups[1].Value }
$profiles=Get-NetFirewallProfile
Check 'All firewall profiles enabled' (-not @($profiles | Where-Object { -not $_.Enabled }).Count) (($profiles | ForEach-Object {"$($_.Name)=$($_.Enabled)"}) -join '; ')
$uac=(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -ErrorAction SilentlyContinue).EnableLUA
Check 'UAC enabled' ($uac -eq 1) "EnableLUA=$uac"
$guest=Get-LocalUser | Where-Object { $_.SID.Value -match '-501$' }
if($guest) { Check 'Guest disabled' (-not $guest.Enabled) "Enabled=$($guest.Enabled)" }
$pref=Get-MpPreference -ErrorAction SilentlyContinue
if($pref){ Check 'Defender PUA protection' ($pref.PUAProtection -eq 1) "PUAProtection=$($pref.PUAProtection)" }
$results | Format-Table -AutoSize -Wrap
$dest=Join-Path $root ('Reports\Compliance-{0}-{1}.csv' -f $Profile,(Get-Date -Format 'yyyyMMdd-HHmmss'))
$results | Export-Csv $dest -NoTypeInformation
Write-Host "Saved: $dest" -ForegroundColor Cyan
Write-Host 'This tests a subset of settings. A passing report is not a competition score guarantee.'
