#requires -Version 5.1
<#
.SYNOPSIS
  Conservative, repeatable local security baseline for Windows 11 / Server 2022.
.DESCRIPTION
  Default: reports proposed changes (WhatIf). Use -Apply to apply baseline settings.
  Never deletes users, resets passwords en masse, removes software, or deletes files.
  Always read the competition README and inspect the report before applying.
.EXAMPLE
  .\Start-Hardening.ps1 -Profile Windows11
.EXAMPLE
  .\Start-Hardening.ps1 -Profile Server2022 -Apply
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [ValidateSet('Windows11','Server2022')][string]$Profile = 'Windows11',
    [switch]$Apply
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$config = Get-Content -LiteralPath (Join-Path $root "Config\$Profile.json") -Raw | ConvertFrom-Json
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$backup = Join-Path $root "Backups\$Profile-$stamp"
New-Item -ItemType Directory -Force -Path $backup | Out-Null
$log = Join-Path $backup 'changes.log'
function Log([string]$Message) { Add-Content -Path $log -Value ('{0} {1}' -f (Get-Date -Format s), $Message); Write-Host $Message }
function Run-Native([string]$Name, [string[]]$Arguments) {
    Log "RUN $Name $($Arguments -join ' ')"
    & $Name @Arguments 2>&1 | Out-String | ForEach-Object { if ($_.Trim()) { Log $_.Trim() } }
    if ($LASTEXITCODE -ne 0) { throw "$Name exited with code $LASTEXITCODE" }
}
function Change([string]$Title, [scriptblock]$Action) {
    if (-not $Apply) { Log "PLAN $Title"; return }
    if ($PSCmdlet.ShouldProcess($env:COMPUTERNAME, $Title)) {
        try { & $Action; Log "OK $Title" } catch { Log "ERROR $Title : $($_.Exception.Message)" }
    }
}
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$admin = ([Security.Principal.WindowsPrincipal]$identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if ($Apply -and -not $admin) { throw 'Run an elevated PowerShell console for -Apply.' }
Log "Profile=$Profile; Apply=$Apply; Computer=$env:COMPUTERNAME; Administrator=$admin"
Log 'WARNING: Review the image README. Domain policies can override local settings.'
# Preserve machine-level policy and firewall configuration before altering anything.
if ($Apply) {
    & secedit.exe /export /cfg (Join-Path $backup 'security-before.inf') /quiet 2>&1 | Out-Null
    & auditpol.exe /backup ('/file:' + (Join-Path $backup 'audit-before.csv')) 2>&1 | Out-Null
    try { Get-NetFirewallProfile | Export-Clixml -Path (Join-Path $backup 'firewall-profiles-before.xml') } catch {}
    foreach ($key in @('HKLM\SOFTWARE\Policies\Google\Chrome','HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System','HKLM\SYSTEM\CurrentControlSet\Control\Lsa')) {
        $target = ($key -replace '[^A-Za-z0-9]','_') + '.reg'
        & reg.exe export $key (Join-Path $backup $target) /y 2>&1 | Out-Null
    }
}
Change 'Set password length, history, age and lockout thresholds' {
    Run-Native 'net.exe' @('accounts',"/minpwlen:$($config.MinimumPasswordLength)","/uniquepw:$($config.PasswordHistory)","/maxpwage:$($config.MaximumPasswordAgeDays)","/minpwage:$($config.MinimumPasswordAgeDays)","/lockoutthreshold:$($config.LockoutThreshold)","/lockoutduration:$($config.LockoutDurationMinutes)","/lockoutwindow:$($config.LockoutWindowMinutes)")
}
Change 'Enable all firewall profiles and block unsolicited inbound connections' {
    Get-NetFirewallProfile | Set-NetFirewallProfile -Enabled True -DefaultInboundAction Block
}
Change 'Enable UAC and administrator approval prompts' {
    $key='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    New-Item -Path $key -Force | Out-Null
    New-ItemProperty -Path $key -Name EnableLUA -Value 1 -PropertyType DWord -Force | Out-Null
    New-ItemProperty -Path $key -Name ConsentPromptBehaviorAdmin -Value 5 -PropertyType DWord -Force | Out-Null
    New-ItemProperty -Path $key -Name PromptOnSecureDesktop -Value 1 -PropertyType DWord -Force | Out-Null
}
Change 'Disable storage of legacy LM password hashes and enable NTLMv2 policy' {
    $key='HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    New-ItemProperty -Path $key -Name NoLMHash -Value 1 -PropertyType DWord -Force | Out-Null
    New-ItemProperty -Path $key -Name LmCompatibilityLevel -Value 5 -PropertyType DWord -Force | Out-Null
}
Change 'Disable reversible password encryption via local security template' {
    $inf=Join-Path $backup 'baseline.inf'
    @('[Unicode]','Unicode=yes','[Version]','signature="$CHICAGO$"','Revision=1','[System Access]','ClearTextPassword = 0') | Set-Content -Path $inf -Encoding Unicode
    Run-Native 'secedit.exe' @('/configure','/db',(Join-Path $backup 'baseline.sdb'),'/cfg',$inf,'/areas','SECURITYPOLICY','/quiet')
}
Change 'Enable important Advanced Audit Policy subcategories' {
    foreach ($subcategory in @('Credential Validation','Security Group Management','Sensitive Privilege Use','Logon','Account Lockout','Audit Policy Change')) {
        Run-Native 'auditpol.exe' @('/set',"/subcategory:$subcategory",'/success:enable','/failure:enable')
    }
}
Change 'Enable Windows Defender PUA protection (when available)' {
    if (Get-Command Set-MpPreference -ErrorAction SilentlyContinue) { Set-MpPreference -PUAProtection Enabled }
}
if ($config.DisableGuest) {
    Change 'Disable built-in Guest account by SID (avoids localized name mismatch)' {
        $guest=Get-LocalUser | Where-Object { $_.SID.Value -match '-501$' }
        if ($guest) { $guest | Disable-LocalUser }
    }
}
if ($config.DisableSpooler) {
    Change 'Disable Print Spooler (only when printing is not required)' {
        if (Get-Service Spooler -ErrorAction SilentlyContinue) {
            Stop-Service Spooler -Force -ErrorAction SilentlyContinue
            Set-Service Spooler -StartupType Disabled
        }
    }
}
if ($config.DisableSimpleTcpIp) {
    Change 'Disable Simple TCP/IP Services if installed' {
        $service=Get-Service simptcp -ErrorAction SilentlyContinue
        if ($service) { Stop-Service simptcp -Force -ErrorAction SilentlyContinue; Set-Service simptcp -StartupType Disabled }
    }
}
if ($config.EnableWindowsUpdate) {
    Change 'Allow Windows automatic updates (policy; download/install still depends on environment)' {
        $key='HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
        New-Item -Path $key -Force | Out-Null
        New-ItemProperty -Path $key -Name NoAutoUpdate -Value 0 -PropertyType DWord -Force | Out-Null
        New-ItemProperty -Path $key -Name AUOptions -Value 4 -PropertyType DWord -Force | Out-Null
    }
}
if ($config.DisableAutoRun) {
    Change 'Disable AutoRun/AutoPlay via Explorer machine policies (review removable-media requirements)' {
        $key='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
        New-Item -Path $key -Force | Out-Null
        New-ItemProperty -Path $key -Name NoDriveTypeAutoRun -Value 255 -PropertyType DWord -Force | Out-Null
        New-ItemProperty -Path $key -Name NoAutorun -Value 1 -PropertyType DWord -Force | Out-Null
    }
}
if ($config.ConfigureChromePolicies) {
    Change 'Enable Chrome Safe Browsing, block dangerous downloads and use HTTPS-first preference' {
        $key='HKLM:\SOFTWARE\Policies\Google\Chrome'
        New-Item -Path $key -Force | Out-Null
        New-ItemProperty -Path $key -Name SafeBrowsingProtectionLevel -Value 2 -PropertyType DWord -Force | Out-Null
        New-ItemProperty -Path $key -Name DownloadRestrictions -Value 1 -PropertyType DWord -Force | Out-Null
        New-ItemProperty -Path $key -Name HttpsOnlyMode -Value 'force_enabled' -PropertyType String -Force | Out-Null
    }
}
Log 'NOTE: Password complexity is intentionally not changed by this script; configure separately when approved.'
Log 'MANUAL: authorized accounts/admins, individual password resets, permissions, unwanted apps, suspicious files, web server config, forensic questions and app updates.'
Log "Finished. Logs and pre-change snapshots: $backup"
if (-not $Apply) { Log 'DRY RUN ONLY: no security baseline settings changed. Repeat with -Apply after inspecting README.' }
