#requires -Version 5.1
<# Read-only review, plus opt-in single-account password reset. No shared hardcoded password. #>
[CmdletBinding()]
param([string]$UserName, [switch]$ResetOnePassword)
Get-LocalUser | Select-Object Name,Enabled,PasswordRequired,PasswordExpires,PasswordLastSet | Format-Table -AutoSize
Write-Host "`nLOCAL ADMINISTRATORS:" -ForegroundColor Cyan
Get-LocalGroupMember -SID 'S-1-5-32-544' | Select-Object Name,ObjectClass,PrincipalSource | Format-Table -AutoSize
if ($ResetOnePassword) {
    if ([string]::IsNullOrWhiteSpace($UserName)) { throw 'Supply -UserName for a single authorized account.' }
    $user=Get-LocalUser -Name $UserName -ErrorAction Stop
    Write-Host "Resetting only $($user.Name). Use an individual strong password." -ForegroundColor Yellow
    $secure=Read-Host 'New unique password' -AsSecureString
    Set-LocalUser -Name $UserName -Password $secure
    Write-Host 'Password updated for specified account.' -ForegroundColor Green
}
