#requires -Version 5.1
[CmdletBinding()]
param([ValidateSet('Windows11','Server2022')][string]$Profile='Windows11')
$root=Split-Path -Parent $MyInvocation.MyCommand.Path
function Invoke-Local([string]$File,[string[]]$Arguments=@()) {& (Join-Path $root $File) @Arguments}
while($true) {
 Write-Host "`n=== WINDOWS SECURITY TOOLKIT : $Profile ===" -ForegroundColor Cyan
 Write-Host '1  Full read-only audit'
 Write-Host '2  Read-only remaining-issues investigation'
 Write-Host '3  Preview safe baseline hardening'
 Write-Host '4  Apply baseline (after README review and VM snapshot)'
 Write-Host '5  Compliance summary'
 Write-Host '6  List accounts and privileges'
 Write-Host '7  Manage accounts interactively'
 Write-Host '8  Review Defender exclusions'
 Write-Host '9  Preview optional RDP encryption change'
 Write-Host '0  Exit'
 $choice=Read-Host 'Select option'
 try {
  switch($choice) {
   '1' {Invoke-Local 'Start-Audit.ps1'}
   '2' {Invoke-Local 'Modules\Inspect-Remaining.ps1'}
   '3' {Invoke-Local 'Start-Hardening.ps1' -Arguments @('-Profile',$Profile)}
   '4' {
    Write-Warning 'Changes may affect network access, services and scoring. Read README and create a VM snapshot.'
    if((Read-Host 'Type APPLY to proceed') -ceq 'APPLY') {Invoke-Local 'Start-Hardening.ps1' -Arguments @('-Profile',$Profile,'-Apply')}
   }
   '5' {Invoke-Local 'Test-Compliance.ps1' -Arguments @('-Profile',$Profile)}
   '6' {Invoke-Local 'Modules\Manage-LocalAccounts.ps1' -Arguments @('-Action','List')}
   '7' {
    Write-Host 'Actions: RemoveUsers, RemoveAdmins, RemoveBackupOperators, ResetPassword, SetPasswordExpiration'
    $a=Read-Host 'Action';Invoke-Local 'Modules\Manage-LocalAccounts.ps1' -Arguments @('-Action',$a)
   }
   '8' {Invoke-Local 'Modules\Review-DefenderExclusions.ps1'}
   '9' {Invoke-Local 'Modules\Set-RdpHighEncryption.ps1'}
   '0' {return}
   default {Write-Host 'Choose 0-9'}
  }
 } catch {Write-Warning "Operation failed: $($_.Exception.Message)"}
}
