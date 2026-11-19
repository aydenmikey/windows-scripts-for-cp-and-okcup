# Windows Security Toolkit v2

Defensive, reusable PowerShell 5.1 toolkit for Windows 11 and Windows Server 2022 training VMs and CyberPatriot / Oklahoma Cup-style images. **No guarantee of a perfect score.**

## Quick start

1. Review the image's own README and take a VMware snapshot.
2. Extract this ZIP. Open **Windows PowerShell as Administrator**.
3. Run `cd "$env:USERPROFILE\Downloads\Windows-Security-Toolkit"` (adjust to your extract location).
4. Start the interactive menu: `powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Start-Toolkit.ps1 -Profile Windows11`
5. For Server 2022, change the profile to `Server2022`.

Running the launcher is safe until you explicitly select an apply/change operation. Individual commands:

```powershell
.\Start-Audit.ps1                         # read-only system audit
.\Modules\Inspect-Remaining.ps1          # read-only investigation
.\Modules\Inspect-Remaining.ps1 -Deep    # searches filenames more widely
.\Start-Hardening.ps1 -Profile Windows11  # preview
.\Start-Hardening.ps1 -Profile Windows11 -Apply # approved changes only
.\Test-Compliance.ps1 -Profile Windows11 # partial baseline verification
.\Modules\Manage-LocalAccounts.ps1 -Action List
.\Modules\Manage-LocalAccounts.ps1 -Action RemoveUsers -Names 'example1','example2'
.\Modules\Manage-LocalAccounts.ps1 -Action RemoveAdmins -Names 'example3'
.\Modules\Manage-LocalAccounts.ps1 -Action SetPasswordExpiration -Names 'example4'
.\Modules\Review-DefenderExclusions.ps1
.\Modules\Review-DefenderExclusions.ps1 -Path 'C:\ProgramData\Example' -Remove
.\Modules\Set-RdpHighEncryption.ps1         # preview
.\Modules\Set-RdpHighEncryption.ps1 -Apply  # opt-in, compatibility check required
```

## Important safeguards

- No blanket deletion of users, files, Python installations, or services. Review the competition README first.
- No bulk setting the same password for every account. Password reset prompts securely, one account at a time.
- Account-management actions require **CONFIRM**, and skip built-in/current user accounts.
- Baseline `-Apply` creates a policy export and change log in `Backups/`; **a VM snapshot remains necessary for complete rollback**.
- **Password complexity is intentionally not changed** by the baseline. Decide separately when you are ready.
- The Defender exclusion tool only removes an exact user-specified path after confirmation.
- Don't commit `Backups/`, `Reports/`, secrets, or image-specific forensic evidence to GitHub.
- Read-only checks can reveal sensitive file paths or system configuration: treat reports as private.
- This toolkit must be tested in a VM before production use. Some settings may be overwritten by Group Policy.

## Scoring context

`Docs/Windows11-Score-2026-11-19.md` records the latest Windows 11 screenshot: **44 points, 13/25 flaws**. See `Docs/Scoring-Coverage.md` for the Windows 11 and Server 2022 flaw categories. Windows build upgrades, forensic answers, third-party app updates, web server configuration, and malware investigation are intentionally manual.

## Notes

- The original `Start-Audit.ps1` supplied by the user remains available unchanged.
- The baseline applies a conservative policy profile and provides audit logs but cannot determine whether an account or service is authorized without the scenario instructions.
- The compliance script tests only a subset of checks, not official score state.
