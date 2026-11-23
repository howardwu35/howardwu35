# 05 · Remediation & Validation

Remediation is not done until a **rescan proves it**: POA&M item → change → validation scan → close or escalate.

## Windows Remediation Playbook
Work from your POA&M, highest contextual risk first. Run PowerShell as administrator.

| Finding type | Remediation | Verify |
|---|---|---|
| Missing Windows cumulative / security updates | Resume Windows Update, install all, reboot | `Get-HotFix \| Sort InstalledOn -Desc \| Select -First 5` |
| Outdated third-party apps (7-Zip, VLC, browsers, Java…) | Update to current version or uninstall if not needed | Version in *Apps & features* |
| SMBv1 enabled | `Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol` (reboot) | `Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol` |
| SMB signing not required | `Set-SmbServerConfiguration -RequireSecuritySignature $true -Force` | `Get-SmbServerConfiguration \| Select RequireSecuritySignature` |
| RDP without NLA | *System → Remote Desktop → Require Network Level Authentication* | Plugin 58453 no longer fires |
| RDP not needed at all | Disable Remote Desktop | Port 3389 closed |

📸 `screenshots/12-remediation-commands.png`: PowerShell fixes
📸 `screenshots/13-windows-update-complete.png`: updates installed

> In production every change goes through change management: ticket, approval, maintenance window, rollback plan. Log yours below as if it were a change record.

## Change Log
| Date | POA&M ID | Change made | Result |
|---|---|---|---|
| | | | |

## Validation Rescan
1. Re-run the **same credentialed policy** against the same IP. Same policy, same scope, or the comparison isn't valid.
2. Export to `scans/rescan-credentialed.nessus`.
3. Generate the validation report:
   ```bash
   python3 scripts/nessus_report.py diff scans/baseline-credentialed.nessus \
       scans/rescan-credentialed.nessus -o reports/validation \
       --assets assets.example.csv --kev known_exploited_vulnerabilities.csv
   ```
4. Update POA&M status. **Remediated** → *Closed* with the rescan date as evidence. **Persisting** → investigate (failed patch? pending reboot?). **New** → triage as new items.

📸 `screenshots/14-rescan-summary.png`: rescan severity breakdown

## Results
> Paste the summary table from `reports/validation/remediation_validation.md` and state the % reduction in Critical/High findings.

---

## Optional: Metasploitable 2
*Instructions for extending the lab. Not part of the documented results.* Verify each on your system.

| Finding | Remediation | Verify |
|---|---|---|
| Bind shell on 1524 (ingreslock) | Comment out `ingreslock` in `/etc/inetd.conf`, restart inetd | `sudo netstat -tlnp \| grep 1524` empty |
| rexec / rlogin / rsh (512–514), telnet | Comment out `exec`, `login`, `shell`, `telnet` in `/etc/inetd.conf`, restart inetd | `nmap -p23,512-514 <ip>` |
| UnrealIRCd backdoor (6667) | Find process (`sudo netstat -tlnp \| grep 6667`), stop it and disable its startup | port closed |
| VNC weak password (5900) | `vncpasswd` with a strong password, or disable VNC | plugin no longer fires |
| NFS world-readable | Restrict `/etc/exports`, `sudo exportfs -ra` | `showmount -e <ip>` |
