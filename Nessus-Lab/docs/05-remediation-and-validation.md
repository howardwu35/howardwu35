# 05 · Remediation & Validation

Remediation is not done until a **rescan proves it**. This closes the loop: POA&M item → change → validation scan → close or escalate.

## Remediation Playbook (lab targets)
Fix the top-priority items from your POA&M. Commands are starting points: **verify on your system**, and record what you actually ran.

### Metasploitable 2 (192.168.56.101)
| Finding | Remediation | Verify |
|---|---|---|
| Bind shell on 1524 (ingreslock) | Comment out the `ingreslock` line in `/etc/inetd.conf`, restart inetd | `sudo netstat -tlnp \| grep 1524` returns nothing |
| rexec / rlogin / rsh (512–514) | Comment out `exec`, `login`, `shell` in `/etc/inetd.conf`, restart inetd | `nmap -p512-514 192.168.56.101` |
| UnrealIRCd backdoor (6667) | Identify process (`sudo netstat -tlnp \| grep 6667`), stop it and disable its startup | port closed |
| VNC weak password (5900) | Set a strong password with `vncpasswd`, or disable VNC | Nessus plugin no longer fires |
| NFS world-readable | Restrict `/etc/exports` to specific hosts / `ro,root_squash`, then `sudo exportfs -ra` | `showmount -e 192.168.56.101` |
| Telnet (23) | Disable `telnet` in inetd; use SSH | port closed |

### Windows Eval (192.168.56.102)
| Finding | Remediation (PowerShell as admin) |
|---|---|
| Missing cumulative updates / MS17-010 | Resume Windows Update and install all updates; reboot |
| SMBv1 enabled | `Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol` |
| SMB signing not required | `Set-SmbServerConfiguration -RequireSecuritySignature $true -Force` |
| RDP without NLA | System Properties → Remote → *Allow connections only from computers running Remote Desktop with Network Level Authentication* |

> In production, each change goes through change management (ticket, approval, maintenance window, rollback plan). Log yours in the table below as if it were a change record.

## Change Log
| Date | POA&M ID | Host | Change made | Result |
|---|---|---|---|---|
| | | | | |

## Validation Rescan
1. Re-run the **same credentialed policy** against the same IPs. Policy consistency matters, or the diff isn't apples to apples.
2. Export to `scans/rescan-credentialed.nessus`.
3. Generate the validation report:
   ```bash
   python3 scripts/nessus_report.py diff scans/baseline-credentialed.nessus \
       scans/rescan-credentialed.nessus -o reports/validation \
       --assets assets.example.csv --kev known_exploited_vulnerabilities.csv
   ```
4. Update POA&M status: **Remediated** findings → *Closed* (with rescan date as evidence). **Persisting** findings → investigate (fix failed? reboot pending?). **New** findings → triage as new POA&M items. Patching can introduce or reveal new issues.

## Results
> Paste the summary table from `reports/validation/remediation_validation.md` here and state the % reduction in Critical/High findings.
