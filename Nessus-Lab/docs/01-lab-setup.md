# 01 · Lab Setup

The documented lab uses **one Windows VM** as the target, scanned by **Nessus Essentials**. Everything shown in screenshots in this repo comes from that setup. An optional Linux target (Metasploitable 2) is described at the end for anyone who wants more findings.

## Components
| Item | Notes |
|---|---|
| Hypervisor | VirtualBox 7.x or VMware Workstation Player (free) |
| Scanner | Nessus Essentials (free, up to 16 IPs), on the host OS or a Kali/Ubuntu VM (4–8 GB RAM) |
| Target | **Windows 10/11 VM** (Microsoft Evaluation Center ISOs work), 2 vCPU, 4 GB RAM |

## 1. Network
Put the Windows VM on a **Host-only** (VirtualBox) or **Host-only / custom VMnet** (VMware) network so the scanner can reach it and scans stay off your home LAN.

1. Create a host-only network (VirtualBox: *File → Tools → Network Manager*), e.g. `192.168.56.0/24`.
2. Windows VM: attach an adapter to the host-only network. A second NAT adapter is fine if you need Windows Update for the remediation phase.
3. Give the VM a static IP or DHCP reservation so it keeps the **same IP for the baseline and the rescan**. The diff tool matches findings on IP + plugin + port.
4. From the scanner, confirm reachability: `ping <windows-ip>` (allow ICMP in the Windows firewall if needed).

📸 `screenshots/01-vm-network-settings.png`: VM network adapter settings
📸 `screenshots/02-windows-ipconfig.png`: `ipconfig` on the Windows VM

## 2. Prepare the Windows Target
### Make it worth scanning (so there is something to find and fix)
A fully patched Windows 11 VM produces very few findings. To create realistic, fixable weaknesses:
- **Pause Windows Update** before the baseline scan.
- **Install a few outdated applications** (older versions of e.g. 7-Zip, VLC, Notepad++, Firefox, Java, or Adobe Reader). Credentialed scans detect vulnerable app versions. This is the most common real-world finding type.
- **Enable SMBv1** (*Turn Windows features on or off → SMB 1.0/CIFS File Sharing Support*).
- **Enable Remote Desktop** and untick *Require devices to use Network Level Authentication*.

Record what you changed. These become your POA&M items and your remediation change log.

### Enable credentialed scanning (local admin account)
1. Create a local admin account for scanning, e.g. `nessus-scan`. Don't reuse your personal account.
2. Set the network profile to **Private** and allow **File and Printer Sharing** in Windows Defender Firewall.
3. Start the **Remote Registry** service and set it to Automatic:
   ```powershell
   Set-Service RemoteRegistry -StartupType Automatic; Start-Service RemoteRegistry
   ```
4. Allow local admin accounts to use admin shares remotely (needed for non-domain local accounts):
   ```powershell
   reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
   ```
5. Test from the scanner (Linux): `smbclient -L //<windows-ip> -U nessus-scan`

📸 `screenshots/03-windows-scan-prep.png`: Remote Registry running / firewall rule

> These settings weaken the host and exist only for scanning. In an enterprise, a **domain service account** pushed by GPO is used instead, and the account is protected as a privileged credential (RA-5(5)).

## 3. Install Nessus Essentials
1. Register for an activation code at tenable.com → *Nessus Essentials*.
2. Install:
   - **Windows host:** run the `.msi` installer.
   - **Kali/Ubuntu:** `sudo dpkg -i Nessus-*.deb && sudo systemctl enable --now nessusd`
3. Browse to `https://localhost:8834` (or `https://<scanner-ip>:8834`), choose **Nessus Essentials**, enter the code, create the admin user.
4. Wait for plugins to download and compile (30–60+ minutes).
5. Note the Nessus version and plugin feed version (*Settings → About*) for your report.

📸 `screenshots/04-nessus-about.png`: version + plugin set (**blur the activation code**)

## 4. Snapshot
Snapshot the Windows VM as `baseline-vulnerable` before scanning, so you can repeat the cycle.

---

## Optional: Add a Linux Target (Metasploitable 2)
*Not part of the documented results. Instructions for anyone extending the lab.*

1. Download Metasploitable 2 (Rapid7, via SourceForge) and import the VMDK.
2. **Host-only adapter ONLY.** It is intentionally backdoored and must never reach the internet or your LAN.
3. Login `msfadmin` / `msfadmin`. Note its IP with `ifconfig`.
4. Add it to the scan targets and add **SSH credentials** (`msfadmin`, elevate with `sudo`) to the credentialed policy (see [02](02-scan-policies.md)).
5. Expect dozens of Critical/High findings (backdoored vsftpd and UnrealIRCd, bind shell on 1524, weak VNC password, rexec/rlogin, NFS exports). Remediation steps are in [05](05-remediation-and-validation.md#optional-metasploitable-2).
