# 01 · Lab Setup

## Hardware / Software
| Item | Notes |
|---|---|
| Hypervisor | VirtualBox 7.x or VMware Workstation Player (free) |
| Host RAM | 16 GB recommended (Nessus 4 GB + targets 1–4 GB each) |
| Scanner VM | Kali Linux or Ubuntu 22.04+, 2 vCPU, 4–8 GB RAM, 40 GB disk |
| Target 1 | **Metasploitable 2** (Rapid7, distributed via SourceForge), 512 MB–1 GB RAM |
| Target 2 | **Windows 10/11 Enterprise Evaluation** (Microsoft Evaluation Center, 90-day) |

## 1. Network Isolation (do this first)
Metasploitable is intentionally compromised-by-design. **It must never touch the internet or your home LAN.**

1. VirtualBox → *File → Tools → Network Manager → Host-only Networks* → create `vboxnet0`, `192.168.56.1/24`, DHCP enabled.
2. Metasploitable & Windows: **Adapter 1 = Host-only only.**
3. Scanner VM: Adapter 1 = NAT (for plugin updates), Adapter 2 = Host-only.
4. Verify from the scanner: `ip a` shows a `192.168.56.x` address; `ping 192.168.56.101` works.

| Host | IP (example) | Credentials |
|---|---|---|
| Scanner | 192.168.56.10 | your own |
| Metasploitable 2 | 192.168.56.101 | `msfadmin` / `msfadmin` |
| Windows Eval | 192.168.56.102 | local admin you create (e.g. `labadmin`) |

> Tip: set static IPs or DHCP reservations so IPs stay the same between baseline and rescan. The diff tool matches findings on IP + plugin + port.

## 2. Windows Target Prep
- During install, create a local admin account (`labadmin`).
- **Pause Windows Update** before the baseline scan so there are findings to remediate.
- For **credentialed** scanning (local account, not domain-joined):
  - Network profile: Private. Enable **File and Printer Sharing** through Windows Defender Firewall.
  - Start and set to Automatic: **Remote Registry** service.
  - Allow local admins to use admin shares remotely (UAC remote restrictions):
    ```powershell
    reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
    ```
  - Confirm from the scanner: `smbclient -L //192.168.56.102 -U labadmin`
- Optional (for more findings): enable SMBv1 (`Turn Windows features on or off → SMB 1.0/CIFS`) and RDP.

> Document every hardening change you make *for scanning* (Remote Registry, LocalAccountTokenFilterPolicy). In production these are change-controlled decisions, and in a real environment you would use a domain service account instead.

## 3. Install Nessus Essentials (scanner VM)
1. Register for an activation code: tenable.com → Nessus Essentials (free, up to 16 IPs).
2. Download the `.deb` for your distro, then:
   ```bash
   sudo dpkg -i Nessus-*-debian10_amd64.deb      # or the ubuntu package
   sudo systemctl enable --now nessusd
   ```
3. Browse to `https://<scanner-ip>:8834`, accept the self-signed cert, choose **Nessus Essentials**, enter the activation code, create the admin user.
4. Wait for plugins to download and compile (this can take 30–60+ minutes).
5. Record the Nessus version and plugin feed version in your report (*Settings → About*). Reports should always state which feed was used.

## 4. Snapshot Everything
Take a snapshot of each target named `baseline-vulnerable` **before** scanning. You can then repeat the remediate → rescan cycle and roll back.

## Evidence to Capture
- [ ] VirtualBox network settings showing Host-only on targets
- [ ] Nessus *About* page (version + plugin set)
- [ ] `ip a` on scanner showing host-only interface
