# 02 · Scan Policies

Three configurations, mirroring how an enterprise program layers discovery, unauthenticated, and authenticated assessment. All are available in **Nessus Essentials**.

| # | Template | Purpose | Credentials |
|---|---|---|---|
| 1 | **Host Discovery** | Confirm the target is live; validate the asset inventory | None |
| 2 | **Basic Network Scan, uncredentialed** | Attacker's-eye view: exposed services and network-reachable vulns | None |
| 3 | **Basic Network Scan, credentialed** | Patch and configuration view: missing updates, outdated apps, local settings | Windows (SMB) |

## Policy 1: Host Discovery
- *New Scan → Host Discovery*, Targets: your host-only subnet (e.g. `192.168.56.0/24`)
- Output: live host list. Reconcile with `assets.example.csv`. **Unknown hosts are a finding** (CM-8).

📸 `screenshots/05-host-discovery.png`

## Policy 2: Basic Network Scan (uncredentialed)
- Targets: `<windows-ip>`
- *Discovery → Port Scanning*: default is fine for Windows. Use **all ports** if adding Metasploitable.
- Name: `LAB-Win-Uncredentialed-YYYYMMDD`

## Policy 3: Basic Network Scan (credentialed)
Same as Policy 2, plus *Credentials → Host → Windows*:
- Authentication method: **Password**
- Username: `nessus-scan`, Password: ‹yours›, Domain: blank (local account)
- Name: `LAB-Win-Credentialed-YYYYMMDD`

📸 `screenshots/06-credential-config.png`: Credentials tab (**password field hidden**)

### Verify the credentials actually worked
A credentialed scan whose login failed silently is just an uncredentialed scan. Check:

| Plugin | What to look for |
|---|---|
| 19506 *Nessus Scan Information* | `Credentialed checks : yes` |
| 141118 *Target Credential Status by Authentication Protocol - Valid Credentials Provided* | Login succeeded |
| 104410 *…Failure for Provided Credentials* / 21745 *OS Security Patch Assessment Failed* | Fix before trusting results (see troubleshooting) |

📸 `screenshots/07-credentialed-checks-yes.png`: plugin 19506 output

> Plugin IDs can change between feeds. Search by name if an ID doesn't match.

### Troubleshooting failed Windows logins
| Symptom | Fix |
|---|---|
| Can't connect to 445 | Firewall: enable File and Printer Sharing (SMB-In); profile set to Private |
| Login OK but "local checks not run" | `LocalAccountTokenFilterPolicy = 1`; account is in Administrators |
| Registry access denied | Start the Remote Registry service |
| Microsoft account used | Use a *local* account. Microsoft-account logins often fail over SMB |

## Not available in Essentials: Compliance Scans
CIS/DISA STIG configuration audits (*Policy Compliance Auditing*, `.audit` files) need Nessus Professional/Expert or Tenable Security Center. In DoD, **ACAS** (Security Center + Nessus) runs these. Free alternative on the Windows VM: DISA **SCAP Compliance Checker (SCC)** + **STIG Viewer**.

---

### Optional: Metasploitable 2 credentials
Add *Credentials → Host → SSH*: password auth, user `msfadmin`, **Elevate privileges with: sudo** (password `msfadmin`), and add its IP to the targets.
