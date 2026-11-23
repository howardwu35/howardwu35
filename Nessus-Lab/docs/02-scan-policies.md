# 02 · Scan Policies

I used three scan configurations, mirroring how an enterprise program layers discovery, unauthenticated, and authenticated assessment.

| # | Template | Purpose | Credentials |
|---|---|---|---|
| 1 | **Host Discovery** | Confirm live hosts / build inventory (validate asset list) | None |
| 2 | **Basic Network Scan, uncredentialed** | Attacker's-eye view: exposed services, network-reachable vulns | None |
| 3 | **Basic Network Scan, credentialed** | Patch-level and configuration view: missing updates, local vulns | SSH (Linux), SMB/Windows (Windows) |

## Policy 1: Host Discovery
- *New Scan → Host Discovery*, Targets: `192.168.56.0/24`
- Discovery type: *Port scan (common ports)*
- Output: live host list; reconcile with `assets.example.csv`. **Unknown hosts are a finding** (CM-8, System Component Inventory).

## Policy 2: Basic Network Scan (uncredentialed)
- Targets: `192.168.56.101, 192.168.56.102`
- *Discovery → Port Scanning*: consider **All ports (1-65535)**. Metasploitable has services on high ports (e.g. 1524, 6667) that a default port list may miss.
- *Assessment*: default
- Name: `LAB-Baseline-Uncredentialed-YYYYMMDD`

## Policy 3: Basic Network Scan (credentialed)
Same settings as Policy 2, plus *Credentials*:

**SSH (Metasploitable)**
- Authentication method: password, Username `msfadmin`
- Elevate privileges with: `sudo` (password `msfadmin`)

**Windows (Win Eval)**
- Authentication method: Password, Username `labadmin`, Domain blank (local account)

Name: `LAB-Baseline-Credentialed-YYYYMMDD`

### Verifying credentials actually worked
A "credentialed" scan whose login failed silently becomes an uncredentialed scan. Check these plugin results:

| Plugin | Meaning |
|---|---|
| 19506 *Nessus Scan Information* | Output shows `Credentialed checks : yes` |
| 141118 *Target Credential Status by Authentication Protocol - Valid Credentials Provided* | Login succeeded |
| 21745 *OS Security Patch Assessment Failed* / 104410 *Target Credential Status by Authentication Protocol - Failure for Provided Credentials* | Login or privilege problem: fix before trusting results |

> Plugin IDs can change between feeds. Search the plugin name in the scan results if an ID doesn't match.

## Compliance Scanning (note)
Configuration audits against **CIS Benchmarks** or **DISA STIGs** (*Policy Compliance Auditing* templates and `.audit` files) are **not available in Nessus Essentials**. They require Nessus Professional/Expert or Tenable Security Center. In DoD environments this is done through **ACAS** (Tenable Security Center + Nessus) together with **DISA STIG / SCAP** benchmarks. Free alternative for practice: DISA **SCAP Compliance Checker (SCC)** + **STIG Viewer** on the Windows VM.

## Evidence to Capture
- [ ] Screenshot of each policy's settings (Discovery + Credentials tabs)
- [ ] Plugin 19506 output showing `Credentialed checks : yes`
