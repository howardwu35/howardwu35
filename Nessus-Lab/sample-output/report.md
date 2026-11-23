# SAMPLE Vulnerability Assessment Report (Synthetic Data)

**Scan date:** 2026-11-16  
**Hosts assessed:** 2  
**Findings (Low+):** 14 across 14 unique weaknesses  
**Generated:** 2026-11-23 by `nessus_report.py`

## 1. Executive Summary

The assessment identified **11 Critical/High contextual-risk findings**. **5** High/Critical findings have a publicly available exploit, and **2** map to CVEs on the CISA Known Exploited Vulnerabilities catalog. The highest aggregate risk is concentrated on **192.168.56.101**. Recommended priority: remediate exploitable Critical findings first, then High findings within SLA, and validate every fix with a credentialed rescan.

### Severity distribution (Nessus severity vs. contextual risk)

| Level | Nessus severity | Contextual risk | Remediation SLA |
|---|---:|---:|---|
| Critical | 6 | 4 | 15 days |
| High | 3 | 7 | 30 days |
| Medium | 5 | 3 | 90 days |
| Low | 0 | 0 | 180 days |

### Risk by host

| Host | OS | Criticality | Credentialed | Crit | High | Med | Low | Aggregate risk |
|---|---|---|---|---:|---:|---:|---:|---:|
| 192.168.56.101 (metasploitable.lab.local) | Linux Kernel 2.6 on Ubuntu 8.04 (hardy) | High | No | 3 | 7 | 1 | 0 | 91.2 |
| 192.168.56.102 (win10-lab.lab.local) | Microsoft Windows 10 Enterprise Evaluati | Medium | No | 1 | 0 | 2 | 0 | 19.3 |

## 2. Top 10 Prioritized Findings

| # | Risk | Score | CVSSv3 | Host | Port | Finding | Exploit | KEV |
|---:|---|---:|---:|---|---|---|---|---|
| 1 | Critical | 10.0 | 9.8 | 192.168.56.101 | 6667/tcp | UnrealIRCd Backdoor Detection | Yes | Yes |
| 2 | Critical | 10.0 | 9.8 | 192.168.56.101 | 1524/tcp | Bind Shell Backdoor Detection | Yes | No |
| 3 | Critical | 10.0 | 10.0 | 192.168.56.101 | 5900/tcp | VNC Server 'password' Password | No | No |
| 4 | Critical | 10.0 | 8.1 | 192.168.56.102 | 445/tcp | MS17-010: Security Update for Microsoft Windows SMB Server (4013389) (ETERNALBLUE) (ETERNALCHAMPION) (ETERNALROMANCE) (ETERNALSYNERGY) (WannaCry) (EternalRocks) (Petya) (uncredentialed check) | Yes | Yes |
| 5 | High | 8.9 | 9.8 | 192.168.56.101 | 21/tcp | vsftpd Smiley Face Backdoor | Yes | No |
| 6 | High | 8.5 | 7.5 | 192.168.56.101 | 512/tcp | rexecd Service Detection | No | No |
| 7 | High | 8.5 | 7.5 | 192.168.56.101 | 25/tcp | SSL Version 2 and 3 Protocol Detection | No | No |
| 8 | High | 8.5 | 7.5 | 192.168.56.101 | 2049/udp | NFS Shares World Readable | No | No |
| 9 | High | 7.7 | 5.9 | 192.168.56.101 | 445/tcp | Samba Badlock Vulnerability | No | No |
| 10 | High | 7.5 | 6.5 | 192.168.56.101 | 5432/tcp | SSL Self-Signed Certificate | No | No |

## 3. Detailed Findings (Critical & High)

### 3.1 UnrealIRCd Backdoor Detection

- **Contextual risk:** Critical (10.0) | **Nessus severity:** Critical | **CVSSv3:** 9.8 | **VPR:** 7.4
- **Plugin ID:** 46882 (Backdoors)
- **CVE(s):** CVE-2010-2075
- **Affected:** 192.168.56.101:6667/tcp
- **Exploitability:** Public exploit available (Metasploit); **listed in CISA KEV**
- **NIST 800-53 controls:** SI-3, SI-4, CM-7

**Synopsis.** SYNTHETIC TEST DATA - UnrealIRCd Backdoor Detection detected.

**Remediation.** Re-download the software, verify it using the published MD5 / SHA1 checksums, and re-install it.

**Evidence (plugin output):**

```
SYNTHETIC: example plugin output for 46882 on port 6667/tcp
```

### 3.2 Bind Shell Backdoor Detection

- **Contextual risk:** Critical (10.0) | **Nessus severity:** Critical | **CVSSv3:** 9.8 | **VPR:** n/a
- **Plugin ID:** 51988 (Backdoors)
- **Affected:** 192.168.56.101:1524/tcp
- **Exploitability:** Public exploit available (Metasploit)
- **NIST 800-53 controls:** SI-3, SI-4, CM-7

**Synopsis.** SYNTHETIC TEST DATA - Bind Shell Backdoor Detection detected.

**Remediation.** Verify if the remote host has been compromised, and reinstall the system if necessary.

**Evidence (plugin output):**

```
SYNTHETIC: example plugin output for 51988 on port 1524/tcp
```

### 3.3 VNC Server 'password' Password

- **Contextual risk:** Critical (10.0) | **Nessus severity:** Critical | **CVSSv3:** 10.0 | **VPR:** n/a
- **Plugin ID:** 61708 (Gain a shell remotely)
- **Affected:** 192.168.56.101:5900/tcp
- **Exploitability:** No public exploit known
- **NIST 800-53 controls:** IA-5, AC-2

**Synopsis.** SYNTHETIC TEST DATA - VNC Server 'password' Password detected.

**Remediation.** Secure the VNC service with a strong password.

**Evidence (plugin output):**

```
SYNTHETIC: example plugin output for 61708 on port 5900/tcp
```

### 3.4 MS17-010: Security Update for Microsoft Windows SMB Server (4013389) (ETERNALBLUE) (ETERNALCHAMPION) (ETERNALROMANCE) (ETERNALSYNERGY) (WannaCry) (EternalRocks) (Petya) (uncredentialed check)

- **Contextual risk:** Critical (10.0) | **Nessus severity:** Critical | **CVSSv3:** 8.1 | **VPR:** 9.7
- **Plugin ID:** 97833 (Windows)
- **CVE(s):** CVE-2017-0143, CVE-2017-0144, CVE-2017-0145, CVE-2017-0146, CVE-2017-0147, CVE-2017-0148
- **Affected:** 192.168.56.102:445/tcp
- **Exploitability:** Public exploit available (Metasploit); **listed in CISA KEV**
- **NIST 800-53 controls:** SI-2, RA-5

**Synopsis.** SYNTHETIC TEST DATA - MS17-010: Security Update for Microsoft Windows SMB Server (4013389) (ETERNALBLUE) (ETERNALCHAMPION) (ETERNALROMANCE) (ETERNALSYNERGY) (WannaCry) (EternalRocks) (Petya) (uncredentialed check) detected.

**Remediation.** Apply MS17-010. Disable SMBv1 and block TCP 445 at the network perimeter.

**Evidence (plugin output):**

```
SYNTHETIC: example plugin output for 97833 on port 445/tcp
```

### 3.5 vsftpd Smiley Face Backdoor

- **Contextual risk:** High (8.9) | **Nessus severity:** Critical | **CVSSv3:** 9.8 | **VPR:** 7.4
- **Plugin ID:** 55523 (FTP)
- **CVE(s):** CVE-2011-2523
- **Affected:** 192.168.56.101:21/tcp
- **Exploitability:** Public exploit available (Metasploit)
- **NIST 800-53 controls:** SI-3, SI-4, CM-7

**Synopsis.** SYNTHETIC TEST DATA - vsftpd Smiley Face Backdoor detected.

**Remediation.** Validate and recompile a legitimate copy of the source code.

**Evidence (plugin output):**

```
SYNTHETIC: example plugin output for 55523 on port 21/tcp
```

### 3.6 rexecd Service Detection

- **Contextual risk:** High (8.5) | **Nessus severity:** High | **CVSSv3:** 7.5 | **VPR:** n/a
- **Plugin ID:** 10203 (Service detection)
- **CVE(s):** CVE-1999-0618
- **Affected:** 192.168.56.101:512/tcp
- **Exploitability:** No public exploit known
- **NIST 800-53 controls:** CM-7, CM-6

**Synopsis.** SYNTHETIC TEST DATA - rexecd Service Detection detected.

**Remediation.** Comment out the 'exec' line in /etc/inetd.conf and restart the inetd process.

**Evidence (plugin output):**

```
SYNTHETIC: example plugin output for 10203 on port 512/tcp
```

### 3.7 SSL Version 2 and 3 Protocol Detection

- **Contextual risk:** High (8.5) | **Nessus severity:** High | **CVSSv3:** 7.5 | **VPR:** n/a
- **Plugin ID:** 20007 (Service detection)
- **Affected:** 192.168.56.101:25/tcp
- **Exploitability:** No public exploit known
- **NIST 800-53 controls:** SC-8, SC-13, SC-23

**Synopsis.** SYNTHETIC TEST DATA - SSL Version 2 and 3 Protocol Detection detected.

**Remediation.** Consult the application's documentation to disable SSL 2.0 and 3.0. Use TLS 1.2 or later.

**Evidence (plugin output):**

```
SYNTHETIC: example plugin output for 20007 on port 25/tcp
```

### 3.8 NFS Shares World Readable

- **Contextual risk:** High (8.5) | **Nessus severity:** High | **CVSSv3:** 7.5 | **VPR:** n/a
- **Plugin ID:** 42256 (RPC)
- **Affected:** 192.168.56.101:2049/udp
- **Exploitability:** No public exploit known
- **NIST 800-53 controls:** CM-7, CM-6

**Synopsis.** SYNTHETIC TEST DATA - NFS Shares World Readable detected.

**Remediation.** Place the appropriate restrictions on all NFS shares.

**Evidence (plugin output):**

```
SYNTHETIC: example plugin output for 42256 on port 2049/udp
```

### 3.9 Samba Badlock Vulnerability

- **Contextual risk:** High (7.7) | **Nessus severity:** Medium | **CVSSv3:** 5.9 | **VPR:** 6.7
- **Plugin ID:** 90509 (General)
- **CVE(s):** CVE-2016-2118
- **Affected:** 192.168.56.101:445/tcp
- **Exploitability:** No public exploit known
- **NIST 800-53 controls:** CM-6, SI-2

**Synopsis.** SYNTHETIC TEST DATA - Samba Badlock Vulnerability detected.

**Remediation.** Upgrade to Samba version 4.2.11 / 4.3.8 / 4.4.2 or later.

**Evidence (plugin output):**

```
SYNTHETIC: example plugin output for 90509 on port 445/tcp
```

### 3.10 SSL Self-Signed Certificate

- **Contextual risk:** High (7.5) | **Nessus severity:** Medium | **CVSSv3:** 6.5 | **VPR:** n/a
- **Plugin ID:** 57582 (General)
- **Affected:** 192.168.56.101:5432/tcp
- **Exploitability:** No public exploit known
- **NIST 800-53 controls:** SC-8, SC-13, SC-23

**Synopsis.** SYNTHETIC TEST DATA - SSL Self-Signed Certificate detected.

**Remediation.** Purchase or generate a proper SSL certificate for this service.

**Evidence (plugin output):**

```
SYNTHETIC: example plugin output for 57582 on port 5432/tcp
```

### 3.11 Debian OpenSSH/OpenSSL Package Random Number Generator Weakness

- **Contextual risk:** High (6.6) | **Nessus severity:** Critical | **CVSSv3:** 9.8 | **VPR:** 5.1
- **Plugin ID:** 32314 (Gain a shell remotely)
- **CVE(s):** CVE-2008-0166
- **Affected:** 192.168.56.101:22/tcp
- **Exploitability:** Public exploit available (Metasploit)
- **NIST 800-53 controls:** SC-8, SC-13, SC-23

**Synopsis.** SYNTHETIC TEST DATA - Debian OpenSSH/OpenSSL Package Random Number Generator Weakness detected.

**Remediation.** Consider all cryptographic material generated on the remote host to be guessable. Regenerate all SSH, SSL and OpenVPN key material.

**Evidence (plugin output):**

```
SYNTHETIC: example plugin output for 32314 on port 22/tcp
```

## 4. Methodology & Scoring

Contextual risk = best available technical score (VPR → CVSSv3 → CVSSv2) + asset context (+1.0 High / 0 Medium / −1.0 Low criticality) + threat context (+0.5 public exploit, +1.5 CISA KEV), bounded 0–10. Ratings: ≥9 Critical, ≥7 High, ≥4 Medium, >0 Low. Guardrail: context may move a rating at most one level from the Nessus severity, except KEV findings, which are never below High. Informational plugins are excluded from counts.
