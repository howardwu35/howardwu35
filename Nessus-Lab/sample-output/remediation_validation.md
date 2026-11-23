# Remediation Validation Report

**Baseline scan:** 2026-11-16  
**Validation rescan:** 2026-11-23

## Summary

| Severity | Baseline | Rescan | Remediated | Persisting | New |
|---|---:|---:|---:|---:|---:|
| Critical | 6 | 2 | 4 | 2 | 0 |
| High | 3 | 2 | 1 | 2 | 0 |
| Medium | 5 | 4 | 2 | 3 | 1 |
| Low | 0 | 0 | 0 | 0 | 0 |

**Risk reduction:** 7 of 14 findings closed (50%). Aggregate risk score 110.5 → 58.7.

## Remediated (close POA&M items)

| Severity | Host | Port | Plugin | Finding | Status |
|---|---|---|---|---|---|
| Critical | 192.168.56.101 | 6667/tcp | 46882 | UnrealIRCd Backdoor Detection | Closed |
| Critical | 192.168.56.101 | 5900/tcp | 61708 | VNC Server 'password' Password | Closed |
| Critical | 192.168.56.102 | 445/tcp | 97833 | MS17-010: Security Update for Microsoft Windows SMB Server (4013389) (ETERNALBLUE) (ETERNALCHAMPION) (ETERNALROMANCE) (ETERNALSYNERGY) (WannaCry) (EternalRocks) (Petya) (uncredentialed check) | Closed |
| Critical | 192.168.56.101 | 21/tcp | 55523 | vsftpd Smiley Face Backdoor | Closed |
| High | 192.168.56.101 | 512/tcp | 10203 | rexecd Service Detection | Closed |
| Medium | 192.168.56.102 | 445/tcp | 57608 | SMB Signing not required | Closed |
| Medium | 192.168.56.101 | 80/tcp | 11213 | HTTP TRACE / TRACK Methods Allowed | Closed |

## Persisting (remediation failed or pending)

| Severity | Host | Port | Plugin | Finding | Status |
|---|---|---|---|---|---|
| Critical | 192.168.56.101 | 1524/tcp | 51988 | Bind Shell Backdoor Detection | Open |
| High | 192.168.56.101 | 25/tcp | 20007 | SSL Version 2 and 3 Protocol Detection | Open |
| High | 192.168.56.101 | 2049/udp | 42256 | NFS Shares World Readable | Open |
| Medium | 192.168.56.101 | 445/tcp | 90509 | Samba Badlock Vulnerability | Open |
| Medium | 192.168.56.101 | 5432/tcp | 57582 | SSL Self-Signed Certificate | Open |
| Critical | 192.168.56.101 | 22/tcp | 32314 | Debian OpenSSH/OpenSSL Package Random Number Generator Weakness | Open |
| Medium | 192.168.56.102 | 3389/tcp | 58453 | Terminal Services Doesn't Use Network Level Authentication (NLA) Only | Open |

## Newly introduced

| Severity | Host | Port | Plugin | Finding | Status |
|---|---|---|---|---|---|
| Medium | 192.168.56.102 | 3389/tcp | 57690 | Terminal Services Encryption Level is Medium or Low | New |
