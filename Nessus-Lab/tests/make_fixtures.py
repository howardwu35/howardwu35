#!/usr/bin/env python3
"""
Generates SYNTHETIC .nessus fixtures used only to test nessus_report.py.

These files are NOT real scan results. They are modeled on findings commonly
reported against intentionally vulnerable lab targets (Metasploitable 2 and an
unpatched Windows host) so the parser and report logic can be tested without a
Nessus license. Real lab results live in ../scans/ and ../reports/.
"""
import os
from xml.sax.saxutils import escape

HERE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")

HOSTS = {
    "192.168.56.101": {
        "os": "Linux Kernel 2.6 on Ubuntu 8.04 (hardy)", "fqdn": "metasploitable.lab.local",
        "items": [
            # port, proto, svc, pid, name, family, sev, cvss3, vpr, cves, exploit, solution
            ("1524", "tcp", "wild_shell", "51988", "Bind Shell Backdoor Detection", "Backdoors", 4, 9.8, None, [], True,
             "Verify if the remote host has been compromised, and reinstall the system if necessary."),
            ("6667", "tcp", "irc", "46882", "UnrealIRCd Backdoor Detection", "Backdoors", 4, 9.8, 7.4, ["CVE-2010-2075"], True,
             "Re-download the software, verify it using the published MD5 / SHA1 checksums, and re-install it."),
            ("21", "tcp", "ftp", "55523", "vsftpd Smiley Face Backdoor", "FTP", 4, 9.8, 7.4, ["CVE-2011-2523"], True,
             "Validate and recompile a legitimate copy of the source code."),
            ("22", "tcp", "ssh", "32314", "Debian OpenSSH/OpenSSL Package Random Number Generator Weakness", "Gain a shell remotely", 4, 9.8, 5.1, ["CVE-2008-0166"], True,
             "Consider all cryptographic material generated on the remote host to be guessable. Regenerate all SSH, SSL and OpenVPN key material."),
            ("5900", "tcp", "vnc", "61708", "VNC Server 'password' Password", "Gain a shell remotely", 4, 10.0, None, [], False,
             "Secure the VNC service with a strong password."),
            ("2049", "udp", "rpc-nfs", "42256", "NFS Shares World Readable", "RPC", 3, 7.5, None, [], False,
             "Place the appropriate restrictions on all NFS shares."),
            ("512", "tcp", "rexecd", "10203", "rexecd Service Detection", "Service detection", 3, 7.5, None, ["CVE-1999-0618"], False,
             "Comment out the 'exec' line in /etc/inetd.conf and restart the inetd process."),
            ("445", "tcp", "cifs", "90509", "Samba Badlock Vulnerability", "General", 2, 5.9, 6.7, ["CVE-2016-2118"], False,
             "Upgrade to Samba version 4.2.11 / 4.3.8 / 4.4.2 or later."),
            ("25", "tcp", "smtp", "20007", "SSL Version 2 and 3 Protocol Detection", "Service detection", 3, 7.5, None, [], False,
             "Consult the application's documentation to disable SSL 2.0 and 3.0. Use TLS 1.2 or later."),
            ("80", "tcp", "www", "11213", "HTTP TRACE / TRACK Methods Allowed", "Web Servers", 2, 5.3, 4.0, ["CVE-2003-1567", "CVE-2004-2320"], False,
             "Disable these HTTP methods."),
            ("5432", "tcp", "postgresql", "57582", "SSL Self-Signed Certificate", "General", 2, 6.5, None, [], False,
             "Purchase or generate a proper SSL certificate for this service."),
        ],
    },
    "192.168.56.102": {
        "os": "Microsoft Windows 10 Enterprise Evaluation Build 14393", "fqdn": "win10-lab.lab.local",
        "items": [
            ("445", "tcp", "cifs", "97833", "MS17-010: Security Update for Microsoft Windows SMB Server (4013389) (ETERNALBLUE) (ETERNALCHAMPION) (ETERNALROMANCE) (ETERNALSYNERGY) (WannaCry) (EternalRocks) (Petya) (uncredentialed check)", "Windows", 4, 8.1, 9.7,
             ["CVE-2017-0143", "CVE-2017-0144", "CVE-2017-0145", "CVE-2017-0146", "CVE-2017-0147", "CVE-2017-0148"], True,
             "Apply MS17-010. Disable SMBv1 and block TCP 445 at the network perimeter."),
            ("445", "tcp", "cifs", "57608", "SMB Signing not required", "Misc.", 2, 5.3, None, [], False,
             "Enforce message signing in the host's configuration (GPO: 'Microsoft network server: Digitally sign communications (always)')."),
            ("3389", "tcp", "msrdp", "58453", "Terminal Services Doesn't Use Network Level Authentication (NLA) Only", "Misc.", 2, 4.0, None, [], False,
             "Enable Network Level Authentication (NLA) on the remote RDP server."),
        ],
    },
}

# Plugins remediated between baseline and rescan (simulated fixes)
FIXED = {("192.168.56.101", "46882"), ("192.168.56.101", "55523"), ("192.168.56.101", "61708"),
         ("192.168.56.101", "10203"), ("192.168.56.101", "11213"), ("192.168.56.102", "97833"),
         ("192.168.56.102", "57608")}
# New finding appearing on rescan
NEW = {"192.168.56.102": [("3389", "tcp", "msrdp", "57690", "Terminal Services Encryption Level is Medium or Low", "Misc.", 2, 5.9, None, [], False,
                           "Change RDP encryption level to High or FIPS-Compliant.")]}


def item_xml(it):
    port, proto, svc, pid, name, fam, sev, c3, vpr, cves, exp, sol = it
    risk = {4: "Critical", 3: "High", 2: "Medium", 1: "Low", 0: "None"}[sev]
    x = [f'<ReportItem port="{port}" svc_name="{svc}" protocol="{proto}" severity="{sev}" pluginID="{pid}" pluginName="{escape(name, {chr(34): "&quot;"})}" pluginFamily="{escape(fam)}">',
         f"<risk_factor>{risk}</risk_factor>",
         f"<synopsis>SYNTHETIC TEST DATA - {escape(name)} detected.</synopsis>",
         f"<description>SYNTHETIC TEST DATA. Example description for {escape(name)}.</description>",
         f"<solution>{escape(sol)}</solution>",
         f"<cvss3_base_score>{c3}</cvss3_base_score>"]
    if vpr is not None:
        x.append(f"<vpr_score>{vpr}</vpr_score>")
    x += [f"<cve>{c}</cve>" for c in cves]
    x.append(f"<exploit_available>{'true' if exp else 'false'}</exploit_available>")
    if exp:
        x.append("<exploit_framework_metasploit>true</exploit_framework_metasploit>")
    x.append(f"<plugin_output>SYNTHETIC: example plugin output for {pid} on port {port}/{proto}</plugin_output>")
    x.append("</ReportItem>")
    return "\n".join(x)


def build(name, start, rescan=False):
    out = ['<?xml version="1.0" ?>', "<!-- SYNTHETIC TEST FIXTURE - NOT A REAL SCAN -->", "<NessusClientData_v2>",
           f'<Report name="{name}">']
    for ip, h in HOSTS.items():
        items = [i for i in h["items"] if not (rescan and (ip, i[3]) in FIXED)]
        if rescan:
            items += NEW.get(ip, [])
        out += [f'<ReportHost name="{ip}"><HostProperties>',
                f'<tag name="HOST_START">{start}</tag>', f'<tag name="host-ip">{ip}</tag>',
                f'<tag name="host-fqdn">{h["fqdn"]}</tag>', f'<tag name="operating-system">{h["os"]}</tag>',
                '<tag name="Credentialed_Scan">false</tag>', "</HostProperties>",
                # one informational item to prove it is filtered
                f'<ReportItem port="0" svc_name="general" protocol="tcp" severity="0" pluginID="19506" pluginName="Nessus Scan Information" pluginFamily="Settings"><plugin_output>SYNTHETIC</plugin_output></ReportItem>']
        out += [item_xml(i) for i in items]
        out.append("</ReportHost>")
    out += ["</Report>", "</NessusClientData_v2>"]
    return "\n".join(out)


if __name__ == "__main__":
    os.makedirs(HERE, exist_ok=True)
    with open(os.path.join(HERE, "synthetic_baseline.nessus"), "w") as f:
        f.write(build("SYNTHETIC-Baseline", "Mon Nov 16 10:00:00 2026"))
    with open(os.path.join(HERE, "synthetic_rescan.nessus"), "w") as f:
        f.write(build("SYNTHETIC-Rescan", "Mon Nov 23 10:00:00 2026", rescan=True))
    with open(os.path.join(HERE, "synthetic_kev.csv"), "w") as f:
        f.write("cveID,vendorProject,product\nCVE-2017-0144,Microsoft,SMBv1\nCVE-2010-2075,UnrealIRCd,UnrealIRCd\n")
    print("fixtures written to", HERE)
