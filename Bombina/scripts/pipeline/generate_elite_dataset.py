#!/usr/bin/env python3
"""
Elite Dataset Generator - Reach 15,000+ samples
Focus: Deep reasoning, real-world scenarios, expert-level decision making
"""

import json
import random
from pathlib import Path

output_dir = Path(__file__).parent.parent / "data" / "generated" / "elite"
output_dir.mkdir(parents=True, exist_ok=True)

# =============================================================================
# 1. ADVANCED ATTACK CHAINS (500 samples)
# =============================================================================

attack_chains = []

chain_scenarios = [
    {
        "name": "Full AD Compromise",
        "steps": ["Initial foothold via phishing", "Local privilege escalation", "Credential harvesting", 
                  "Lateral movement to DC", "DCSync attack", "Golden ticket persistence"],
        "constraints": ["EDR present", "Network segmentation", "MFA on privileged accounts"],
        "detection_points": ["Email gateway", "Endpoint behavior", "LDAP anomalies", "Kerberos monitoring"]
    },
    {
        "name": "Cloud to On-Prem Pivot",
        "steps": ["Compromised cloud identity", "Azure AD Connect abuse", "On-prem hash sync exploitation",
                  "Service account compromise", "Domain escalation"],
        "constraints": ["Conditional access policies", "Cloud SIEM active", "Hybrid environment"],
        "detection_points": ["Azure sign-in logs", "Sync service monitoring", "Privileged access alerts"]
    },
    {
        "name": "Supply Chain Attack",
        "steps": ["Vendor portal compromise", "Software update poisoning", "Backdoor deployment",
                  "Internal network access", "Data exfiltration"],
        "constraints": ["Code signing required", "Network isolation", "Vendor trust relationships"],
        "detection_points": ["Binary integrity checks", "Outbound traffic analysis", "Vendor audit logs"]
    },
    {
        "name": "Web App to Internal Network",
        "steps": ["SQL injection discovery", "Database access", "Stored credential extraction",
                  "Internal service pivot", "Lateral movement"],
        "constraints": ["WAF deployed", "Database encryption", "Network segmentation"],
        "detection_points": ["WAF logs", "Database query analysis", "East-west traffic monitoring"]
    },
    {
        "name": "Insider Threat Simulation",
        "steps": ["Legitimate access abuse", "Privilege boundary testing", "Data staging",
                  "Exfiltration channel establishment", "Cover tracks"],
        "constraints": ["DLP controls", "Access logging", "Behavioral analytics"],
        "detection_points": ["UEBA alerts", "Data access patterns", "After-hours activity"]
    },
]

for i in range(500):
    scenario = random.choice(chain_scenarios)
    step_idx = random.randint(0, len(scenario["steps"]) - 2)
    current_step = scenario["steps"][step_idx]
    next_step = scenario["steps"][step_idx + 1]
    constraint = random.choice(scenario["constraints"])
    detection = random.choice(scenario["detection_points"])
    
    attack_chains.append({
        "instruction": f"You are executing a {scenario['name']} attack chain. Current phase: {current_step}",
        "input": f"Next objective: {next_step}. Constraint: {constraint}. Detection concern: {detection}",
        "output": f"""**Current Position**: {current_step} completed successfully.

**Next Phase Analysis**: {next_step}

**Constraint Impact**: {constraint} affects our approach:
- Must avoid triggering automated alerts
- Need to blend with legitimate traffic patterns
- Timing and volume considerations critical

**Detection Avoidance for {detection}**:
- Use slow, low-volume operations
- Leverage existing legitimate tools where possible
- Consider time-of-day patterns for normal activity

**Recommended Approach**:
1. Validate current access is stable before proceeding
2. Enumerate {next_step.lower()} opportunities quietly
3. Stage tools/scripts needed for the phase
4. Execute during peak business hours for cover
5. Verify success before moving to next phase

**Risk Assessment**: Medium-High
**Estimated Detection Probability**: 15-25% with proper OPSEC"""
    })

with open(output_dir / "attack_chains.jsonl", "w") as f:
    for sample in attack_chains:
        f.write(json.dumps(sample) + "\n")
print(f"Generated {len(attack_chains)} attack chain samples")

# =============================================================================
# 2. REAL-WORLD PENTEST SCENARIOS (800 samples)
# =============================================================================

pentest_scenarios = []

environments = [
    ("healthcare", "HIPAA compliance", "medical devices", "PHI access"),
    ("financial", "PCI-DSS", "trading systems", "customer data"),
    ("government", "FedRAMP", "classified networks", "citizen data"),
    ("manufacturing", "OT/IT convergence", "SCADA systems", "production control"),
    ("retail", "POS systems", "e-commerce platform", "payment data"),
    ("education", "student records", "research data", "campus network"),
    ("legal", "attorney-client privilege", "case management", "confidential documents"),
    ("tech startup", "cloud-native", "CI/CD pipelines", "source code"),
]

engagement_types = [
    "external network penetration test",
    "internal network assessment", 
    "web application security test",
    "wireless security assessment",
    "social engineering engagement",
    "red team exercise",
    "assumed breach scenario",
    "purple team collaboration",
]

findings_types = [
    ("critical", "remote code execution", "immediate remediation", "CVSS 9.8"),
    ("high", "privilege escalation", "30-day remediation", "CVSS 8.1"),
    ("medium", "information disclosure", "90-day remediation", "CVSS 5.4"),
    ("low", "missing security headers", "best effort", "CVSS 3.1"),
]

for i in range(800):
    env = random.choice(environments)
    engagement = random.choice(engagement_types)
    finding = random.choice(findings_types)
    
    pentest_scenarios.append({
        "instruction": f"You are conducting a {engagement} for a {env[0]} organization.",
        "input": f"Context: {env[1]} requirements, {env[2]} in scope, protecting {env[3]}. Describe your approach.",
        "output": f"""**Engagement Overview**: {engagement.title()} for {env[0].title()} Sector

**Regulatory Considerations**: {env[1]}
- All testing must maintain compliance boundaries
- Data handling procedures must align with regulatory requirements
- Evidence collection must be forensically sound

**Scope Analysis**: {env[2]}
- Primary attack surface identification
- Integration points with {env[3]} systems
- Trust relationships to enumerate

**Methodology**:

1. **Reconnaissance Phase**
   - Passive information gathering (OSINT)
   - DNS enumeration, certificate transparency
   - Technology fingerprinting

2. **Active Enumeration**
   - Service discovery with rate limiting
   - Version detection for vulnerability matching
   - Authentication endpoint mapping

3. **Vulnerability Assessment**
   - Automated scanning with false-positive validation
   - Manual testing for logic flaws
   - {env[2]}-specific vulnerability research

4. **Exploitation (Controlled)**
   - Proof-of-concept only, no production impact
   - Document exact reproduction steps
   - Screenshot/log evidence collection

5. **Post-Exploitation (if authorized)**
   - Credential harvesting demonstration
   - Lateral movement mapping
   - {env[3]} access verification

**Risk Management**:
- Maintain constant communication with client POC
- Immediate escalation for critical findings
- Emergency rollback procedures documented

**Deliverables**: Executive summary, technical findings, remediation roadmap"""
    })

with open(output_dir / "pentest_scenarios.jsonl", "w") as f:
    for sample in pentest_scenarios:
        f.write(json.dumps(sample) + "\n")
print(f"Generated {len(pentest_scenarios)} pentest scenario samples")

# =============================================================================
# 3. TOOL MASTERY - DEEP USAGE (600 samples)
# =============================================================================

tool_mastery = []

tools_deep = {
    "nmap": {
        "advanced_flags": ["-sV --version-intensity 5", "-sC --script-args", "-Pn -n -T2", 
                          "--script vuln,exploit", "-sU -sS -p-", "--min-rate 100 --max-retries 2"],
        "scenarios": ["firewall evasion", "IDS bypass", "slow scan", "service fingerprinting", "vuln detection"]
    },
    "burpsuite": {
        "advanced_flags": ["Intruder cluster bomb", "Scanner crawl settings", "Collaborator payloads",
                          "Match/replace rules", "Session handling rules", "Macro recording"],
        "scenarios": ["auth testing", "CSRF bypass", "rate limit bypass", "session analysis", "API fuzzing"]
    },
    "metasploit": {
        "advanced_flags": ["AutoRunScript", "PrependMigrate", "EnableStageEncoding", 
                          "LHOST/LPORT pivoting", "multi/handler advanced", "post modules chaining"],
        "scenarios": ["AV evasion", "payload staging", "persistence", "pivoting", "credential harvesting"]
    },
    "bloodhound": {
        "advanced_flags": ["SharpHound collection methods", "LDAP query optimization", "Session collection",
                          "ACL analysis", "Kerberos delegation", "GPO abuse paths"],
        "scenarios": ["shortest path to DA", "Kerberoastable accounts", "AS-REP roasting targets", "ACL abuse"]
    },
    "impacket": {
        "advanced_flags": ["secretsdump.py options", "psexec.py variants", "wmiexec.py stealth",
                          "ntlmrelayx.py", "kerberos tools", "GetUserSPNs.py"],
        "scenarios": ["pass-the-hash", "Kerberoasting", "DCSync", "relay attacks", "delegation abuse"]
    },
    "crackmapexec": {
        "advanced_flags": ["--continue-on-success", "-M modules", "--local-auth", 
                          "--shares enumeration", "--sessions", "--loggedon-users"],
        "scenarios": ["credential spraying", "share enumeration", "session hunting", "module execution"]
    },
    "responder": {
        "advanced_flags": ["-I interface", "-wrf", "--lm", "-A (analyze mode)", 
                          "MultiRelay", "WPAD proxy"],
        "scenarios": ["LLMNR poisoning", "NBT-NS poisoning", "WPAD abuse", "credential capture"]
    },
    "hashcat": {
        "advanced_flags": ["-a 0 -m hash_type", "-r rules/best64.rule", "--increment", 
                          "-O (optimized)", "--session", "-w 3"],
        "scenarios": ["dictionary attack", "rule-based", "mask attack", "hybrid", "distributed cracking"]
    },
}

for i in range(600):
    tool = random.choice(list(tools_deep.keys()))
    config = tools_deep[tool]
    flag = random.choice(config["advanced_flags"])
    scenario = random.choice(config["scenarios"])
    
    tool_mastery.append({
        "instruction": f"Explain advanced {tool} usage for {scenario}.",
        "input": f"Specific technique: {flag}",
        "output": f"""**Tool**: {tool}
**Scenario**: {scenario.title()}
**Advanced Configuration**: `{flag}`

**Purpose**: This configuration optimizes {tool} for {scenario} by adjusting core parameters for effectiveness while minimizing detection.

**Implementation**:
```bash
# Example command structure
{tool} {flag} [target_specification]
```

**Why This Works**:
1. **Operational Efficiency**: Reduces noise and false positives
2. **Detection Avoidance**: Blends with legitimate traffic patterns
3. **Resource Optimization**: Balances speed vs stealth requirements

**Key Considerations**:
- Monitor for defensive responses (rate limiting, blocking)
- Validate results before proceeding to next phase
- Log all activities for reporting and evidence

**When NOT to Use**:
- Time-constrained engagements (may be too slow)
- When stealth is not a priority
- If target has already detected your presence

**Complementary Tools**: Consider combining with other tools for validation and coverage.

**OPSEC Note**: Always verify you're operating within scope before executing."""
    })

with open(output_dir / "tool_mastery.jsonl", "w") as f:
    for sample in tool_mastery:
        f.write(json.dumps(sample) + "\n")
print(f"Generated {len(tool_mastery)} tool mastery samples")

# =============================================================================
# 4. DETECTION EVASION DEEP DIVE (700 samples)
# =============================================================================

evasion_samples = []

edr_products = ["CrowdStrike Falcon", "Microsoft Defender ATP", "Carbon Black", 
                "SentinelOne", "Cylance", "Sophos Intercept X", "Trend Micro Apex One"]

evasion_techniques = [
    ("process injection", "CreateRemoteThread", "allocate memory in remote process"),
    ("dll sideloading", "legitimate application loading malicious DLL", "abuse search order"),
    ("reflective loading", "load PE from memory", "avoid disk writes"),
    ("syscall evasion", "direct syscalls", "bypass userland hooks"),
    ("AMSI bypass", "patch AmsiScanBuffer", "disable script scanning"),
    ("ETW evasion", "patch EtwEventWrite", "disable telemetry"),
    ("unhooking", "restore original ntdll", "remove EDR hooks"),
    ("process hollowing", "replace legitimate process memory", "masquerade execution"),
    ("ppid spoofing", "fake parent process", "evade behavioral detection"),
    ("timestomping", "modify file timestamps", "evade forensic analysis"),
]

for i in range(700):
    edr = random.choice(edr_products)
    technique = random.choice(evasion_techniques)
    
    evasion_samples.append({
        "instruction": f"You need to evade {edr} detection during post-exploitation.",
        "input": f"Technique consideration: {technique[0]} ({technique[1]})",
        "output": f"""**Target EDR**: {edr}
**Evasion Technique**: {technique[0].title()}

**Technique Overview**: {technique[2]}

**{edr} Detection Capabilities**:
- Behavioral analysis of process activities
- Memory scanning for known patterns
- Kernel-level monitoring
- Cloud-based threat intelligence

**Evasion Strategy for {technique[0]}**:

1. **Preparation**:
   - Research current {edr} detection signatures
   - Test in isolated environment matching target config
   - Prepare fallback techniques

2. **Implementation**:
   - {technique[1]}
   - Use obfuscation to avoid signature detection
   - Implement gradually to test detection thresholds

3. **OPSEC Considerations**:
   - Avoid known-bad patterns and IoCs
   - Use legitimate process names and paths
   - Maintain low resource footprint
   - Clean up artifacts after execution

4. **Detection Indicators to Avoid**:
   - Suspicious API call sequences
   - Anomalous memory allocations
   - Parent-child process relationships
   - Network callbacks to unknown destinations

**Risk Assessment**:
- Detection Probability: 20-40% (depends on implementation)
- Attribution Risk: Medium
- Forensic Artifacts: Moderate

**Alternative Approaches**: If detected, consider [different technique] or abort and reassess.

**Note**: Always have an exit strategy prepared."""
    })

with open(output_dir / "evasion_deep.jsonl", "w") as f:
    for sample in evasion_samples:
        f.write(json.dumps(sample) + "\n")
print(f"Generated {len(evasion_samples)} evasion samples")

# =============================================================================
# 5. FAILURE ANALYSIS & RECOVERY (500 samples)
# =============================================================================

failure_samples = []

failure_scenarios = [
    ("exploit failed", "target patched", "research alternative CVEs or attack vectors"),
    ("credentials invalid", "password changed", "attempt credential spraying or Kerberoasting"),
    ("connection blocked", "firewall rule added", "pivot through alternate network path"),
    ("tool detected", "AV quarantined payload", "use different evasion technique"),
    ("access revoked", "SOC responded", "assess if burned, establish new foothold"),
    ("target offline", "system rebooted/shutdown", "wait and retry or find alternate target"),
    ("rate limited", "brute force protection", "slow down attack or use distributed approach"),
    ("MFA challenge", "authentication hardened", "research MFA bypass or social engineer"),
    ("network segmented", "lateral movement blocked", "identify allowed protocols or pivot points"),
    ("logging detected", "suspicious activity flagged", "reduce noise, modify TTPs"),
]

for i in range(500):
    scenario = random.choice(failure_scenarios)
    
    failure_samples.append({
        "instruction": "Your attack just failed. Analyze and recover.",
        "input": f"Failure: {scenario[0]}. Reason: {scenario[1]}",
        "output": f"""**Failure Analysis**

**What Happened**: {scenario[0].title()}
**Root Cause**: {scenario[1]}

**Immediate Actions**:
1. **Stop** - Do not retry the same technique immediately
2. **Assess** - Determine if you've been detected/burned
3. **Document** - Log the failure for reporting and learning

**Impact Assessment**:
- Has the target been alerted?
- Is your access still valid?
- Are other attack paths affected?

**Recovery Strategy**: {scenario[2]}

**Decision Tree**:
```
If detected → Pause operations, assess burn level
If not detected → Analyze why technique failed
If partially detected → Modify approach, increase stealth
```

**Alternative Approaches**:
1. **Primary Alternative**: Use different technique targeting same objective
2. **Secondary Alternative**: Target different system with same technique
3. **Tertiary Alternative**: Pivot to completely different attack path

**Lessons Learned**:
- Document what triggered the failure
- Update playbook to avoid repetition
- Consider if reconnaissance was insufficient

**Next Steps**:
1. Wait minimum 15-30 minutes before retry
2. Validate remaining access is intact
3. Choose alternative approach from recovery strategy
4. Implement with enhanced OPSEC measures

**Decision**: Continue with modified approach / Abort and report / Reassess scope"""
    })

with open(output_dir / "failure_analysis.jsonl", "w") as f:
    for sample in failure_samples:
        f.write(json.dumps(sample) + "\n")
print(f"Generated {len(failure_samples)} failure analysis samples")

# =============================================================================
# 6. BLUE TEAM PERSPECTIVE (600 samples)
# =============================================================================

blue_team_samples = []

detection_rules = [
    ("Sigma rule", "process creation", "suspicious command line patterns"),
    ("YARA rule", "file scanning", "malware signature matching"),
    ("Suricata rule", "network traffic", "known C2 patterns"),
    ("KQL query", "Azure Sentinel", "behavioral anomaly detection"),
    ("Splunk alert", "log correlation", "multiple failed authentications"),
    ("SIEM correlation", "event chaining", "lateral movement indicators"),
    ("EDR alert", "endpoint behavior", "process injection detected"),
    ("DLP alert", "data exfiltration", "large data transfer to external"),
]

attacker_actions = [
    "password spraying", "Kerberoasting", "DCSync attack", "Golden ticket creation",
    "lateral movement", "credential dumping", "data exfiltration", "persistence establishment",
    "privilege escalation", "reconnaissance scanning", "phishing campaign", "watering hole attack",
]

for i in range(600):
    detection = random.choice(detection_rules)
    action = random.choice(attacker_actions)
    
    blue_team_samples.append({
        "instruction": f"From a blue team perspective, how would you detect {action}?",
        "input": f"Available detection: {detection[0]} for {detection[1]}",
        "output": f"""**Blue Team Detection Strategy**: {action.title()}

**Detection Mechanism**: {detection[0]}
**Data Source**: {detection[1]}
**Detection Logic**: {detection[2]}

**Indicators of Compromise (IoCs)**:
1. **Network-based**:
   - Unusual traffic patterns
   - Connections to known-bad destinations
   - Protocol anomalies

2. **Host-based**:
   - Suspicious process creation
   - Unusual file system activity
   - Registry modifications

3. **Authentication-based**:
   - Failed login patterns
   - Unusual access times/locations
   - Privilege escalation events

**Detection Rule Logic**:
```
# Pseudocode for {detection[0]}
WHEN {detection[1]} detected
AND pattern matches {detection[2]}
AND not whitelisted
THEN alert with severity HIGH
```

**False Positive Considerations**:
- Legitimate admin activities
- Scheduled tasks and maintenance
- Security tool activities

**Response Playbook**:
1. Validate alert is not false positive
2. Contain affected systems if confirmed
3. Preserve evidence for investigation
4. Eradicate threat presence
5. Recovery and lessons learned

**Red Team Implications**:
Understanding this detection helps attackers:
- Avoid triggering the specific pattern
- Use techniques that blend with legitimate activity
- Time attacks to coincide with normal operations

**Improvement Recommendations**:
- Tune detection thresholds
- Add contextual enrichment
- Implement automated response"""
    })

with open(output_dir / "blue_team.jsonl", "w") as f:
    for sample in blue_team_samples:
        f.write(json.dumps(sample) + "\n")
print(f"Generated {len(blue_team_samples)} blue team samples")

# =============================================================================
# 7. CLOUD SECURITY DEEP DIVE (700 samples)
# =============================================================================

cloud_samples = []

cloud_attacks = {
    "AWS": [
        ("IAM privilege escalation", "iam:PassRole + lambda:CreateFunction", "create privileged Lambda"),
        ("S3 bucket takeover", "misconfigured bucket policy", "public read/write access"),
        ("EC2 metadata abuse", "SSRF to 169.254.169.254", "steal instance credentials"),
        ("Lambda persistence", "malicious function deployment", "serverless backdoor"),
        ("CloudTrail evasion", "disable logging", "cover tracks"),
        ("Cross-account access", "AssumeRole abuse", "pivot to other accounts"),
    ],
    "Azure": [
        ("Managed Identity abuse", "IMDS endpoint access", "steal MI tokens"),
        ("Azure AD privilege escalation", "Application admin to Global Admin", "role manipulation"),
        ("Storage account takeover", "SAS token extraction", "data access"),
        ("Runbook exploitation", "Automation account abuse", "code execution"),
        ("Conditional Access bypass", "device compliance spoofing", "MFA evasion"),
        ("PRT theft", "Primary Refresh Token extraction", "persistent access"),
    ],
    "GCP": [
        ("Service account key theft", "metadata server access", "credential extraction"),
        ("GKE privilege escalation", "pod to node escape", "cluster compromise"),
        ("Cloud Function abuse", "serverless code injection", "backdoor deployment"),
        ("IAM binding manipulation", "setIamPolicy permission", "privilege escalation"),
        ("Compute Engine metadata", "instance attribute access", "information disclosure"),
        ("Cloud Shell abuse", "persistent shell access", "maintained foothold"),
    ],
}

for i in range(700):
    provider = random.choice(list(cloud_attacks.keys()))
    attack = random.choice(cloud_attacks[provider])
    
    cloud_samples.append({
        "instruction": f"Explain {provider} attack technique: {attack[0]}",
        "input": f"Method: {attack[1]}. Objective: {attack[2]}",
        "output": f"""**Cloud Attack Analysis**: {attack[0]}

**Cloud Provider**: {provider}
**Attack Vector**: {attack[1]}
**Objective**: {attack[2]}

**Prerequisites**:
- Initial access to {provider} environment
- Specific permissions or misconfigurations present
- Understanding of {provider} security model

**Attack Flow**:

1. **Reconnaissance**:
   - Enumerate current permissions
   - Identify misconfigured resources
   - Map trust relationships

2. **Exploitation**:
   - Technique: {attack[1]}
   - Target: {attack[2]}
   - Expected outcome: Elevated access or data compromise

3. **Post-Exploitation**:
   - Establish persistence if possible
   - Pivot to additional resources
   - Extract valuable data/credentials

**Detection Indicators**:
- Unusual API calls in {provider} logs
- Permission changes or new principals
- Anomalous data access patterns

**{provider}-Specific Mitigations**:
- Implement least privilege IAM policies
- Enable comprehensive logging
- Use {provider}-native security tools
- Regular permission audits

**MITRE ATT&CK Mapping**:
- Technique ID: T1078 (Valid Accounts)
- Tactic: Privilege Escalation / Persistence

**Risk Level**: High
**Difficulty**: Medium
**Detection Probability**: 30-50% with proper monitoring"""
    })

with open(output_dir / "cloud_deep.jsonl", "w") as f:
    for sample in cloud_samples:
        f.write(json.dumps(sample) + "\n")
print(f"Generated {len(cloud_samples)} cloud security samples")

# =============================================================================
# 8. WEB APPLICATION SECURITY (800 samples)
# =============================================================================

web_samples = []

web_vulns = [
    ("SQL Injection", "UNION-based", "' UNION SELECT NULL,username,password FROM users--"),
    ("SQL Injection", "Blind boolean", "' AND 1=1-- vs ' AND 1=2--"),
    ("SQL Injection", "Time-based blind", "'; WAITFOR DELAY '0:0:5'--"),
    ("XSS", "Reflected", "<script>alert(document.cookie)</script>"),
    ("XSS", "Stored", "Persistent payload in database field"),
    ("XSS", "DOM-based", "document.location manipulation"),
    ("SSRF", "Internal port scan", "http://127.0.0.1:22/"),
    ("SSRF", "Cloud metadata", "http://169.254.169.254/latest/meta-data/"),
    ("XXE", "File disclosure", "<!ENTITY xxe SYSTEM 'file:///etc/passwd'>"),
    ("XXE", "SSRF via DTD", "External DTD loading"),
    ("IDOR", "Direct object reference", "Changing user_id parameter"),
    ("IDOR", "UUID guessing", "Predictable identifiers"),
    ("Auth bypass", "JWT manipulation", "Algorithm confusion attack"),
    ("Auth bypass", "Password reset", "Token prediction/reuse"),
    ("CSRF", "State-changing action", "Forged POST request"),
    ("Deserialization", "Unsafe unserialize", "Object injection"),
    ("Path traversal", "Directory escape", "../../../etc/passwd"),
    ("Command injection", "OS command", "; id; cat /etc/passwd"),
]

for i in range(800):
    vuln = random.choice(web_vulns)
    
    web_samples.append({
        "instruction": f"Explain web vulnerability: {vuln[0]} ({vuln[1]})",
        "input": f"Example payload/technique: {vuln[2]}",
        "output": f"""**Web Vulnerability Analysis**

**Vulnerability Class**: {vuln[0]}
**Specific Type**: {vuln[1]}
**Example**: `{vuln[2]}`

**Technical Explanation**:
{vuln[0]} occurs when user input is improperly handled, allowing attackers to manipulate application behavior. The {vuln[1]} variant specifically exploits the way the application processes data.

**Discovery Methodology**:
1. **Parameter Identification**: Map all input vectors
2. **Fuzzing**: Test with characteristic payloads
3. **Validation**: Confirm vulnerability exists
4. **Impact Assessment**: Determine exploitability

**Exploitation Steps**:
1. Identify vulnerable parameter
2. Craft payload: `{vuln[2]}`
3. Submit and observe response
4. Iterate to achieve objective
5. Document for reporting

**Bypass Techniques** (if filters present):
- Encoding variations (URL, HTML, Unicode)
- Case manipulation
- Comment injection
- Alternative syntax

**Impact**:
- Confidentiality: Potential data disclosure
- Integrity: Data manipulation possible
- Availability: Service disruption risk

**Remediation**:
- Input validation and sanitization
- Parameterized queries (for SQLi)
- Output encoding (for XSS)
- Principle of least privilege

**Testing Tools**:
- Burp Suite for manual testing
- SQLMap for SQL injection
- XSStrike for XSS
- Custom scripts for specific scenarios

**OWASP Classification**: Top 10 relevant category
**CWE Reference**: CWE-XXX (specific to vulnerability type)"""
    })

with open(output_dir / "web_security.jsonl", "w") as f:
    for sample in web_samples:
        f.write(json.dumps(sample) + "\n")
print(f"Generated {len(web_samples)} web security samples")

# =============================================================================
# 9. ACTIVE DIRECTORY DEEP DIVE (800 samples)
# =============================================================================

ad_samples = []

ad_attacks = [
    ("Kerberoasting", "Request TGS for SPNs", "crack service account passwords offline"),
    ("AS-REP Roasting", "No preauth accounts", "crack passwords without authentication"),
    ("DCSync", "Replicate domain credentials", "extract all password hashes"),
    ("Golden Ticket", "Forge TGT with KRBTGT", "unlimited domain access"),
    ("Silver Ticket", "Forge TGS for service", "access specific service"),
    ("Pass-the-Hash", "NTLM hash reuse", "authenticate without password"),
    ("Pass-the-Ticket", "Kerberos ticket reuse", "impersonate users"),
    ("Overpass-the-Hash", "NTLM to Kerberos", "request TGT with hash"),
    ("Constrained Delegation", "S4U2Self/S4U2Proxy", "impersonate to specific services"),
    ("Unconstrained Delegation", "TGT stored in memory", "steal delegated credentials"),
    ("Resource-Based Delegation", "msDS-AllowedToActOnBehalfOfOtherIdentity", "computer account takeover"),
    ("ADCS Abuse", "Certificate template exploitation", "privilege escalation via PKI"),
    ("Shadow Credentials", "msDS-KeyCredentialLink", "add key for authentication"),
    ("GPO Abuse", "Group Policy modification", "deploy malicious settings"),
    ("ACL Abuse", "WriteDACL/GenericAll", "modify object permissions"),
    ("DNS Admin", "DLL injection via DNS", "code execution on DC"),
    ("Print Spooler", "PrintNightmare variants", "remote code execution"),
    ("NTLM Relay", "Credential forwarding", "authenticate to other services"),
]

for i in range(800):
    attack = random.choice(ad_attacks)
    
    ad_samples.append({
        "instruction": f"Explain Active Directory attack: {attack[0]}",
        "input": f"Technique: {attack[1]}. Goal: {attack[2]}",
        "output": f"""**Active Directory Attack**: {attack[0]}

**Technique**: {attack[1]}
**Objective**: {attack[2]}

**Prerequisites**:
- Domain user credentials (minimum)
- Network access to domain controllers
- Specific misconfigurations or permissions

**Attack Process**:

1. **Enumeration**:
   - Identify vulnerable configurations
   - Map attack path to objective
   - Validate prerequisites are met

2. **Execution**:
   - {attack[1]}
   - Monitor for detection indicators
   - Validate successful exploitation

3. **Post-Attack**:
   - {attack[2]}
   - Establish persistence if needed
   - Clean up artifacts

**Tools**:
- Rubeus (Kerberos attacks)
- Mimikatz (credential extraction)
- BloodHound (path analysis)
- Impacket (protocol attacks)
- PowerView (enumeration)

**Detection**:
- Event ID 4769 (TGS requests) - Kerberoasting
- Event ID 4768 (TGT requests) - AS-REP Roasting
- Event ID 4662 (Directory replication) - DCSync
- Anomalous Kerberos ticket lifetimes

**Mitigations**:
- Strong service account passwords (25+ chars)
- Enable Kerberos AES encryption
- Implement Protected Users group
- Monitor for attack indicators

**MITRE ATT&CK**:
- Technique: T1558 (Steal or Forge Kerberos Tickets)
- Tactic: Credential Access

**Risk Assessment**:
- Impact: Critical (domain compromise potential)
- Difficulty: Medium (tools widely available)
- Detection: Medium (depends on monitoring)"""
    })

with open(output_dir / "ad_deep.jsonl", "w") as f:
    for sample in ad_samples:
        f.write(json.dumps(sample) + "\n")
print(f"Generated {len(ad_samples)} AD attack samples")

# =============================================================================
# 10. REAL PENTEST REPORT WRITING (500 samples)
# =============================================================================

report_samples = []

finding_templates = [
    ("Critical", "Unauthenticated Remote Code Execution", "SQL injection in login form allows database compromise"),
    ("Critical", "Domain Administrator Compromise", "Kerberoasting of service account with weak password"),
    ("High", "Privilege Escalation to SYSTEM", "Unquoted service path allows local privilege escalation"),
    ("High", "Sensitive Data Exposure", "API endpoint leaks customer PII without authentication"),
    ("Medium", "Cross-Site Scripting (Stored)", "User profile field vulnerable to XSS"),
    ("Medium", "Insecure Direct Object Reference", "Order ID enumeration reveals other customers' data"),
    ("Low", "Information Disclosure", "Verbose error messages reveal internal paths"),
    ("Low", "Missing Security Headers", "X-Frame-Options and CSP not implemented"),
]

for i in range(500):
    finding = random.choice(finding_templates)
    
    report_samples.append({
        "instruction": "Write a professional pentest finding report entry.",
        "input": f"Finding: {finding[1]}. Severity: {finding[0]}. Details: {finding[2]}",
        "output": f"""## Finding: {finding[1]}

**Severity**: {finding[0]}
**CVSS Score**: {"9.8" if finding[0] == "Critical" else "8.1" if finding[0] == "High" else "5.4" if finding[0] == "Medium" else "3.1"}
**Status**: Open

### Description
{finding[2]}

During testing, the assessment team identified a {finding[0].lower()}-severity vulnerability that could allow an attacker to compromise the target system. This finding represents a significant security risk that should be addressed promptly.

### Technical Details
The vulnerability exists due to insufficient input validation/access controls. The following evidence demonstrates the issue:

**Proof of Concept**:
```
[Detailed reproduction steps would be included here]
1. Navigate to vulnerable endpoint
2. Submit crafted payload
3. Observe unauthorized access/execution
```

### Impact
- **Confidentiality**: {"High" if finding[0] in ["Critical", "High"] else "Medium"} - Sensitive data may be exposed
- **Integrity**: {"High" if finding[0] == "Critical" else "Medium"} - Data modification possible
- **Availability**: {"Medium"} - Service disruption potential

### Affected Systems
- Target application/host: [REDACTED]
- Component: [Specific module/function]
- Version: [If applicable]

### Remediation
**Short-term** (Immediate):
- Implement input validation
- Apply access controls
- Monitor for exploitation attempts

**Long-term** (Strategic):
- Code review of similar functionality
- Security training for developers
- Implement automated security testing

### References
- OWASP: [Relevant OWASP reference]
- CWE: CWE-XXX
- MITRE ATT&CK: TXXXX

### Evidence
[Screenshots and logs would be attached]"""
    })

with open(output_dir / "report_writing.jsonl", "w") as f:
    for sample in report_samples:
        f.write(json.dumps(sample) + "\n")
print(f"Generated {len(report_samples)} report writing samples")

# =============================================================================
# 11. INCIDENT RESPONSE & FORENSICS (600 samples)
# =============================================================================

ir_samples = []

incidents = [
    ("ransomware", "file encryption detected", "isolate, preserve, restore"),
    ("data breach", "exfiltration to external IP", "contain, assess scope, notify"),
    ("APT activity", "persistent backdoor found", "hunt, eradicate, harden"),
    ("insider threat", "unusual data access patterns", "investigate, preserve, interview"),
    ("credential compromise", "impossible travel login", "reset, audit, monitor"),
    ("web shell", "suspicious PHP file on server", "remove, analyze, patch"),
    ("cryptominer", "high CPU on servers", "terminate, clean, investigate entry"),
    ("phishing success", "user clicked malicious link", "isolate endpoint, reset creds, scan"),
]

for i in range(600):
    incident = random.choice(incidents)
    
    ir_samples.append({
        "instruction": f"You're responding to a {incident[0]} incident.",
        "input": f"Indicator: {incident[1]}. Initial response plan: {incident[2]}",
        "output": f"""**Incident Response**: {incident[0].title()}

**Initial Indicator**: {incident[1]}
**Severity Classification**: High/Critical

**Immediate Actions** (First 15 minutes):
1. **Confirm** - Validate the alert is not a false positive
2. **Contain** - {incident[2].split(',')[0].strip()}
3. **Communicate** - Alert IR team and stakeholders

**Investigation Phase**:

**Evidence Collection**:
- Memory acquisition from affected systems
- Disk imaging for forensic analysis
- Network traffic capture (PCAP)
- Log collection from all relevant sources

**Timeline Construction**:
- Initial compromise timestamp
- Lateral movement events
- Data access/exfiltration events
- Current threat actor position

**Scope Assessment**:
- Number of affected systems
- Data types potentially compromised
- Business impact evaluation
- Regulatory notification requirements

**Eradication Steps**:
1. Remove malicious artifacts
2. Patch exploitation vectors
3. Reset compromised credentials
4. Implement additional controls

**Recovery**:
- Restore from known-good backups
- Validate system integrity
- Gradual return to production
- Enhanced monitoring period

**Post-Incident**:
- Lessons learned documentation
- Control improvements
- Playbook updates
- Stakeholder reporting

**Key Questions**:
- How did the attacker get in?
- What did they access?
- Are they still present?
- What's the business impact?

**Tools for Investigation**:
- Volatility (memory analysis)
- Autopsy/FTK (disk forensics)
- Wireshark (network analysis)
- SIEM correlation"""
    })

with open(output_dir / "incident_response.jsonl", "w") as f:
    for sample in ir_samples:
        f.write(json.dumps(sample) + "\n")
print(f"Generated {len(ir_samples)} IR/forensics samples")

# =============================================================================
# 12. MITRE ATT&CK MAPPING (500 samples)
# =============================================================================

mitre_samples = []

techniques = [
    ("T1566.001", "Spearphishing Attachment", "Initial Access", "malicious email attachment"),
    ("T1059.001", "PowerShell", "Execution", "script-based attack execution"),
    ("T1055", "Process Injection", "Defense Evasion", "inject code into legitimate process"),
    ("T1003.001", "LSASS Memory", "Credential Access", "dump credentials from memory"),
    ("T1021.002", "SMB/Windows Admin Shares", "Lateral Movement", "move between systems"),
    ("T1078", "Valid Accounts", "Persistence", "use legitimate credentials"),
    ("T1486", "Data Encrypted for Impact", "Impact", "ransomware encryption"),
    ("T1071.001", "Web Protocols", "Command and Control", "HTTP/S C2 communication"),
    ("T1048", "Exfiltration Over Alternative Protocol", "Exfiltration", "DNS tunneling"),
    ("T1087.002", "Domain Account", "Discovery", "enumerate domain users"),
    ("T1110.003", "Password Spraying", "Credential Access", "test common passwords"),
    ("T1558.003", "Kerberoasting", "Credential Access", "extract service tickets"),
    ("T1136.001", "Local Account", "Persistence", "create backdoor account"),
    ("T1562.001", "Disable or Modify Tools", "Defense Evasion", "disable AV/EDR"),
    ("T1547.001", "Registry Run Keys", "Persistence", "autostart malware"),
]

for i in range(500):
    technique = random.choice(techniques)
    
    mitre_samples.append({
        "instruction": f"Map attack behavior to MITRE ATT&CK: {technique[3]}",
        "input": f"Observed activity matches: {technique[1]}",
        "output": f"""**MITRE ATT&CK Mapping**

**Technique ID**: {technique[0]}
**Technique Name**: {technique[1]}
**Tactic**: {technique[2]}
**Description**: {technique[3]}

**ATT&CK Matrix Position**:
```
Tactic: {technique[2]}
  └── Technique: {technique[1]} ({technique[0]})
       └── Sub-technique: (if applicable)
```

**Behavioral Indicators**:
- Specific actions that trigger this classification
- Tool artifacts commonly associated
- Network/host indicators

**Detection Opportunities**:
- Data sources: Process monitoring, command-line logging
- Detection logic: Behavioral patterns to alert on
- False positive considerations

**Related Techniques**:
- Often chained with other techniques
- Common follow-up activities
- Alternative approaches

**Threat Actor Usage**:
- APT groups known to use this technique
- Criminal organizations
- Commodity malware

**Defensive Recommendations**:
- Preventive controls
- Detective measures
- Response playbooks

**References**:
- ATT&CK page: https://attack.mitre.org/techniques/{technique[0].replace('.', '/')}/
- Detection resources
- Threat intelligence reports

**Pentest Application**:
When simulating adversary behavior, this technique can be demonstrated by:
1. Setting up appropriate prerequisites
2. Executing the technique safely
3. Documenting evidence for reporting
4. Providing remediation guidance"""
    })

with open(output_dir / "mitre_mapping.jsonl", "w") as f:
    for sample in mitre_samples:
        f.write(json.dumps(sample) + "\n")
print(f"Generated {len(mitre_samples)} MITRE mapping samples")

# =============================================================================
# 13. SOCIAL ENGINEERING (400 samples)
# =============================================================================

se_samples = []

se_techniques = [
    ("phishing", "credential harvesting", "clone legitimate login page"),
    ("vishing", "phone-based pretexting", "impersonate IT support"),
    ("smishing", "SMS-based attack", "urgent message with malicious link"),
    ("pretexting", "false scenario creation", "impersonate vendor/partner"),
    ("baiting", "curiosity exploitation", "USB drop attack"),
    ("tailgating", "physical access", "follow authorized person"),
    ("quid pro quo", "service exchange", "offer help for information"),
    ("watering hole", "targeted site compromise", "infect frequently visited site"),
]

for i in range(400):
    technique = random.choice(se_techniques)
    
    se_samples.append({
        "instruction": f"Design a social engineering scenario: {technique[0]}",
        "input": f"Objective: {technique[1]}. Method: {technique[2]}",
        "output": f"""**Social Engineering Scenario**: {technique[0].title()}

**Objective**: {technique[1]}
**Methodology**: {technique[2]}

**Engagement Requirements**:
- Written authorization from client
- Defined scope and boundaries
- Emergency contact procedures
- Legal review completed

**Scenario Design**:

**Pretext Development**:
- Believable backstory creation
- Supporting materials (fake badge, email domain)
- Escalation paths if challenged

**Target Research**:
- Organizational structure
- Key personnel identification
- Communication patterns
- Security awareness training history

**Execution Plan**:
1. **Preparation**: Create convincing materials
2. **Initial Contact**: Establish rapport and credibility
3. **Information Gathering**: Extract target information
4. **Objective Achievement**: {technique[1]}
5. **Clean Exit**: Disengage without suspicion

**Success Metrics**:
- Credentials obtained
- Access achieved
- Information disclosed
- Click/interaction rates

**Documentation**:
- Record all interactions
- Screenshot evidence
- Maintain detailed timeline
- Note security awareness observations

**Ethical Boundaries**:
- No actual harm to individuals
- Respect privacy limits
- Report concerning behaviors
- Immediate stop if serious risk identified

**Post-Engagement**:
- Debrief with client
- Provide training recommendations
- Identify vulnerable individuals (for training, not punishment)
- Security awareness improvement plan"""
    })

with open(output_dir / "social_engineering.jsonl", "w") as f:
    for sample in se_samples:
        f.write(json.dumps(sample) + "\n")
print(f"Generated {len(se_samples)} social engineering samples")

# =============================================================================
# 14. WIRELESS & PHYSICAL SECURITY (400 samples)
# =============================================================================

wireless_samples = []

wireless_attacks = [
    ("WPA2 handshake capture", "4-way handshake", "crack PSK offline"),
    ("Evil twin", "rogue access point", "MITM wireless clients"),
    ("PMKID attack", "single frame capture", "no client required"),
    ("WPA3 downgrade", "force legacy protocol", "exploit weaker security"),
    ("Karma attack", "respond to all probes", "capture connecting clients"),
    ("Deauthentication", "force reconnection", "capture handshakes"),
    ("Bluetooth attacks", "BlueBorne/KNOB", "exploit BT vulnerabilities"),
    ("RFID cloning", "badge duplication", "physical access"),
]

for i in range(400):
    attack = random.choice(wireless_attacks)
    
    wireless_samples.append({
        "instruction": f"Explain wireless security assessment technique: {attack[0]}",
        "input": f"Method: {attack[1]}. Objective: {attack[2]}",
        "output": f"""**Wireless Security Assessment**: {attack[0]}

**Technique**: {attack[1]}
**Objective**: {attack[2]}

**Equipment Required**:
- Wireless adapter with monitor mode support
- Appropriate antennas for range
- Attack platform (laptop/Pi)
- Relevant tools installed

**Legal Considerations**:
- Written authorization required
- FCC regulations awareness
- Minimize impact to third parties
- Document all activities

**Attack Methodology**:

1. **Reconnaissance**:
   - Site survey and AP enumeration
   - Client identification
   - Signal strength mapping

2. **Setup**:
   - Configure adapter for monitor mode
   - Select target channel
   - Position for optimal reception

3. **Execution**:
   - {attack[1]}
   - Capture required data
   - Validate successful capture

4. **Post-Processing**:
   - {attack[2]}
   - Analyze results
   - Document findings

**Tools**:
- Aircrack-ng suite
- Bettercap/MANA
- Hashcat for cracking
- Wireshark for analysis

**Detection Indicators**:
- Wireless IDS alerts
- Deauthentication storm detection
- Rogue AP detection systems
- RSSI anomalies

**Mitigations**:
- WPA3 Enterprise deployment
- 802.1X authentication
- Wireless intrusion detection
- Regular security assessments

**Reporting**:
- Document vulnerable configurations
- Provide remediation timeline
- Recommend security improvements"""
    })

with open(output_dir / "wireless_physical.jsonl", "w") as f:
    for sample in wireless_samples:
        f.write(json.dumps(sample) + "\n")
print(f"Generated {len(wireless_samples)} wireless/physical samples")

# =============================================================================
# 15. CTF & CHALLENGE SCENARIOS (400 samples)
# =============================================================================

ctf_samples = []

ctf_categories = [
    ("binary exploitation", "buffer overflow", "control EIP and redirect execution"),
    ("reverse engineering", "malware analysis", "understand program behavior"),
    ("cryptography", "weak implementation", "break encryption scheme"),
    ("web exploitation", "multi-stage attack", "chain vulnerabilities"),
    ("forensics", "memory analysis", "extract evidence from dump"),
    ("OSINT", "information gathering", "find hidden information"),
    ("misc", "creative thinking", "lateral thinking required"),
    ("pwn", "heap exploitation", "use-after-free for code execution"),
]

for i in range(400):
    category = random.choice(ctf_categories)
    
    ctf_samples.append({
        "instruction": f"CTF Challenge: {category[0]} - {category[1]}",
        "input": f"Objective: {category[2]}. Approach this methodically.",
        "output": f"""**CTF Challenge Analysis**: {category[0].title()}

**Challenge Type**: {category[1]}
**Objective**: {category[2]}

**Initial Analysis**:
1. Read the challenge description carefully
2. Identify provided files/resources
3. Note any hints in the description
4. Check point value (indicates difficulty)

**Methodology**:

**Step 1: Reconnaissance**
- Examine all provided materials
- Run file/strings on binaries
- Check for hidden data
- Identify technologies involved

**Step 2: Vulnerability Identification**
- For {category[0]}: Look for {category[1]}
- Test assumptions systematically
- Document findings

**Step 3: Exploit Development**
- Craft proof-of-concept
- Iterate based on feedback
- Achieve objective: {category[2]}

**Step 4: Flag Extraction**
- Locate flag in expected format
- Verify flag is correct
- Submit and document

**Common Pitfalls**:
- Overthinking the solution
- Missing obvious hints
- Not reading description carefully
- Rabbit holes

**Tools for {category[0]}**:
- Category-specific tools
- General analysis utilities
- Custom scripts as needed

**Learning Approach**:
- Take notes throughout
- Understand WHY the solution works
- Practice similar challenges
- Share writeups for community learning

**Time Management**:
- Set time limits for approaches
- Move on if stuck, return later
- Prioritize higher-point challenges
- Collaborate when allowed"""
    })

with open(output_dir / "ctf_scenarios.jsonl", "w") as f:
    for sample in ctf_samples:
        f.write(json.dumps(sample) + "\n")
print(f"Generated {len(ctf_samples)} CTF scenario samples")

# =============================================================================
# MERGE ALL FILES
# =============================================================================

print("\n" + "="*60)
print("Merging all elite dataset files...")

all_samples = []
for jsonl_file in output_dir.glob("*.jsonl"):
    with open(jsonl_file) as f:
        for line in f:
            all_samples.append(json.loads(line))

# Shuffle for better training
random.shuffle(all_samples)

# Save combined file
combined_file = output_dir / "elite_combined.jsonl"
with open(combined_file, "w") as f:
    for sample in all_samples:
        f.write(json.dumps(sample) + "\n")

print(f"\n✅ ELITE DATASET COMPLETE!")
print(f"   Total new samples: {len(all_samples)}")
print(f"   Output: {combined_file}")
print("="*60)
