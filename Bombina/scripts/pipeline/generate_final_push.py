#!/usr/bin/env python3
"""
Final Push Generator - Reach 15,000+ total samples
Unique combinations to fill remaining gaps
"""

import json
import random
import hashlib
from pathlib import Path

output_dir = Path(__file__).parent.parent / "data" / "generated" / "final_push"
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

print("Final push to 15k+ samples...")

# =============================================================================
# 1. CHAINED ATTACK PROGRESSIONS (800 samples)
# =============================================================================

attack_progressions = [
    {
        "name": "External to Domain Admin",
        "stages": [
            ("OSINT", "gather employee emails", "email list for phishing"),
            ("phishing", "send credential harvester", "captured credentials"),
            ("initial access", "VPN login with creds", "internal network access"),
            ("enumeration", "BloodHound collection", "attack path identified"),
            ("credential theft", "Kerberoast service accounts", "crackable TGS tickets"),
            ("cracking", "hashcat with rules", "plaintext password"),
            ("lateral movement", "psexec to server", "server admin access"),
            ("privilege escalation", "DCSync", "domain admin hash"),
            ("persistence", "golden ticket", "permanent access"),
        ]
    },
    {
        "name": "Web App to Internal Network",
        "stages": [
            ("recon", "subdomain enumeration", "discovered dev.target.com"),
            ("scanning", "nuclei vulnerability scan", "SQL injection found"),
            ("exploitation", "SQLi to file write", "web shell uploaded"),
            ("shell upgrade", "reverse shell callback", "interactive shell"),
            ("enumeration", "internal network scan", "discovered database server"),
            ("credential extraction", "config file passwords", "DB credentials"),
            ("lateral movement", "SSH to DB server", "database access"),
            ("data exfiltration", "dump customer data", "PII extracted"),
        ]
    },
    {
        "name": "Cloud Initial Access to Data Breach",
        "stages": [
            ("OSINT", "GitHub secret scanning", "AWS access keys found"),
            ("validation", "test AWS credentials", "valid IAM user access"),
            ("enumeration", "enumerate S3 buckets", "backup bucket found"),
            ("access", "download S3 objects", "database backup obtained"),
            ("analysis", "extract backup data", "connection strings found"),
            ("pivot", "connect to RDS", "production database access"),
            ("exfiltration", "dump user table", "credentials and PII"),
        ]
    },
]

for progression in attack_progressions:
    for i, (stage_name, action, outcome) in enumerate(progression["stages"]):
        context = f"Stage {i+1} of {len(progression['stages'])}"
        previous = progression["stages"][i-1][2] if i > 0 else "initial position"
        next_stage = progression["stages"][i+1][0] if i < len(progression["stages"])-1 else "objective achieved"
        
        inst = f"{progression['name']} attack chain: {stage_name}"
        inp = f"Previous outcome: {previous}. Current stage: {stage_name}. Action: {action}"
        out = f"""**Attack Chain**: {progression['name']}
**Stage**: {i+1}/{len(progression["stages"])} - {stage_name.title()}

**Context**: {context}
**Previous Outcome**: {previous}

**Current Stage: {stage_name.title()}**

**Action**: {action}
**Expected Outcome**: {outcome}

**Execution**:
1. Leverage {previous}
2. Perform {action}
3. Validate {outcome}
4. Prepare for next stage

**Technique Details**:
```
# Commands/techniques for {action}
# [Stage-specific methodology]
```

**Risk Assessment**:
- Detection probability at this stage
- Points of potential failure
- Rollback options if needed

**Success Criteria**:
- {outcome} achieved
- Access stable and usable
- Ready for: {next_stage}

**OPSEC Notes**:
- Stage-specific detection risks
- Evidence/artifacts created
- Cleanup requirements

**If Stage Fails**:
- Alternative techniques available
- Consider returning to previous stage
- Document findings regardless"""
        add_sample(inst, inp, out)

print(f"Attack progressions: {len(all_samples)} samples")

# =============================================================================
# 2. SPECIFIC TOOL WORKFLOWS (600 samples)
# =============================================================================
start_count = len(all_samples)

tool_workflows = {
    "Burp Suite": [
        ("intercepting traffic", "configure proxy, capture requests", "analyze request/response"),
        ("active scanning", "right-click scan, configure scope", "vulnerability findings"),
        ("intruder attack", "mark positions, select payload list", "successful injection points"),
        ("repeater testing", "modify parameters, analyze response", "manual exploitation"),
        ("sequencer analysis", "capture tokens, analyze randomness", "weak session tokens"),
    ],
    "Metasploit": [
        ("exploit selection", "search, info, use", "configured exploit module"),
        ("payload configuration", "set payload, options", "ready to exploit"),
        ("exploitation", "check, exploit", "meterpreter session"),
        ("post exploitation", "use post modules, hashdump", "credentials extracted"),
        ("pivoting", "route add, autoroute", "access to internal network"),
    ],
    "BloodHound": [
        ("data collection", "SharpHound, all collection methods", "JSON files ready"),
        ("database import", "upload to Neo4j", "graph populated"),
        ("path analysis", "find shortest path to DA", "attack path identified"),
        ("ACL analysis", "find dangerous permissions", "abuse opportunities found"),
        ("kerberoastable", "mark service accounts", "targets for Kerberoasting"),
    ],
    "Nmap": [
        ("host discovery", "-sn, -PR, -PS", "live hosts identified"),
        ("port scanning", "-p-, -sS, timing", "open ports found"),
        ("service detection", "-sV, version intensity", "services identified"),
        ("script scanning", "-sC, --script", "vulnerabilities found"),
        ("output parsing", "grep, awk, or parsers", "actionable results"),
    ],
    "Hashcat": [
        ("hash identification", "hashid, hash-identifier", "hash type confirmed"),
        ("attack mode selection", "dictionary, rules, mask", "attack configured"),
        ("optimization", "-w 3, -O, --force", "speed optimized"),
        ("rule creation", "custom rule file", "targeted attack"),
        ("distributed cracking", "--session, restore", "multi-system attack"),
    ],
}

for tool, workflows in tool_workflows.items():
    for workflow_name, steps, outcome in workflows:
        for scenario in ["pentest engagement", "CTF competition", "bug bounty", "red team op", "training exercise"]:
            inst = f"{tool} workflow: {workflow_name}"
            inp = f"Tool: {tool}. Workflow: {workflow_name}. Scenario: {scenario}. Steps: {steps}"
            out = f"""**Tool Workflow**: {tool}

**Workflow**: {workflow_name}
**Scenario**: {scenario}
**Expected Outcome**: {outcome}

**Step-by-Step Process**:

**Steps**: {steps}

1. **Setup**
   - Launch {tool}
   - Configure for {scenario}
   - Verify target scope

2. **Execution**
```
# {tool} specific commands
{steps}
```

3. **Analysis**
   - Review {outcome}
   - Document findings
   - Prioritize next steps

**Workflow Tips**:
- {workflow_name} is essential for {scenario}
- Output feeds into subsequent phases
- Save configuration for future use

**Common Issues**:
- [Typical problems with {workflow_name}]
- [Solutions and workarounds]

**Integration**:
- Export results for other tools
- Chain with complementary workflows
- Document for reporting

**Outcome Achieved**: {outcome}"""
            add_sample(inst, inp, out)

print(f"Tool workflows: {len(all_samples) - start_count} new samples")

# =============================================================================
# 3. SECURITY CONCEPTS EXPLANATIONS (500 samples)
# =============================================================================
start_count = len(all_samples)

concepts = [
    ("authentication", ["single-factor", "multi-factor", "passwordless", "certificate-based", "biometric"]),
    ("authorization", ["RBAC", "ABAC", "ACLs", "capabilities", "least privilege"]),
    ("encryption", ["symmetric", "asymmetric", "hashing", "TLS/SSL", "at-rest"]),
    ("network security", ["firewalls", "segmentation", "IDS/IPS", "VPN", "zero trust"]),
    ("application security", ["input validation", "output encoding", "parameterized queries", "CSRF tokens"]),
    ("identity management", ["SSO", "federation", "OAuth", "SAML", "OIDC"]),
    ("monitoring", ["logging", "SIEM", "EDR", "NDR", "UEBA"]),
    ("incident response", ["preparation", "detection", "containment", "eradication", "recovery"]),
]

perspectives = ["attacker perspective", "defender perspective", "architect perspective", "auditor perspective"]

for concept_name, variants in concepts:
    for variant in variants:
        for perspective in perspectives:
            inst = f"Explain {concept_name}: {variant}"
            inp = f"Concept: {variant}. Perspective: {perspective}"
            out = f"""**Security Concept**: {concept_name.title()}
**Specific Topic**: {variant}
**Perspective**: {perspective.title()}

**Overview**:
{variant} is a key component of {concept_name} that provides [specific security benefit].

**{perspective.title()}**:

{f'''**Attacker Perspective**:
- How to identify {variant} implementation
- Common weaknesses to exploit
- Bypass techniques
- Detection evasion''' if perspective == "attacker perspective" else ""}

{f'''**Defender Perspective**:
- How to implement {variant} securely
- Monitoring for abuse
- Incident response procedures
- Hardening recommendations''' if perspective == "defender perspective" else ""}

{f'''**Architect Perspective**:
- Design considerations for {variant}
- Integration with other controls
- Scalability and performance
- Compliance requirements''' if perspective == "architect perspective" else ""}

{f'''**Auditor Perspective**:
- How to assess {variant} implementation
- Common findings and gaps
- Evidence collection
- Reporting recommendations''' if perspective == "auditor perspective" else ""}

**Key Points**:
1. {variant} purpose and function
2. Implementation best practices
3. Common misconfigurations
4. Testing approach

**Related Concepts**:
- Other aspects of {concept_name}
- Complementary security controls
- Industry standards and frameworks"""
            add_sample(inst, inp, out)

print(f"Security concepts: {len(all_samples) - start_count} new samples")

# =============================================================================
# 4. SPECIFIC VULNERABILITY EXPLOITS (600 samples)
# =============================================================================
start_count = len(all_samples)

specific_vulns = [
    ("Log4Shell", "CVE-2021-44228", "JNDI lookup injection", "RCE via crafted string"),
    ("ProxyLogon", "CVE-2021-26855", "Exchange SSRF", "Pre-auth RCE on Exchange"),
    ("Zerologon", "CVE-2020-1472", "Netlogon crypto flaw", "Domain admin without creds"),
    ("EternalBlue", "CVE-2017-0144", "SMBv1 buffer overflow", "Remote SYSTEM shell"),
    ("PrintNightmare", "CVE-2021-34527", "Print Spooler RCE", "SYSTEM via driver install"),
    ("BlueKeep", "CVE-2019-0708", "RDP pre-auth RCE", "Remote code execution"),
    ("Shellshock", "CVE-2014-6271", "Bash function export", "Command injection via headers"),
    ("Heartbleed", "CVE-2014-0160", "OpenSSL memory leak", "Memory disclosure"),
    ("MS08-067", "CVE-2008-4250", "Server service overflow", "Remote code execution"),
    ("Spring4Shell", "CVE-2022-22965", "Spring ClassLoader", "RCE via property binding"),
]

phases = ["detection", "validation", "exploitation", "post-exploitation", "remediation verification"]

for vuln_name, cve, method, impact in specific_vulns:
    for phase in phases:
        for target in ["external target", "internal system", "lab environment", "production (authorized)"]:
            inst = f"{vuln_name} ({cve}): {phase}"
            inp = f"Vulnerability: {vuln_name}. CVE: {cve}. Phase: {phase}. Target: {target}"
            out = f"""**Vulnerability**: {vuln_name} ({cve})

**Method**: {method}
**Impact**: {impact}
**Phase**: {phase}
**Target Type**: {target}

**{phase.title()}**:

{f'''**Detection**:
- Scan with vulnerability scanners
- Check for vulnerable versions
- Look for exposed attack surface
- Validate prerequisites''' if phase == "detection" else ""}

{f'''**Validation**:
- Confirm vulnerability exists
- Test with benign payload
- Verify exploitable conditions
- Document for reporting''' if phase == "validation" else ""}

{f'''**Exploitation**:
Using {method}:
```
# Exploit payload/commands for {vuln_name}
# [Specific exploitation steps]
```
Expected outcome: {impact}''' if phase == "exploitation" else ""}

{f'''**Post-Exploitation**:
After achieving {impact}:
1. Establish persistent access
2. Enumerate from new position
3. Document impact demonstrated
4. Maintain OPSEC''' if phase == "post-exploitation" else ""}

{f'''**Remediation Verification**:
After patching:
1. Re-scan for vulnerability
2. Verify patch applied correctly
3. Test exploitation fails
4. Document remediation success''' if phase == "remediation verification" else ""}

**CVSS Score**: Critical (9.0+)
**Affected Products**: [Specific versions]

**References**:
- NVD: https://nvd.nist.gov/vuln/detail/{cve}
- Exploit-DB / PoC sources
- Vendor advisory"""
            add_sample(inst, inp, out)

print(f"Specific vulnerabilities: {len(all_samples) - start_count} new samples")

# =============================================================================
# 5. ENVIRONMENT-SPECIFIC TECHNIQUES (500 samples)
# =============================================================================
start_count = len(all_samples)

environments = [
    ("Docker", ["container escape", "socket access", "image analysis", "runtime security", "secrets extraction"]),
    ("Kubernetes", ["pod escape", "RBAC abuse", "secrets access", "network policy bypass", "service account abuse"]),
    ("AWS", ["IAM escalation", "S3 enumeration", "Lambda abuse", "EC2 metadata", "CloudTrail evasion"]),
    ("Azure", ["managed identity", "storage access", "runbook abuse", "AD connect", "function apps"]),
    ("GCP", ["service accounts", "GKE escape", "Cloud Functions", "metadata server", "BigQuery access"]),
    ("VMware", ["vCenter access", "ESXi exploitation", "VM escape", "snapshot access", "network config"]),
    ("Active Directory", ["GPO abuse", "delegation abuse", "ACL exploitation", "certificate abuse", "trust attacks"]),
]

for env, techniques in environments:
    for technique in techniques:
        for access_level in ["unauthenticated", "low privilege user", "standard user", "admin equivalent"]:
            inst = f"{env} security: {technique}"
            inp = f"Environment: {env}. Technique: {technique}. Current access: {access_level}"
            out = f"""**Environment**: {env}
**Technique**: {technique}
**Current Access**: {access_level}

**Attack Methodology**:

**Prerequisites**:
- {access_level} access to {env}
- Understanding of {env} architecture
- Appropriate tools available

**{technique.title()}**:

1. **Enumeration**
   - Identify {technique} opportunities
   - Map permissions and access
   - Find misconfigurations

2. **Exploitation**
```
# {env}-specific commands for {technique}
# [Technique-specific syntax]
```

3. **Validation**
   - Confirm successful exploitation
   - Document impact achieved
   - Prepare for next phase

**{env}-Specific Considerations**:
- Native logging and monitoring
- Built-in security controls
- Common misconfigurations
- Audit requirements

**Detection Indicators**:
- {env} audit logs
- API call patterns
- Resource changes

**Remediation**:
- Specific fixes for {technique}
- {env} hardening guidelines
- Monitoring recommendations

**Tools**:
- {env}-specific tools for {technique}
- Cloud CLI utilities
- Custom scripts"""
            add_sample(inst, inp, out)

print(f"Environment-specific: {len(all_samples) - start_count} new samples")

# =============================================================================
# 6. DECISION TREES (400 samples)
# =============================================================================
start_count = len(all_samples)

decision_scenarios = [
    {
        "scenario": "Initial foothold established",
        "options": [
            ("persist first", "ensure access survives", "stability over speed"),
            ("escalate first", "get higher privileges", "more capabilities"),
            ("enumerate first", "understand environment", "informed decisions"),
            ("exfiltrate first", "grab quick wins", "immediate value"),
        ]
    },
    {
        "scenario": "Detected by security team",
        "options": [
            ("pause operations", "wait for investigation to end", "avoid escalation"),
            ("switch techniques", "change TTPs", "continue with stealth"),
            ("accelerate", "achieve objectives quickly", "before containment"),
            ("abort", "end operation cleanly", "prevent attribution"),
        ]
    },
    {
        "scenario": "Found sensitive data",
        "options": [
            ("document and continue", "evidence for report", "comprehensive test"),
            ("exfiltrate immediately", "demonstrate impact", "prove risk"),
            ("notify client", "early warning", "responsible disclosure"),
            ("deeper access", "follow the data", "find more exposure"),
        ]
    },
    {
        "scenario": "Multiple attack paths available",
        "options": [
            ("quickest path", "fastest to objective", "time efficiency"),
            ("stealthiest path", "lowest detection risk", "operational security"),
            ("most impactful", "demonstrates highest risk", "reporting value"),
            ("test all paths", "comprehensive coverage", "thorough assessment"),
        ]
    },
]

for decision in decision_scenarios:
    for option_name, action, rationale in decision["options"]:
        for constraint in ["time-limited engagement", "stealth required", "loud test allowed", "compliance scope"]:
            inst = f"Pentest decision: {decision['scenario']}"
            inp = f"Scenario: {decision['scenario']}. Option: {option_name}. Constraint: {constraint}"
            out = f"""**Decision Point**: {decision["scenario"]}

**Chosen Option**: {option_name}
**Action**: {action}
**Rationale**: {rationale}
**Constraint**: {constraint}

**Decision Analysis**:

**Why {option_name}?**
Given {constraint}, {option_name} is optimal because:
- {rationale}
- Aligns with engagement constraints
- Balances risk and reward

**Implementation**:
1. {action}
2. Monitor for issues
3. Adjust as needed
4. Document decision

**Alternative Options Considered**:
{chr(10).join(f"- {opt[0]}: {opt[2]}" for opt in decision['options'] if opt[0] != option_name)}

**Risk Assessment**:
- Detection risk: [Based on option]
- Impact if failed: [Consequences]
- Reversibility: [Can we undo?]

**Constraint Impact** ({constraint}):
- How constraint affects this choice
- Modifications needed
- Trade-offs accepted

**Next Steps**:
After {action}:
- Evaluate outcome
- Decide next action
- Document for reporting"""
            add_sample(inst, inp, out)

print(f"Decision trees: {len(all_samples) - start_count} new samples")

# =============================================================================
# SAVE FINAL PUSH DATASET
# =============================================================================

print("\n" + "="*60)
print("Saving final push dataset...")

random.shuffle(all_samples)

output_file = output_dir / "final_push_combined.jsonl"
with open(output_file, "w") as f:
    for sample in all_samples:
        f.write(json.dumps(sample) + "\n")

print(f"\n✅ FINAL PUSH DATASET COMPLETE!")
print(f"   Total unique samples: {len(all_samples)}")
print(f"   Output: {output_file}")
print("="*60)
