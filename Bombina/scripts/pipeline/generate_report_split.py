#!/usr/bin/env python3
"""
Split Report LoRA into Executive and Technical datasets
- Executive: Board-level, CISO, business language
- Technical: SOC, Engineers, detailed findings
"""

import json
import hashlib
import random
from pathlib import Path

base_dir = Path(__file__).parent.parent / "data" / "report_lora"
exec_dir = base_dir / "executive"
tech_dir = base_dir / "technical"
exec_dir.mkdir(parents=True, exist_ok=True)
tech_dir.mkdir(parents=True, exist_ok=True)

seen_hashes = set()

def add_sample(samples_list, instruction, input_text, output):
    content = f"{instruction}|{input_text}"
    h = hashlib.md5(content.encode()).hexdigest()
    if h not in seen_hashes:
        seen_hashes.add(h)
        samples_list.append({"instruction": instruction, "input": input_text, "output": output})
        return True
    return False

print("="*60)
print("GENERATING SPLIT REPORT LORA DATASETS")
print("="*60)

# ============================================================
# EXECUTIVE LORA - Board/CISO Language
# ============================================================

exec_samples = []

# 1. Executive Summaries (300)
risk_levels = ["critical", "high", "moderate", "low"]
business_impacts = [
    "significant financial exposure",
    "regulatory compliance violations",
    "reputational damage",
    "operational disruption",
    "competitive disadvantage",
    "customer trust erosion"
]
strategic_recommendations = [
    "immediate security investment",
    "risk acceptance with monitoring",
    "phased remediation approach",
    "third-party security assessment",
    "security program maturation"
]

for risk in risk_levels:
    for impact in business_impacts:
        for rec in strategic_recommendations:
            add_sample(exec_samples,
                "Write an executive summary for the board of directors",
                f"Risk level: {risk}. Business impact: {impact}. Recommendation: {rec}.",
                f"""## Executive Summary

### Assessment Overview
An independent security assessment was conducted to evaluate the organization's cybersecurity posture. This report presents findings requiring board-level attention.

### Risk Posture
The assessment identified **{risk.upper()}** overall risk to the organization, primarily manifesting as {impact}.

### Key Business Implications
- **Financial**: Potential exposure from security incidents
- **Regulatory**: Compliance considerations for industry standards
- **Strategic**: Impact on business objectives and market position

### Board-Level Recommendations

**Primary Recommendation**: {rec.title()}

The security team recommends {rec} to address identified risks. This approach balances security improvement with business operational requirements.

### Investment Considerations
| Priority | Investment Area | Expected Outcome |
|----------|----------------|------------------|
| High | Security Controls | Risk reduction |
| Medium | Monitoring | Detection capability |
| Ongoing | Training | Human factor mitigation |

### Next Steps
1. Review detailed findings with CISO
2. Approve recommended security investments
3. Establish quarterly security review cadence

*This summary is intended for board consumption. Technical details available in the full assessment report.*""")

print(f"Executive summaries: {len(exec_samples)}")
start = len(exec_samples)

# 2. Risk Briefings (200)
threat_actors = ["nation-state", "cybercriminal", "insider", "hacktivist", "competitor"]
attack_vectors = ["supply chain", "phishing", "vulnerability exploitation", "credential theft", "social engineering"]
business_functions = ["finance", "operations", "customer data", "intellectual property", "executive communications"]

for actor in threat_actors:
    for vector in attack_vectors:
        for function in business_functions:
            add_sample(exec_samples,
                "Write a risk briefing for C-suite executives",
                f"Threat actor: {actor}. Attack vector: {vector}. Target: {function}.",
                f"""## Risk Briefing: {function.title()} Security

### Threat Landscape
Recent assessment identified potential exposure to {actor} threat actors targeting {function} through {vector} attacks.

### Business Context
The {function} function represents a high-value target due to:
- Strategic business importance
- Regulatory requirements
- Customer/stakeholder expectations

### Risk Quantification
| Metric | Assessment |
|--------|------------|
| Likelihood | {'High' if actor in ['cybercriminal', 'insider'] else 'Medium'} |
| Impact | {'Critical' if function in ['finance', 'customer data'] else 'High'} |
| Current Controls | Partial mitigation |

### Executive Decision Required
Management attention needed for:
1. Resource allocation for enhanced controls
2. Risk acceptance vs. mitigation decision
3. Communication strategy if incident occurs

### Recommended Actions
- **Immediate**: Validate current {function} access controls
- **30 Days**: Implement enhanced monitoring
- **90 Days**: Complete security architecture review

*Briefing prepared for executive leadership. Board notification recommended.*""")

print(f"Risk briefings: {len(exec_samples) - start}")
start = len(exec_samples)

# 3. Strategic Recommendations (200)
security_programs = ["zero trust", "security operations", "identity management", "data protection", "cloud security"]
maturity_levels = ["initial", "developing", "defined", "managed", "optimized"]
budget_ranges = ["limited", "moderate", "significant", "substantial"]

for program in security_programs:
    for maturity in maturity_levels:
        for budget in budget_ranges:
            add_sample(exec_samples,
                "Write strategic security recommendations for leadership",
                f"Program: {program}. Current maturity: {maturity}. Budget: {budget}.",
                f"""## Strategic Security Recommendation

### Program Assessment: {program.title()}
Current maturity level: **{maturity.title()}**

### Strategic Gap Analysis
The {program} program requires advancement to meet business objectives and industry expectations. Current {maturity} maturity exposes the organization to preventable risks.

### Investment Proposal
With {budget} budget allocation, the following improvements are achievable:

| Phase | Objective | Timeline | Investment |
|-------|-----------|----------|------------|
| 1 | Foundation | Q1 | 30% |
| 2 | Enhancement | Q2-Q3 | 50% |
| 3 | Optimization | Q4 | 20% |

### Business Case
**Return on Security Investment (ROSI)**:
- Risk reduction: {'60-80%' if budget in ['significant', 'substantial'] else '30-50%'}
- Compliance alignment: Industry standards
- Competitive advantage: Security as differentiator

### Success Metrics
- Reduction in security incidents
- Improved audit findings
- Enhanced stakeholder confidence

### Leadership Action Items
1. Approve {program} investment proposal
2. Assign executive sponsor
3. Establish governance framework

*Prepared for executive approval and board oversight.*""")

print(f"Strategic recommendations: {len(exec_samples) - start}")

# ============================================================
# TECHNICAL LORA - SOC/Engineer Detail
# ============================================================

tech_samples = []

# 1. Detailed Vulnerability Analysis (400)
vulns = [
    ("CVE-2024-XXXX", "SQL Injection", "CVSS 9.8", "CWE-89"),
    ("CVE-2024-YYYY", "Remote Code Execution", "CVSS 10.0", "CWE-94"),
    ("CVE-2024-ZZZZ", "Authentication Bypass", "CVSS 9.1", "CWE-287"),
    ("CVE-2024-AAAA", "Privilege Escalation", "CVSS 8.8", "CWE-269"),
    ("CVE-2024-BBBB", "Path Traversal", "CVSS 7.5", "CWE-22"),
    ("CVE-2024-CCCC", "XXE Injection", "CVSS 8.2", "CWE-611"),
    ("CVE-2024-DDDD", "SSRF", "CVSS 8.6", "CWE-918"),
    ("CVE-2024-EEEE", "Deserialization", "CVSS 9.8", "CWE-502"),
]

exploit_methods = ["manual exploitation", "Metasploit module", "custom script", "Burp Suite", "nuclei template"]
affected_systems = ["web application", "API endpoint", "internal service", "database server", "authentication system"]

for cve, vuln_type, cvss, cwe in vulns:
    for method in exploit_methods:
        for system in affected_systems:
            add_sample(tech_samples,
                f"Write a detailed technical finding for {vuln_type}",
                f"CVE: {cve}. CVSS: {cvss}. CWE: {cwe}. Method: {method}. Target: {system}.",
                f"""## Technical Finding: {vuln_type}

### Vulnerability Details
| Attribute | Value |
|-----------|-------|
| CVE | {cve} |
| CVSS | {cvss} |
| CWE | {cwe} |
| Type | {vuln_type} |
| Affected | {system} |

### Technical Description
A {vuln_type.lower()} vulnerability was identified in the {system}. This vulnerability allows an attacker to {'execute arbitrary code' if 'RCE' in vuln_type or 'Deserial' in vuln_type else 'bypass security controls' if 'Bypass' in vuln_type or 'Escalation' in vuln_type else 'access unauthorized data'}.

### Exploitation Method
**Tool/Technique**: {method}

#### Proof of Concept
```
# {vuln_type} exploitation against {system}
# Method: {method}

# Step 1: Identify vulnerable endpoint
# Step 2: Craft malicious payload
# Step 3: Execute attack
# Step 4: Verify exploitation

# Example payload:
{{"payload": "example_{vuln_type.lower().replace(' ', '_')}_poc"}}
```

### Technical Impact
- **Confidentiality**: {'Complete' if 'SQL' in vuln_type or 'Traversal' in vuln_type else 'Partial'}
- **Integrity**: {'Complete' if 'RCE' in vuln_type or 'Deserial' in vuln_type else 'Partial'}
- **Availability**: {'Complete' if 'RCE' in vuln_type else 'None'}

### Attack Vector Analysis
1. **Prerequisites**: {'Unauthenticated' if 'Bypass' in vuln_type else 'Low privilege access'}
2. **Complexity**: {'Low' if method == 'Metasploit module' else 'Medium'}
3. **User Interaction**: None required

### Detection Signatures
```
# SIEM/IDS Detection Rule
alert tcp any any -> any any (msg:"{vuln_type} attempt"; content:"suspicious_pattern"; sid:1000001;)
```

### Remediation Steps
1. Apply vendor patch for {cve}
2. Implement input validation for {system}
3. Deploy WAF rules to block exploitation attempts
4. Enable logging for detection
5. Conduct post-remediation verification

### References
- NVD: https://nvd.nist.gov/vuln/detail/{cve}
- CWE: https://cwe.mitre.org/data/definitions/{cwe.split('-')[1]}.html
- Vendor Advisory: [Link]""")

print(f"Technical vulnerability analysis: {len(tech_samples)}")
start = len(tech_samples)

# 2. Attack Chain Documentation (300)
attack_phases = [
    ("Initial Access", "T1190", "Exploit public-facing application"),
    ("Execution", "T1059", "Command and scripting interpreter"),
    ("Persistence", "T1053", "Scheduled task/job"),
    ("Privilege Escalation", "T1068", "Exploitation for privilege escalation"),
    ("Defense Evasion", "T1070", "Indicator removal"),
    ("Credential Access", "T1003", "OS credential dumping"),
    ("Discovery", "T1087", "Account discovery"),
    ("Lateral Movement", "T1021", "Remote services"),
    ("Collection", "T1005", "Data from local system"),
    ("Exfiltration", "T1041", "Exfiltration over C2 channel"),
]

for i in range(len(attack_phases) - 2):
    phase1 = attack_phases[i]
    phase2 = attack_phases[i+1]
    phase3 = attack_phases[i+2]
    
    for env in ["Windows", "Linux", "Cloud"]:
        add_sample(tech_samples,
            "Document attack chain with MITRE ATT&CK mapping",
            f"Environment: {env}. Phases: {phase1[0]} → {phase2[0]} → {phase3[0]}",
            f"""## Attack Chain Analysis

### Environment
**Target**: {env} Infrastructure

### Attack Progression

#### Phase 1: {phase1[0]}
| Attribute | Details |
|-----------|---------|
| MITRE ID | {phase1[1]} |
| Technique | {phase1[2]} |
| Evidence | Logs showing initial compromise |

**Technical Details**:
```
# {env} - {phase1[0]} evidence
# Timestamp: [REDACTED]
# Source: [ATTACKER_IP]
```

#### Phase 2: {phase2[0]}
| Attribute | Details |
|-----------|---------|
| MITRE ID | {phase2[1]} |
| Technique | {phase2[2]} |
| Time Delta | +15 minutes |

**Technical Details**:
```
# {env} - {phase2[0]} indicators
# Process tree analysis
# Command line artifacts
```

#### Phase 3: {phase3[0]}
| Attribute | Details |
|-----------|---------|
| MITRE ID | {phase3[1]} |
| Technique | {phase3[2]} |
| Time Delta | +45 minutes |

**Technical Details**:
```
# {env} - {phase3[0]} artifacts
# Persistence mechanism identified
```

### Detection Opportunities
| Phase | Detection Source | Alert Type |
|-------|-----------------|------------|
| {phase1[0]} | WAF/IDS | Exploit attempt |
| {phase2[0]} | EDR | Process anomaly |
| {phase3[0]} | SIEM | Behavioral |

### Forensic Artifacts
- **{env} Logs**: Authentication, process creation
- **Network**: C2 communication patterns
- **Memory**: Malicious code artifacts

### IOCs
```
# Indicators of Compromise
IP: [ATTACKER_IPS]
Hash: [MALWARE_HASHES]
Domain: [C2_DOMAINS]
```

### Recommendations
1. Implement detection for {phase1[1]}
2. Block techniques associated with {phase2[1]}
3. Monitor for {phase3[1]} indicators""")

print(f"Attack chain documentation: {len(tech_samples) - start}")
start = len(tech_samples)

# 3. Remediation Technical Guides (300)
remediation_types = [
    ("Input Validation", "parameterized queries", "prepared statements"),
    ("Authentication Hardening", "MFA implementation", "session management"),
    ("Network Segmentation", "firewall rules", "VLAN configuration"),
    ("Endpoint Protection", "EDR deployment", "application whitelisting"),
    ("Logging Enhancement", "SIEM integration", "log forwarding"),
    ("Patch Management", "vulnerability scanning", "automated patching"),
]

platforms = ["Windows Server", "Linux", "AWS", "Azure", "Kubernetes"]

for rem_type, method1, method2 in remediation_types:
    for platform in platforms:
        add_sample(tech_samples,
            f"Write technical remediation guide for {rem_type}",
            f"Platform: {platform}. Methods: {method1}, {method2}.",
            f"""## Technical Remediation: {rem_type}

### Platform
**Target**: {platform}

### Implementation Guide

#### Method 1: {method1.title()}

**Configuration Steps**:
```
# {platform} - {method1} implementation

# Step 1: Backup current configuration
# Step 2: Apply security settings
# Step 3: Validate changes
# Step 4: Monitor for issues

# Example configuration:
{platform.lower().replace(' ', '_')}_config:
  {method1.replace(' ', '_')}:
    enabled: true
    strict_mode: true
```

#### Method 2: {method2.title()}

**Configuration Steps**:
```
# {platform} - {method2} implementation

# Deployment commands
# Verification commands
# Rollback procedure
```

### Verification Testing
```
# Test {rem_type} effectiveness

# 1. Pre-remediation baseline
# 2. Apply remediation
# 3. Post-remediation validation
# 4. Document results

# Expected output: Vulnerability mitigated
```

### Monitoring
Configure alerts for:
- Configuration drift
- Bypass attempts
- Performance impact

### Rollback Procedure
```
# Emergency rollback for {platform}
# Execute if remediation causes issues

# 1. Stop affected services
# 2. Restore backup configuration
# 3. Restart services
# 4. Verify functionality
```

### Success Criteria
- [ ] Vulnerability scan shows remediated
- [ ] No functional regression
- [ ] Monitoring in place
- [ ] Documentation updated""")

print(f"Technical remediation guides: {len(tech_samples) - start}")

# ============================================================
# SAVE DATASETS
# ============================================================

print(f"\n{'='*60}")
print("SAVING SPLIT REPORT LORA DATASETS")
print(f"{'='*60}")

# Save Executive LoRA
random.shuffle(exec_samples)
split_idx = int(len(exec_samples) * 0.95)
exec_train = exec_samples[:split_idx]
exec_val = exec_samples[split_idx:]

with open(exec_dir / "exec_train.jsonl", "w") as f:
    for s in exec_train:
        f.write(json.dumps(s) + "\n")

with open(exec_dir / "exec_val.jsonl", "w") as f:
    for s in exec_val:
        f.write(json.dumps(s) + "\n")

print(f"\n📊 Executive LoRA Dataset:")
print(f"   Train: {len(exec_train)} samples")
print(f"   Val: {len(exec_val)} samples")
print(f"   Output: {exec_dir}")

# Save Technical LoRA
random.shuffle(tech_samples)
split_idx = int(len(tech_samples) * 0.95)
tech_train = tech_samples[:split_idx]
tech_val = tech_samples[split_idx:]

with open(tech_dir / "tech_train.jsonl", "w") as f:
    for s in tech_train:
        f.write(json.dumps(s) + "\n")

with open(tech_dir / "tech_val.jsonl", "w") as f:
    for s in tech_val:
        f.write(json.dumps(s) + "\n")

print(f"\n📊 Technical LoRA Dataset:")
print(f"   Train: {len(tech_train)} samples")
print(f"   Val: {len(tech_val)} samples")
print(f"   Output: {tech_dir}")

print(f"\n✅ TOTAL REPORT SAMPLES: {len(exec_samples) + len(tech_samples)}")
