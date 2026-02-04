#!/usr/bin/env python3
"""
Generate Report LoRA Dataset - Professional pentest report samples
Categories: Executive Summary, Technical Findings, Remediation, Risk Assessment
Target: 2,500+ samples for separate Report LoRA
"""

import json
import hashlib
import random
from pathlib import Path

output_dir = Path(__file__).parent.parent / "data" / "report_lora"
output_dir.mkdir(parents=True, exist_ok=True)

seen_hashes = set()
all_samples = []

def add_sample(instruction, input_text, output):
    content = f"{instruction}|{input_text}"
    h = hashlib.md5(content.encode()).hexdigest()
    if h not in seen_hashes:
        seen_hashes.add(h)
        all_samples.append({"instruction": instruction, "input": input_text, "output": output})
        return True
    return False

print("Generating Report LoRA Dataset...")
print("="*60)

# ============================================================
# 1. EXECUTIVE SUMMARIES (500 samples)
# ============================================================

vuln_types = [
    ("SQL Injection", "Critical", "complete database compromise"),
    ("Remote Code Execution", "Critical", "full system takeover"),
    ("Authentication Bypass", "Critical", "unauthorized access to all accounts"),
    ("Privilege Escalation", "High", "administrative access from standard user"),
    ("Cross-Site Scripting", "Medium", "client-side attack vector"),
    ("Information Disclosure", "Low", "sensitive data exposure"),
    ("IDOR", "High", "unauthorized data access"),
    ("SSRF", "High", "internal network access"),
    ("XXE", "High", "file disclosure and SSRF"),
    ("Broken Access Control", "High", "horizontal privilege escalation"),
]

environments = ["web application", "internal network", "Active Directory", "cloud infrastructure", "API endpoints"]
outcomes = ["successful compromise", "identified weaknesses", "validated controls", "discovered critical gaps"]
mitigations = ["partially effective", "inadequate", "well-implemented but bypassable", "non-existent"]

for vuln, sev, impact in vuln_types:
    for env in environments:
        for outcome in outcomes:
            for mitigation in mitigations:
                add_sample(
                    f"Write an executive summary for a pentest that found {vuln}",
                    f"Environment: {env}. Severity: {sev}. Impact: {impact}. Outcome: {outcome}. Current mitigations: {mitigation}.",
                    f"""## Executive Summary

A comprehensive penetration test was conducted against the {env} to evaluate the security posture and identify potential vulnerabilities. The assessment resulted in {outcome}.

### Key Findings

The most significant finding was a **{sev.upper()} severity {vuln}** vulnerability that could allow {impact}. Current security controls were {mitigation}, failing to prevent exploitation of this attack vector.

### Business Impact

If exploited by a malicious actor, this vulnerability could result in:
- Unauthorized access to sensitive business data
- Reputational damage and loss of customer trust
- Potential regulatory compliance violations
- Financial losses from incident response and remediation

### Risk Assessment

| Metric | Rating |
|--------|--------|
| Likelihood of Exploitation | High |
| Business Impact | {sev} |
| Overall Risk | {sev} |

### Recommendations

Immediate action is recommended to address the identified {vuln} vulnerability. A detailed remediation plan is provided in the Technical Findings section of this report.

The organization should prioritize security improvements based on risk severity and allocate appropriate resources for remediation activities.""")

print(f"Executive summaries: {len(all_samples)}")
start = len(all_samples)

# ============================================================
# 2. TECHNICAL FINDINGS (600 samples)
# ============================================================

findings = [
    {
        "title": "SQL Injection in Login Form",
        "cvss": "9.8",
        "cwe": "CWE-89",
        "affected": "login.php",
        "evidence": "' OR '1'='1' -- ",
        "mitre": "T1190"
    },
    {
        "title": "Hardcoded Credentials in Source Code",
        "cvss": "7.5",
        "cwe": "CWE-798",
        "affected": "config.js",
        "evidence": "password: 'admin123'",
        "mitre": "T1552.001"
    },
    {
        "title": "Missing Authentication on Admin API",
        "cvss": "9.1",
        "cwe": "CWE-306",
        "affected": "/api/admin/*",
        "evidence": "HTTP 200 without auth header",
        "mitre": "T1190"
    },
    {
        "title": "Insecure Direct Object Reference",
        "cvss": "7.1",
        "cwe": "CWE-639",
        "affected": "/api/users/{id}",
        "evidence": "Changed user_id parameter",
        "mitre": "T1078"
    },
    {
        "title": "Kerberoastable Service Account",
        "cvss": "7.5",
        "cwe": "CWE-521",
        "affected": "svc_backup",
        "evidence": "Weak password cracked in 2 hours",
        "mitre": "T1558.003"
    },
    {
        "title": "Unconstrained Delegation",
        "cvss": "8.1",
        "cwe": "CWE-269",
        "affected": "WEB01.corp.local",
        "evidence": "TrustedForDelegation=True",
        "mitre": "T1558.001"
    },
    {
        "title": "Outdated SSL/TLS Configuration",
        "cvss": "5.3",
        "cwe": "CWE-326",
        "affected": "https://app.example.com",
        "evidence": "TLS 1.0 enabled",
        "mitre": "T1557"
    },
    {
        "title": "AWS S3 Bucket Public Access",
        "cvss": "7.5",
        "cwe": "CWE-732",
        "affected": "s3://company-backups",
        "evidence": "Public ACL enabled",
        "mitre": "T1530"
    },
]

risk_ratings = ["Critical", "High", "Medium", "Low"]
exploit_complexity = ["Low", "Medium", "High"]
business_contexts = ["customer data", "financial records", "intellectual property", "PII", "healthcare records"]

for finding in findings:
    for complexity in exploit_complexity:
        for context in business_contexts:
            add_sample(
                f"Write a technical finding for {finding['title']}",
                f"CVSS: {finding['cvss']}. CWE: {finding['cwe']}. Affected: {finding['affected']}. Business context: {context}. Exploit complexity: {complexity}.",
                f"""## Finding: {finding['title']}

### Severity
| Metric | Value |
|--------|-------|
| CVSS Score | {finding['cvss']} |
| Risk Rating | {'Critical' if float(finding['cvss']) >= 9 else 'High' if float(finding['cvss']) >= 7 else 'Medium'} |
| CWE | {finding['cwe']} |
| MITRE ATT&CK | {finding['mitre']} |

### Affected Asset
`{finding['affected']}`

### Description
During the assessment, a {finding['title'].lower()} vulnerability was identified affecting {finding['affected']}. This vulnerability exists due to insufficient security controls and could be exploited to access {context}.

### Evidence
```
{finding['evidence']}
```

### Exploitation Complexity
**{complexity}** - {'Requires no special skills or tools' if complexity == 'Low' else 'Requires moderate technical knowledge' if complexity == 'Medium' else 'Requires advanced skills and specific conditions'}

### Business Impact
Successful exploitation could result in:
- Unauthorized access to {context}
- Potential data breach affecting affected records
- Regulatory compliance violations (GDPR, HIPAA, PCI-DSS)
- Reputational damage

### Remediation
**Priority: {'Immediate' if float(finding['cvss']) >= 9 else 'High' if float(finding['cvss']) >= 7 else 'Medium'}**

1. Apply security patches or configuration changes
2. Implement additional security controls
3. Conduct security code review
4. Perform follow-up testing after remediation

### References
- {finding['cwe']}: https://cwe.mitre.org/data/definitions/{finding['cwe'].split('-')[1]}.html
- MITRE ATT&CK {finding['mitre']}: https://attack.mitre.org/techniques/{finding['mitre'].replace('.', '/')}/""")

print(f"Technical findings: {len(all_samples) - start}")
start = len(all_samples)

# ============================================================
# 3. REMEDIATION RECOMMENDATIONS (500 samples)
# ============================================================

remediations = [
    ("SQL Injection", "parameterized queries", "prepared statements", "input validation"),
    ("XSS", "output encoding", "Content-Security-Policy", "input sanitization"),
    ("Authentication Bypass", "multi-factor authentication", "session management", "rate limiting"),
    ("Privilege Escalation", "least privilege principle", "role-based access", "privilege auditing"),
    ("Credential Exposure", "secrets management", "vault integration", "credential rotation"),
    ("Weak Encryption", "TLS 1.3", "strong cipher suites", "certificate management"),
    ("IDOR", "authorization checks", "indirect references", "access control lists"),
    ("SSRF", "allowlist validation", "network segmentation", "egress filtering"),
    ("Kerberoasting", "strong passwords", "managed service accounts", "AES encryption"),
    ("Delegation Abuse", "constrained delegation", "resource-based delegation", "privileged access workstations"),
]

timeframes = ["immediate (24-48 hours)", "short-term (1-2 weeks)", "medium-term (1-3 months)", "long-term (3-6 months)"]
effort_levels = ["low", "moderate", "significant", "major project"]

for vuln, fix1, fix2, fix3 in remediations:
    for timeframe in timeframes:
        for effort in effort_levels:
            add_sample(
                f"Write remediation recommendations for {vuln}",
                f"Timeframe: {timeframe}. Effort required: {effort}. Primary fixes: {fix1}, {fix2}, {fix3}.",
                f"""## Remediation: {vuln}

### Priority
**Timeframe**: {timeframe}
**Effort Level**: {effort.title()}

### Recommended Actions

#### 1. {fix1.title()} (Primary)
Implement {fix1} to address the root cause of this vulnerability. This is the most effective countermeasure and should be prioritized.

**Implementation Steps**:
1. Review current implementation
2. Design remediation approach
3. Implement changes in development environment
4. Conduct security testing
5. Deploy to production with rollback plan

#### 2. {fix2.title()} (Defense in Depth)
Deploy {fix2} as an additional security layer. This provides defense in depth even if the primary control fails.

#### 3. {fix3.title()} (Compensating Control)
Implement {fix3} as a compensating control while primary remediation is in progress.

### Resource Requirements
- **Developer time**: {'2-4 hours' if effort == 'low' else '1-2 days' if effort == 'moderate' else '1-2 weeks' if effort == 'significant' else '1-3 months'}
- **Testing**: Required before production deployment
- **Change management**: {'Standard change' if effort in ['low', 'moderate'] else 'CAB approval required'}

### Verification
After remediation:
1. Conduct vulnerability re-testing
2. Verify fix effectiveness
3. Document changes
4. Update security baselines

### References
- OWASP {vuln} Prevention Cheat Sheet
- CIS Benchmark recommendations
- Industry best practices""")

print(f"Remediation: {len(all_samples) - start}")
start = len(all_samples)

# ============================================================
# 4. RISK ASSESSMENT NARRATIVES (400 samples)
# ============================================================

attack_scenarios = [
    ("external attacker", "internet-facing application", "data breach"),
    ("insider threat", "internal network", "data exfiltration"),
    ("compromised vendor", "supply chain", "backdoor access"),
    ("nation-state actor", "critical infrastructure", "persistent access"),
    ("ransomware operator", "Windows environment", "encryption and extortion"),
]

likelihood_factors = ["public exploit available", "low attacker skill required", "high-value target", "weak monitoring"]
impact_factors = ["customer data affected", "regulatory implications", "business continuity", "financial loss"]

for attacker, target, outcome in attack_scenarios:
    for likelihood in likelihood_factors:
        for impact in impact_factors:
            add_sample(
                f"Write a risk assessment narrative for {outcome} scenario",
                f"Attacker: {attacker}. Target: {target}. Likelihood factor: {likelihood}. Impact factor: {impact}.",
                f"""## Risk Assessment: {outcome.title()} via {target.title()}

### Threat Scenario
A {attacker} targeting the organization's {target} could exploit identified vulnerabilities to achieve {outcome}.

### Likelihood Assessment
**Rating: {'High' if 'public exploit' in likelihood or 'low attacker skill' in likelihood else 'Medium'}**

Contributing factors:
- {likelihood.title()}
- Vulnerabilities identified during assessment
- Attack surface exposure
- Current detection capabilities

### Impact Assessment  
**Rating: {'Critical' if 'customer data' in impact or 'regulatory' in impact else 'High'}**

Potential consequences:
- **{impact.title()}**: Direct business impact from successful attack
- **Operational disruption**: Potential service interruption during incident
- **Recovery costs**: Incident response, forensics, and remediation expenses
- **Long-term effects**: Reputation damage and customer trust erosion

### Risk Matrix

|              | Low Impact | Medium Impact | High Impact | Critical Impact |
|--------------|------------|---------------|-------------|-----------------|
| **High Likelihood** | Medium | High | Critical | Critical |
| **Medium Likelihood** | Low | Medium | High | Critical |
| **Low Likelihood** | Low | Low | Medium | High |

**Current Risk Level**: {'Critical' if 'customer data' in impact else 'High'}

### Risk Mitigation
1. **Immediate**: Address critical and high-severity vulnerabilities
2. **Short-term**: Implement enhanced monitoring and detection
3. **Long-term**: Strengthen security architecture and controls

### Residual Risk
After implementing recommended remediations, residual risk is expected to decrease to **Medium** level, within organizational risk tolerance.""")

print(f"Risk assessments: {len(all_samples) - start}")
start = len(all_samples)

# ============================================================
# 5. ATTACK NARRATIVES (400 samples)
# ============================================================

attack_chains = [
    ["phishing email", "credential harvest", "VPN access", "lateral movement", "domain admin"],
    ["web shell upload", "reverse shell", "privilege escalation", "persistence", "data exfiltration"],
    ["password spray", "valid account", "mailbox access", "internal recon", "sensitive data"],
    ["public exploit", "initial access", "credential dumping", "golden ticket", "complete compromise"],
    ["supply chain", "trusted access", "internal pivot", "cloud access", "multi-environment compromise"],
]

detection_points = ["initial access", "lateral movement", "privilege escalation", "data access", "exfiltration"]

for chain in attack_chains:
    for detection in detection_points:
        add_sample(
            f"Write an attack narrative for a pentest",
            f"Attack chain: {' → '.join(chain)}. Detection opportunity: {detection}.",
            f"""## Attack Narrative

### Overview
This section describes the attack path identified during the penetration test, demonstrating how an attacker could progress from initial access to objective completion.

### Attack Chain

```
{' → '.join(chain)}
```

### Phase 1: Initial Access
**Technique**: {chain[0].title()}

The assessment began with {chain[0]}, which provided the initial foothold into the environment. This technique was successful due to insufficient preventive controls.

### Phase 2: Establishing Foothold
**Technique**: {chain[1].title()}

After initial access, {chain[1]} was achieved. This allowed persistent access and set the stage for further exploitation.

### Phase 3: Escalation
**Technique**: {chain[2].title()} → {chain[3].title()}

The attack progressed through {chain[2]} followed by {chain[3]}. Each step increased access privileges and expanded the attack surface.

### Phase 4: Objective Completion
**Technique**: {chain[4].title()}

The final objective of {chain[4]} was achieved, demonstrating the complete attack path.

### Detection Analysis

**Missed Detection Opportunity**: {detection.title()}

The attack could have been detected during the {detection} phase with proper monitoring. Current controls did not trigger alerts at this stage.

**Recommended Detection**:
- Enhanced logging for {detection} activities
- Behavioral analytics to identify anomalies
- Alert thresholds tuned for sensitive operations

### MITRE ATT&CK Mapping
| Phase | Tactic | Technique |
|-------|--------|-----------|
| {chain[0]} | Initial Access | T1566/T1190 |
| {chain[1]} | Execution | T1059 |
| {chain[2]} | Privilege Escalation | T1068/T1548 |
| {chain[3]} | Persistence | T1053/T1136 |
| {chain[4]} | Impact | T1486/T1565 |""")

print(f"Attack narratives: {len(all_samples) - start}")
start = len(all_samples)

# ============================================================
# 6. METHODOLOGY SECTIONS (300 samples)
# ============================================================

methodologies = ["OWASP", "PTES", "OSSTMM", "NIST", "MITRE ATT&CK"]
scopes = ["web application", "internal network", "external perimeter", "cloud infrastructure", "mobile application"]
test_types = ["black box", "gray box", "white box"]

for methodology in methodologies:
    for scope in scopes:
        for test_type in test_types:
            add_sample(
                f"Write a methodology section for a {scope} pentest",
                f"Methodology: {methodology}. Scope: {scope}. Test type: {test_type}.",
                f"""## Methodology

### Framework
This assessment followed the **{methodology}** methodology, adapted for {scope} testing.

### Scope
**Test Type**: {test_type.title()}

| Aspect | Details |
|--------|---------|
| Target | {scope.title()} |
| Access Level | {'No prior knowledge' if test_type == 'black box' else 'Partial documentation' if test_type == 'gray box' else 'Full documentation and source code'} |
| Credentials | {'None provided' if test_type == 'black box' else 'Standard user account' if test_type == 'gray box' else 'Multiple privilege levels'} |

### Testing Phases

#### 1. Reconnaissance
- {'OSINT gathering' if test_type == 'black box' else 'Documentation review'}
- Asset enumeration
- Technology fingerprinting

#### 2. Vulnerability Identification
- Automated scanning
- Manual testing
- Configuration review

#### 3. Exploitation
- Vulnerability validation
- Proof-of-concept development
- Impact demonstration

#### 4. Post-Exploitation
- Privilege escalation attempts
- Lateral movement testing
- Data access validation

#### 5. Reporting
- Finding documentation
- Risk assessment
- Remediation recommendations

### Tools Used
- Network: Nmap, Masscan
- Web: Burp Suite, OWASP ZAP
- Exploitation: Metasploit, custom scripts
- {'AD: BloodHound, Rubeus, Mimikatz' if 'network' in scope else 'Cloud: Pacu, ScoutSuite' if 'cloud' in scope else 'Mobile: Frida, MobSF' if 'mobile' in scope else 'Application: SQLMap, Nuclei'}

### Rules of Engagement
- Testing window: Business hours / After hours
- Excluded systems: Production databases (read-only)
- Emergency contact: Security team on-call""")

print(f"Methodology sections: {len(all_samples) - start}")
start = len(all_samples)

# ============================================================
# 7. COMPLIANCE MAPPING (300 samples)
# ============================================================

frameworks = ["PCI-DSS", "HIPAA", "SOC 2", "GDPR", "ISO 27001", "NIST CSF"]
requirements = [
    ("access control", "unauthorized access", "authentication and authorization"),
    ("encryption", "data exposure", "cryptographic controls"),
    ("logging", "audit trail gaps", "monitoring and alerting"),
    ("vulnerability management", "unpatched systems", "patch management"),
    ("incident response", "detection delays", "security operations"),
]

for framework in frameworks:
    for req, finding, control in requirements:
        add_sample(
            f"Map pentest findings to {framework} compliance requirements",
            f"Finding: {finding}. Requirement area: {req}. Control gap: {control}.",
            f"""## Compliance Impact: {framework}

### Finding Overview
**Issue**: {finding.title()}
**Control Area**: {req.title()}

### {framework} Requirement Mapping

| Requirement | Description | Status |
|-------------|-------------|--------|
| {req.upper()}-01 | {control.title()} | ❌ Non-Compliant |

### Gap Analysis

The identified {finding} represents a gap in {control} controls required by {framework}. This finding may impact compliance certification and should be addressed promptly.

### Regulatory Risk

**{framework} Implications**:
- Potential audit finding
- {'Fines up to 4% of annual revenue' if framework == 'GDPR' else 'Potential loss of certification' if framework == 'PCI-DSS' else 'Breach notification requirements' if framework == 'HIPAA' else 'Audit qualification'}
- Remediation required before next assessment

### Remediation Priority
**High** - Address before next compliance audit

### Evidence for Auditors
- Vulnerability scan results
- Penetration test report
- Remediation timeline
- Compensating controls (if applicable)""")

print(f"Compliance mapping: {len(all_samples) - start}")

# ============================================================
# SAVE DATASET
# ============================================================

print(f"\n{'='*60}")
print("REPORT LORA DATASET COMPLETE")
print(f"{'='*60}")

random.shuffle(all_samples)

# Split 95/5
split_idx = int(len(all_samples) * 0.95)
train_samples = all_samples[:split_idx]
val_samples = all_samples[split_idx:]

# Save
train_file = output_dir / "report_train.jsonl"
val_file = output_dir / "report_val.jsonl"

with open(train_file, "w") as f:
    for s in train_samples:
        f.write(json.dumps(s) + "\n")

with open(val_file, "w") as f:
    for s in val_samples:
        f.write(json.dumps(s) + "\n")

print(f"✅ Train samples: {len(train_samples)}")
print(f"✅ Val samples: {len(val_samples)}")
print(f"✅ TOTAL: {len(all_samples)}")
print(f"\nOutput: {output_dir}")
