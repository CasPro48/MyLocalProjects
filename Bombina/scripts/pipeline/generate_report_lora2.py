#!/usr/bin/env python3
"""
Report LoRA Dataset Expansion - Additional professional report samples
"""

import json
import hashlib
import random
from pathlib import Path

output_dir = Path(__file__).parent.parent / "data" / "report_lora"
output_dir.mkdir(parents=True, exist_ok=True)

# Load existing hashes
seen_hashes = set()
existing_file = output_dir / "report_train.jsonl"
if existing_file.exists():
    with open(existing_file) as f:
        for line in f:
            s = json.loads(line)
            content = f"{s['instruction']}|{s['input']}"
            seen_hashes.add(hashlib.md5(content.encode()).hexdigest())

all_samples = []

def add_sample(instruction, input_text, output):
    content = f"{instruction}|{input_text}"
    h = hashlib.md5(content.encode()).hexdigest()
    if h not in seen_hashes:
        seen_hashes.add(h)
        all_samples.append({"instruction": instruction, "input": input_text, "output": output})
        return True
    return False

print("Expanding Report LoRA Dataset...")
print("="*60)

# ============================================================
# 1. PENTEST REPORT INTRODUCTION (200)
# ============================================================

clients = ["financial institution", "healthcare provider", "e-commerce platform", "government agency", "technology startup"]
engagement_types = ["external penetration test", "internal penetration test", "web application assessment", "red team engagement", "cloud security assessment"]
durations = ["one week", "two weeks", "three weeks", "one month"]

for client in clients:
    for eng_type in engagement_types:
        for duration in durations:
            add_sample(
                "Write the introduction section for a pentest report",
                f"Client: {client}. Engagement: {eng_type}. Duration: {duration}.",
                f"""## 1. Introduction

### 1.1 Purpose
This report documents the findings from the {eng_type} conducted for {client}. The assessment was performed over {duration} to identify security vulnerabilities and assess the organization's security posture.

### 1.2 Engagement Overview
| Detail | Description |
|--------|-------------|
| Client | {client.title()} |
| Engagement Type | {eng_type.title()} |
| Duration | {duration.title()} |
| Report Date | [DATE] |
| Assessment Team | Bombina Security |

### 1.3 Objectives
The primary objectives of this {eng_type} were to:
1. Identify exploitable vulnerabilities in the target environment
2. Assess the effectiveness of existing security controls
3. Provide actionable remediation recommendations
4. Demonstrate potential business impact of identified risks

### 1.4 Scope
The assessment scope included systems and applications authorized by the client. All testing was conducted in accordance with the rules of engagement defined prior to the assessment.

### 1.5 Disclaimer
This assessment was conducted at a point in time and represents the security posture as of the assessment date. New vulnerabilities may emerge after this assessment. The findings should be used to improve security and not as a guarantee of security.""")

print(f"Introductions: {len(all_samples)}")
start = len(all_samples)

# ============================================================
# 2. FINDING SEVERITY EXPLANATIONS (200)
# ============================================================

severities = [
    ("Critical", "9.0-10.0", "immediate exploitation likely", "complete system compromise"),
    ("High", "7.0-8.9", "exploitation feasible", "significant data breach"),
    ("Medium", "4.0-6.9", "exploitation possible with effort", "limited data exposure"),
    ("Low", "0.1-3.9", "exploitation requires specific conditions", "minimal impact"),
    ("Informational", "0.0", "no direct exploitation", "security improvement opportunity"),
]

finding_counts = ["1 finding", "3 findings", "5 findings", "10 findings", "15+ findings"]

for sev, cvss, likelihood, impact in severities:
    for count in finding_counts:
        add_sample(
            f"Explain {sev} severity findings in a report",
            f"Severity: {sev}. CVSS range: {cvss}. Count: {count}.",
            f"""## {sev} Severity Findings

### Overview
This assessment identified **{count}** rated as **{sev}** severity.

### Severity Definition
| Attribute | Description |
|-----------|-------------|
| CVSS Range | {cvss} |
| Exploitation | {likelihood.title()} |
| Business Impact | {impact.title()} |

### Remediation Priority
{sev} severity findings should be addressed {'within 24-48 hours' if sev == 'Critical' else 'within 1-2 weeks' if sev == 'High' else 'within 1-3 months' if sev == 'Medium' else 'during regular maintenance cycles' if sev == 'Low' else 'as resources permit'}.

### Risk Context
{sev} findings represent {'the highest risk to the organization and require immediate executive attention' if sev == 'Critical' else 'significant risk requiring prompt remediation' if sev == 'High' else 'moderate risk that should be addressed in a reasonable timeframe' if sev == 'Medium' else 'lower risk but should not be ignored' if sev == 'Low' else 'opportunities for security improvement without immediate risk'}.""")

print(f"Severity explanations: {len(all_samples) - start}")
start = len(all_samples)

# ============================================================
# 3. CONCLUSION SECTIONS (200)
# ============================================================

overall_ratings = ["Poor", "Below Average", "Average", "Good", "Excellent"]
critical_counts = ["0", "1", "2-3", "4-5", "5+"]
high_counts = ["0", "1-2", "3-5", "6-10", "10+"]

for rating in overall_ratings:
    for critical in critical_counts:
        for high in high_counts:
            add_sample(
                "Write the conclusion section for a pentest report",
                f"Overall rating: {rating}. Critical findings: {critical}. High findings: {high}.",
                f"""## Conclusion

### Security Posture Assessment
Based on the findings from this penetration test, the organization's current security posture is rated as **{rating}**.

### Finding Summary
| Severity | Count |
|----------|-------|
| Critical | {critical} |
| High | {high} |
| Medium | [X] |
| Low | [X] |
| Informational | [X] |

### Key Observations

{'The presence of critical vulnerabilities indicates significant gaps in security controls that require immediate attention.' if critical != '0' else 'No critical vulnerabilities were identified, indicating effective controls against the most severe threats.'}

{'Multiple high-severity findings suggest systemic security issues that should be prioritized for remediation.' if high not in ['0', '1-2'] else 'The limited number of high-severity findings indicates reasonable security controls are in place.'}

### Recommendations Summary
1. {'Address critical vulnerabilities within 24-48 hours' if critical != '0' else 'Maintain current security controls'}
2. {'Prioritize high-severity remediation within 2 weeks' if high not in ['0'] else 'Continue security monitoring'}
3. Implement defense-in-depth strategies
4. Conduct regular security assessments
5. Enhance security awareness training

### Next Steps
- Develop remediation timeline
- Assign ownership for each finding
- Schedule re-testing after remediation
- Consider follow-up assessment in 6-12 months

### Acknowledgments
We thank the {rating.lower() if rating in ['Good', 'Excellent'] else 'organization'} team for their cooperation during this assessment.""")

print(f"Conclusions: {len(all_samples) - start}")
start = len(all_samples)

# ============================================================
# 4. SCOPE AND LIMITATIONS (150)
# ============================================================

scopes = ["web application", "internal network", "external perimeter", "Active Directory", "cloud environment"]
limitations = ["time constraints", "scope restrictions", "production environment", "testing window", "access limitations"]
exclusions = ["denial of service", "social engineering", "physical access", "third-party systems", "production data modification"]

for scope in scopes:
    for limitation in limitations:
        for exclusion in exclusions:
            add_sample(
                "Write the scope and limitations section",
                f"Scope: {scope}. Limitation: {limitation}. Exclusion: {exclusion}.",
                f"""## Scope and Limitations

### In-Scope Assets
The following were included in the assessment scope:
- **Primary Target**: {scope.title()}
- Associated infrastructure and dependencies
- User accounts and authentication systems

### Out-of-Scope
The following were explicitly excluded:
- **{exclusion.title()}**: Not permitted per rules of engagement
- Systems not owned by the client
- Third-party SaaS applications

### Testing Limitations

#### {limitation.title()}
This assessment was subject to {limitation}, which may have impacted the comprehensiveness of testing. 

**Impact**: Some vulnerabilities may not have been identified due to this constraint.

### Assumptions
- Systems tested were representative of the production environment
- Provided credentials were valid for the assessment period
- Network conditions were stable during testing

### Compensating Measures
To address limitations, the assessment team:
- Prioritized high-risk areas
- Used automated and manual testing techniques
- Documented areas requiring additional review

### Recommendation
Consider additional testing to address areas impacted by {limitation}.""")

print(f"Scope sections: {len(all_samples) - start}")
start = len(all_samples)

# ============================================================
# 5. MITRE ATT&CK MAPPING (200)
# ============================================================

tactics = [
    ("Initial Access", "TA0001", ["T1190", "T1566", "T1078"]),
    ("Execution", "TA0002", ["T1059", "T1203", "T1047"]),
    ("Persistence", "TA0003", ["T1053", "T1136", "T1505"]),
    ("Privilege Escalation", "TA0004", ["T1068", "T1548", "T1134"]),
    ("Defense Evasion", "TA0005", ["T1070", "T1027", "T1562"]),
    ("Credential Access", "TA0006", ["T1003", "T1558", "T1552"]),
    ("Discovery", "TA0007", ["T1087", "T1082", "T1083"]),
    ("Lateral Movement", "TA0008", ["T1021", "T1570", "T1080"]),
    ("Collection", "TA0009", ["T1005", "T1039", "T1114"]),
    ("Exfiltration", "TA0010", ["T1041", "T1048", "T1567"]),
]

for tactic, tactic_id, techniques in tactics:
    for technique in techniques:
        for success in ["successful", "attempted", "detected"]:
            add_sample(
                f"Map finding to MITRE ATT&CK {tactic}",
                f"Tactic: {tactic}. Technique: {technique}. Status: {success}.",
                f"""## MITRE ATT&CK Mapping

### Tactic: {tactic} ({tactic_id})

| Attribute | Value |
|-----------|-------|
| Technique ID | {technique} |
| Status | {success.title()} |
| Detection | {'Evaded' if success == 'successful' else 'Partial' if success == 'attempted' else 'Detected'} |

### Technique Description
**{technique}**: This technique was {'successfully exploited during the assessment' if success == 'successful' else 'attempted but not fully successful' if success == 'attempted' else 'attempted and detected by security controls'}.

### Attack Context
The {tactic.lower()} phase of the attack chain utilized {technique} to {'gain initial foothold' if 'Initial' in tactic else 'escalate privileges' if 'Privilege' in tactic else 'move laterally' if 'Lateral' in tactic else 'achieve tactical objective'}.

### Detection Recommendations
To detect {technique}:
- Enable logging for related events
- Configure SIEM rules for {tactic.lower()} indicators
- Implement behavioral analytics
- Review EDR coverage for this technique

### Reference
- MITRE ATT&CK: https://attack.mitre.org/techniques/{technique}/
- Detection guidance available in ATT&CK Navigator""")

print(f"MITRE mapping: {len(all_samples) - start}")
start = len(all_samples)

# ============================================================
# 6. TOOL OUTPUT INTERPRETATIONS (200)
# ============================================================

tools = [
    ("Nmap", "port scan", "open ports and services"),
    ("Burp Suite", "web scan", "web vulnerabilities"),
    ("BloodHound", "AD analysis", "attack paths"),
    ("Nuclei", "vulnerability scan", "known CVEs"),
    ("SQLMap", "SQL injection", "database access"),
    ("Responder", "LLMNR poisoning", "captured hashes"),
    ("CrackMapExec", "SMB enumeration", "network shares"),
    ("Pacu", "AWS enumeration", "IAM misconfigurations"),
]

for tool, scan_type, findings_type in tools:
    for severity in ["critical", "high", "medium", "low"]:
        for count in ["multiple", "several", "few"]:
            add_sample(
                f"Interpret {tool} output for a pentest report",
                f"Tool: {tool}. Scan type: {scan_type}. Findings: {count} {severity} {findings_type}.",
                f"""## Tool Analysis: {tool}

### Scan Type
**{scan_type.title()}**

### Summary
{tool} analysis identified **{count} {severity}** findings related to {findings_type}.

### Key Observations

The {scan_type} revealed:
- {findings_type.title()} warranting further investigation
- {'Critical exposure requiring immediate attention' if severity == 'critical' else 'Significant issues to address' if severity == 'high' else 'Moderate concerns' if severity == 'medium' else 'Minor issues'}
- Potential attack vectors identified

### Evidence
```
[{tool} output excerpt]
# {findings_type} identified
# Severity: {severity.upper()}
```

### Analysis
The {tool} results indicate {'severe security gaps' if severity in ['critical', 'high'] else 'areas for improvement'}. {count.title()} {findings_type} were identified that could be exploited by an attacker.

### Recommendations
1. Review all {findings_type} identified
2. Prioritize remediation based on risk
3. Implement compensating controls
4. Re-scan after remediation""")

print(f"Tool interpretations: {len(all_samples) - start}")

# ============================================================
# MERGE AND SAVE
# ============================================================

print(f"\n{'='*60}")
print("MERGING WITH EXISTING REPORT DATASET")
print(f"{'='*60}")

# Load existing samples
existing_samples = []
if existing_file.exists():
    with open(existing_file) as f:
        for line in f:
            existing_samples.append(json.loads(line))

existing_val = []
val_file = output_dir / "report_val.jsonl"
if val_file.exists():
    with open(val_file) as f:
        for line in f:
            existing_val.append(json.loads(line))

# Combine
all_combined = existing_samples + existing_val + all_samples
random.shuffle(all_combined)

# New split
split_idx = int(len(all_combined) * 0.95)
train = all_combined[:split_idx]
val = all_combined[split_idx:]

# Save
with open(output_dir / "report_train.jsonl", "w") as f:
    for s in train:
        f.write(json.dumps(s) + "\n")

with open(output_dir / "report_val.jsonl", "w") as f:
    for s in val:
        f.write(json.dumps(s) + "\n")

print(f"✅ Train samples: {len(train)}")
print(f"✅ Val samples: {len(val)}")
print(f"✅ TOTAL: {len(all_combined)}")
