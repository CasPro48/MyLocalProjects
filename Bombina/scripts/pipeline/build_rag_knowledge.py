#!/usr/bin/env python3
"""
Bombina RAG Expansion System
Fetches and indexes:
- CVE database
- Exploit-DB exploits
- Tool documentation
- MITRE ATT&CK techniques

For use with local FAISS/Chroma vector DB
"""

import json
import hashlib
import requests
import time
from pathlib import Path
from datetime import datetime, timedelta
from typing import List, Dict, Optional
import subprocess

class RAGKnowledgeBuilder:
    """Build and maintain RAG knowledge base for Bombina"""
    
    def __init__(self, base_dir: str):
        self.base_dir = Path(base_dir)
        self.cve_dir = self.base_dir / "cves"
        self.exploits_dir = self.base_dir / "exploits"
        self.tools_dir = self.base_dir / "tools"
        self.mitre_dir = self.base_dir / "mitre"
        
        # Create directories
        for d in [self.cve_dir, self.exploits_dir, self.tools_dir, self.mitre_dir]:
            d.mkdir(parents=True, exist_ok=True)
        
        self.index = []
    
    # =========================================================
    # CVE FETCHING
    # =========================================================
    
    def fetch_recent_cves(self, days: int = 90, max_results: int = 500) -> List[Dict]:
        """Fetch recent CVEs from NVD API"""
        print(f"\n📥 Fetching CVEs from last {days} days...")
        
        end_date = datetime.now()
        start_date = end_date - timedelta(days=days)
        
        # NVD API 2.0
        base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        params = {
            "pubStartDate": start_date.strftime("%Y-%m-%dT00:00:00.000"),
            "pubEndDate": end_date.strftime("%Y-%m-%dT23:59:59.999"),
            "resultsPerPage": min(max_results, 2000)
        }
        
        cves = []
        try:
            response = requests.get(base_url, params=params, timeout=30)
            if response.status_code == 200:
                data = response.json()
                vulnerabilities = data.get("vulnerabilities", [])
                
                for vuln in vulnerabilities[:max_results]:
                    cve_data = vuln.get("cve", {})
                    cve_id = cve_data.get("id", "")
                    
                    # Extract description
                    descriptions = cve_data.get("descriptions", [])
                    description = ""
                    for desc in descriptions:
                        if desc.get("lang") == "en":
                            description = desc.get("value", "")
                            break
                    
                    # Extract CVSS
                    metrics = cve_data.get("metrics", {})
                    cvss_score = "N/A"
                    severity = "N/A"
                    
                    if "cvssMetricV31" in metrics:
                        cvss_data = metrics["cvssMetricV31"][0]["cvssData"]
                        cvss_score = cvss_data.get("baseScore", "N/A")
                        severity = cvss_data.get("baseSeverity", "N/A")
                    elif "cvssMetricV30" in metrics:
                        cvss_data = metrics["cvssMetricV30"][0]["cvssData"]
                        cvss_score = cvss_data.get("baseScore", "N/A")
                        severity = cvss_data.get("baseSeverity", "N/A")
                    
                    # Extract weaknesses (CWE)
                    weaknesses = cve_data.get("weaknesses", [])
                    cwes = []
                    for weakness in weaknesses:
                        for desc in weakness.get("description", []):
                            if desc.get("value", "").startswith("CWE-"):
                                cwes.append(desc.get("value"))
                    
                    cve_entry = {
                        "id": cve_id,
                        "description": description,
                        "cvss_score": cvss_score,
                        "severity": severity,
                        "cwes": cwes,
                        "published": cve_data.get("published", ""),
                        "type": "cve"
                    }
                    cves.append(cve_entry)
                
                print(f"   ✓ Fetched {len(cves)} CVEs")
            else:
                print(f"   ✗ API error: {response.status_code}")
        except Exception as e:
            print(f"   ✗ Error fetching CVEs: {e}")
        
        return cves
    
    def save_cves(self, cves: List[Dict]):
        """Save CVEs to knowledge base"""
        output_file = self.cve_dir / "cves.jsonl"
        
        with open(output_file, "w") as f:
            for cve in cves:
                # Create RAG-friendly document
                doc = {
                    "id": cve["id"],
                    "type": "cve",
                    "title": f"{cve['id']} - {cve['severity']} ({cve['cvss_score']})",
                    "content": f"""CVE: {cve['id']}
Severity: {cve['severity']} (CVSS: {cve['cvss_score']})
CWE: {', '.join(cve['cwes']) if cve['cwes'] else 'N/A'}
Published: {cve['published']}

Description:
{cve['description']}

Security Implications:
- Severity level indicates {'critical risk requiring immediate attention' if cve['severity'] == 'CRITICAL' else 'high risk requiring prompt remediation' if cve['severity'] == 'HIGH' else 'moderate risk' if cve['severity'] == 'MEDIUM' else 'lower risk'}
- Check vendor advisories for patches
- Implement compensating controls if patch unavailable""",
                    "metadata": {
                        "cvss": cve["cvss_score"],
                        "severity": cve["severity"],
                        "cwes": cve["cwes"]
                    }
                }
                f.write(json.dumps(doc) + "\n")
                self.index.append(doc)
        
        print(f"   💾 Saved to {output_file}")
    
    # =========================================================
    # EXPLOIT-DB (Local samples since API requires auth)
    # =========================================================
    
    def generate_exploit_samples(self, count: int = 200) -> List[Dict]:
        """Generate exploit knowledge samples (real exploits would come from exploit-db)"""
        print(f"\n📥 Generating {count} exploit knowledge samples...")
        
        # Real-world exploit categories
        exploit_types = [
            {
                "category": "Web Application",
                "techniques": ["SQL Injection", "XSS", "RCE", "LFI", "SSRF", "XXE", "Deserialization"],
                "tools": ["sqlmap", "burpsuite", "nuclei", "ffuf"]
            },
            {
                "category": "Windows",
                "techniques": ["Privilege Escalation", "Token Manipulation", "DLL Hijacking", "Service Exploitation"],
                "tools": ["mimikatz", "rubeus", "seatbelt", "winpeas"]
            },
            {
                "category": "Linux",
                "techniques": ["SUID Abuse", "Kernel Exploits", "Cron Jobs", "Sudo Misconfig"],
                "tools": ["linpeas", "pspy", "linux-exploit-suggester"]
            },
            {
                "category": "Active Directory",
                "techniques": ["Kerberoasting", "AS-REP Roasting", "DCSync", "Golden Ticket", "ADCS Abuse"],
                "tools": ["bloodhound", "crackmapexec", "impacket", "certipy"]
            },
            {
                "category": "Network",
                "techniques": ["LLMNR Poisoning", "SMB Relay", "ARP Spoofing", "MITM"],
                "tools": ["responder", "ntlmrelayx", "bettercap", "wireshark"]
            }
        ]
        
        exploits = []
        for exp_type in exploit_types:
            for technique in exp_type["techniques"]:
                for tool in exp_type["tools"]:
                    exploit_doc = {
                        "id": f"exploit_{exp_type['category'].lower().replace(' ', '_')}_{technique.lower().replace(' ', '_')}",
                        "type": "exploit",
                        "title": f"{exp_type['category']} - {technique}",
                        "content": f"""Exploit Category: {exp_type['category']}
Technique: {technique}
Primary Tool: {tool}

Overview:
{technique} is a {'critical' if technique in ['RCE', 'DCSync', 'Golden Ticket'] else 'significant'} attack technique targeting {exp_type['category'].lower()} environments.

Attack Methodology:
1. Reconnaissance - Identify vulnerable targets
2. Preparation - Configure exploitation tools
3. Exploitation - Execute {technique.lower()} attack
4. Post-Exploitation - Maintain access, escalate privileges

Tool Usage ({tool}):
```
# Basic {tool} usage for {technique}
# Syntax varies based on specific target
# Always verify scope authorization before testing
```

Detection Indicators:
- Log sources: {'Windows Event Logs' if exp_type['category'] in ['Windows', 'Active Directory'] else 'System logs, Web logs' if exp_type['category'] == 'Web Application' else 'Network traffic, auth logs'}
- Common IOCs: Unusual process execution, network connections
- MITRE ATT&CK: Related techniques in {exp_type['category']} matrix

Mitigation:
- Patch vulnerable systems
- Implement security controls
- Enable monitoring and alerting
- Regular security assessments""",
                        "metadata": {
                            "category": exp_type["category"],
                            "technique": technique,
                            "tool": tool
                        }
                    }
                    exploits.append(exploit_doc)
                    
                    if len(exploits) >= count:
                        break
                if len(exploits) >= count:
                    break
            if len(exploits) >= count:
                break
        
        print(f"   ✓ Generated {len(exploits)} exploit samples")
        return exploits
    
    def save_exploits(self, exploits: List[Dict]):
        """Save exploits to knowledge base"""
        output_file = self.exploits_dir / "exploits.jsonl"
        
        with open(output_file, "w") as f:
            for exploit in exploits:
                f.write(json.dumps(exploit) + "\n")
                self.index.append(exploit)
        
        print(f"   💾 Saved to {output_file}")
    
    # =========================================================
    # TOOL DOCUMENTATION
    # =========================================================
    
    def generate_tool_docs(self) -> List[Dict]:
        """Generate comprehensive tool documentation"""
        print(f"\n📥 Generating tool documentation...")
        
        tools = [
            {
                "name": "Nmap",
                "category": "Reconnaissance",
                "description": "Network discovery and security auditing tool",
                "commands": [
                    ("nmap -sV -sC target", "Service version detection with default scripts"),
                    ("nmap -p- -T4 target", "Full port scan with timing template 4"),
                    ("nmap -sU -p 53,161 target", "UDP scan on specific ports"),
                    ("nmap --script vuln target", "Run vulnerability scripts"),
                    ("nmap -sn 192.168.1.0/24", "Ping sweep for host discovery"),
                ]
            },
            {
                "name": "Burp Suite",
                "category": "Web Application",
                "description": "Web application security testing platform",
                "commands": [
                    ("Proxy > Intercept", "Capture and modify HTTP requests"),
                    ("Scanner > Active Scan", "Automated vulnerability scanning"),
                    ("Intruder > Positions", "Automated payload injection"),
                    ("Repeater", "Manual request modification and replay"),
                    ("Decoder", "Encode/decode data in various formats"),
                ]
            },
            {
                "name": "Metasploit",
                "category": "Exploitation",
                "description": "Penetration testing framework",
                "commands": [
                    ("search type:exploit name:windows", "Search for Windows exploits"),
                    ("use exploit/multi/handler", "Set up payload handler"),
                    ("set PAYLOAD windows/meterpreter/reverse_tcp", "Configure payload"),
                    ("run post/windows/gather/hashdump", "Dump password hashes"),
                    ("sessions -l", "List active sessions"),
                ]
            },
            {
                "name": "BloodHound",
                "category": "Active Directory",
                "description": "AD attack path analysis tool",
                "commands": [
                    ("bloodhound-python -d domain -u user -p pass -c all", "Collect all AD data"),
                    ("SharpHound.exe -c all", "Windows collection"),
                    ("Shortest Path to Domain Admins", "GUI query"),
                    ("Find Kerberoastable Users", "Built-in query"),
                    ("Mark user as owned", "Track compromise progress"),
                ]
            },
            {
                "name": "Impacket",
                "category": "Active Directory",
                "description": "Python classes for network protocols",
                "commands": [
                    ("secretsdump.py domain/user@dc -just-dc", "DCSync attack"),
                    ("psexec.py domain/admin@target", "Remote command execution"),
                    ("GetUserSPNs.py domain/user -request", "Kerberoasting"),
                    ("wmiexec.py domain/user@target", "WMI execution"),
                    ("smbclient.py domain/user@target", "SMB client"),
                ]
            },
            {
                "name": "CrackMapExec",
                "category": "Active Directory",
                "description": "Swiss army knife for Windows/AD pentesting",
                "commands": [
                    ("cme smb targets -u user -p pass", "SMB authentication"),
                    ("cme smb targets -u user -p pass --shares", "List shares"),
                    ("cme smb targets -u user -p pass -M lsassy", "Dump credentials"),
                    ("cme ldap dc -u user -p pass --users", "Enumerate users"),
                    ("cme smb targets -u user -H hash", "Pass-the-hash"),
                ]
            },
            {
                "name": "Responder",
                "category": "Network",
                "description": "LLMNR/NBT-NS/MDNS poisoner",
                "commands": [
                    ("responder -I eth0", "Basic poisoning"),
                    ("responder -I eth0 -wrf", "WPAD, fingerprinting, force auth"),
                    ("responder -I eth0 --lm", "Downgrade to LM hashes"),
                    ("Logs in /usr/share/responder/logs/", "Captured hashes location"),
                ]
            },
            {
                "name": "Hashcat",
                "category": "Password Cracking",
                "description": "Advanced password recovery",
                "commands": [
                    ("hashcat -m 1000 hashes.txt wordlist.txt", "NTLM cracking"),
                    ("hashcat -m 13100 hashes.txt wordlist.txt", "Kerberoast"),
                    ("hashcat -m 18200 hashes.txt wordlist.txt", "AS-REP roast"),
                    ("hashcat -m 1000 hashes.txt -a 3 ?a?a?a?a?a?a", "Brute force"),
                    ("hashcat --show hashes.txt", "Show cracked passwords"),
                ]
            },
            {
                "name": "Mimikatz",
                "category": "Credential Access",
                "description": "Windows credential extraction",
                "commands": [
                    ("sekurlsa::logonpasswords", "Dump plaintext passwords"),
                    ("lsadump::dcsync /user:krbtgt", "DCSync for krbtgt"),
                    ("kerberos::golden /user:admin /domain:x /sid:x /krbtgt:hash", "Golden ticket"),
                    ("sekurlsa::pth /user:admin /ntlm:hash /domain:x", "Pass-the-hash"),
                    ("privilege::debug", "Enable debug privilege"),
                ]
            },
            {
                "name": "SQLMap",
                "category": "Web Application",
                "description": "Automatic SQL injection tool",
                "commands": [
                    ("sqlmap -u 'url?id=1' --dbs", "Enumerate databases"),
                    ("sqlmap -u 'url?id=1' -D db --tables", "List tables"),
                    ("sqlmap -u 'url?id=1' --os-shell", "Get OS shell"),
                    ("sqlmap -r request.txt --batch", "Use saved request"),
                    ("sqlmap -u 'url?id=1' --tamper=space2comment", "Use tamper script"),
                ]
            },
            {
                "name": "Gobuster",
                "category": "Web Application",
                "description": "Directory and DNS brute-forcing",
                "commands": [
                    ("gobuster dir -u http://target -w wordlist.txt", "Directory brute"),
                    ("gobuster dns -d domain.com -w wordlist.txt", "DNS brute"),
                    ("gobuster vhost -u http://target -w wordlist.txt", "Virtual host brute"),
                    ("gobuster dir -u http://target -w list -x php,txt", "With extensions"),
                ]
            },
            {
                "name": "Nuclei",
                "category": "Vulnerability Scanning",
                "description": "Fast vulnerability scanner",
                "commands": [
                    ("nuclei -u http://target", "Basic scan"),
                    ("nuclei -u http://target -t cves/", "CVE templates"),
                    ("nuclei -l urls.txt -t technologies/", "Tech detection"),
                    ("nuclei -u http://target -severity critical,high", "By severity"),
                ]
            },
        ]
        
        docs = []
        for tool in tools:
            doc = {
                "id": f"tool_{tool['name'].lower().replace(' ', '_')}",
                "type": "tool",
                "title": f"{tool['name']} - {tool['category']}",
                "content": f"""Tool: {tool['name']}
Category: {tool['category']}
Description: {tool['description']}

Common Commands:
{''.join([f'''
{cmd[0]}
  └─ {cmd[1]}
''' for cmd in tool['commands']])}

Usage Guidelines:
- Always verify authorization before testing
- Start with less intrusive options
- Document all findings
- Consider detection implications

OPSEC Considerations:
- {tool['name']} may trigger security alerts
- Use appropriate timing and rate limiting
- Consider logging and evidence
- Clean up artifacts after testing""",
                "metadata": {
                    "tool": tool["name"],
                    "category": tool["category"]
                }
            }
            docs.append(doc)
        
        print(f"   ✓ Generated {len(docs)} tool documentation entries")
        return docs
    
    def save_tool_docs(self, docs: List[Dict]):
        """Save tool documentation to knowledge base"""
        output_file = self.tools_dir / "tools.jsonl"
        
        with open(output_file, "w") as f:
            for doc in docs:
                f.write(json.dumps(doc) + "\n")
                self.index.append(doc)
        
        print(f"   💾 Saved to {output_file}")
    
    # =========================================================
    # MITRE ATT&CK
    # =========================================================
    
    def generate_mitre_techniques(self) -> List[Dict]:
        """Generate MITRE ATT&CK technique documentation"""
        print(f"\n📥 Generating MITRE ATT&CK technique documentation...")
        
        techniques = [
            # Initial Access
            ("T1190", "Exploit Public-Facing Application", "Initial Access", 
             "Adversaries may exploit vulnerabilities in internet-facing systems to gain access."),
            ("T1566", "Phishing", "Initial Access",
             "Adversaries may send phishing messages to gain access through malicious attachments or links."),
            ("T1078", "Valid Accounts", "Initial Access",
             "Adversaries may use legitimate credentials to gain access to systems."),
            
            # Execution
            ("T1059", "Command and Scripting Interpreter", "Execution",
             "Adversaries may abuse command interpreters to execute commands and scripts."),
            ("T1203", "Exploitation for Client Execution", "Execution",
             "Adversaries may exploit vulnerabilities in client applications to execute code."),
            
            # Persistence
            ("T1053", "Scheduled Task/Job", "Persistence",
             "Adversaries may create scheduled tasks to maintain persistence."),
            ("T1136", "Create Account", "Persistence",
             "Adversaries may create accounts to maintain access to victim systems."),
            ("T1505", "Server Software Component", "Persistence",
             "Adversaries may install malicious components in server software."),
            
            # Privilege Escalation
            ("T1068", "Exploitation for Privilege Escalation", "Privilege Escalation",
             "Adversaries may exploit vulnerabilities to escalate privileges."),
            ("T1548", "Abuse Elevation Control Mechanism", "Privilege Escalation",
             "Adversaries may bypass UAC or sudo to escalate privileges."),
            
            # Defense Evasion
            ("T1070", "Indicator Removal", "Defense Evasion",
             "Adversaries may delete or modify artifacts to cover their tracks."),
            ("T1027", "Obfuscated Files or Information", "Defense Evasion",
             "Adversaries may obfuscate payloads to evade detection."),
            
            # Credential Access
            ("T1003", "OS Credential Dumping", "Credential Access",
             "Adversaries may dump credentials from operating system memory."),
            ("T1558", "Steal or Forge Kerberos Tickets", "Credential Access",
             "Adversaries may steal or forge Kerberos tickets for lateral movement."),
            ("T1552", "Unsecured Credentials", "Credential Access",
             "Adversaries may search for unsecured credentials in files or registries."),
            
            # Discovery
            ("T1087", "Account Discovery", "Discovery",
             "Adversaries may enumerate accounts to understand the environment."),
            ("T1082", "System Information Discovery", "Discovery",
             "Adversaries may gather system information to understand the target."),
            
            # Lateral Movement
            ("T1021", "Remote Services", "Lateral Movement",
             "Adversaries may use remote services like RDP, SSH, SMB for lateral movement."),
            ("T1550", "Use Alternate Authentication Material", "Lateral Movement",
             "Adversaries may use stolen hashes or tickets to authenticate."),
            
            # Collection
            ("T1005", "Data from Local System", "Collection",
             "Adversaries may collect data from the local system."),
            ("T1039", "Data from Network Shared Drive", "Collection",
             "Adversaries may collect data from network shares."),
            
            # Exfiltration
            ("T1041", "Exfiltration Over C2 Channel", "Exfiltration",
             "Adversaries may exfiltrate data over existing C2 communications."),
            ("T1048", "Exfiltration Over Alternative Protocol", "Exfiltration",
             "Adversaries may use protocols like DNS or ICMP for exfiltration."),
            
            # Impact
            ("T1486", "Data Encrypted for Impact", "Impact",
             "Adversaries may encrypt data to disrupt availability (ransomware)."),
            ("T1490", "Inhibit System Recovery", "Impact",
             "Adversaries may delete backups to prevent recovery."),
        ]
        
        docs = []
        for tid, name, tactic, description in techniques:
            doc = {
                "id": f"mitre_{tid}",
                "type": "mitre",
                "title": f"{tid}: {name}",
                "content": f"""MITRE ATT&CK Technique: {tid}
Name: {name}
Tactic: {tactic}

Description:
{description}

Detection:
- Monitor for indicators associated with {name.lower()}
- Enable appropriate logging for {tactic.lower()} activities
- Configure SIEM rules for behavioral detection
- Use EDR for endpoint visibility

Mitigation:
- Implement security controls to prevent {name.lower()}
- Enable monitoring and alerting
- Conduct regular security assessments
- Maintain security awareness training

Related Techniques:
- Sub-techniques may exist for more specific variants
- Check ATT&CK Navigator for related techniques
- Consider technique chains in attack scenarios

References:
- https://attack.mitre.org/techniques/{tid}/
- MITRE ATT&CK Navigator
- Related CTI reports and case studies""",
                "metadata": {
                    "technique_id": tid,
                    "technique_name": name,
                    "tactic": tactic
                }
            }
            docs.append(doc)
        
        print(f"   ✓ Generated {len(docs)} MITRE techniques")
        return docs
    
    def save_mitre(self, docs: List[Dict]):
        """Save MITRE techniques to knowledge base"""
        output_file = self.mitre_dir / "mitre_attack.jsonl"
        
        with open(output_file, "w") as f:
            for doc in docs:
                f.write(json.dumps(doc) + "\n")
                self.index.append(doc)
        
        print(f"   💾 Saved to {output_file}")
    
    # =========================================================
    # INDEX BUILDING
    # =========================================================
    
    def build_combined_index(self):
        """Build combined index for RAG"""
        index_file = self.base_dir / "rag_index.jsonl"
        
        with open(index_file, "w") as f:
            for doc in self.index:
                f.write(json.dumps(doc) + "\n")
        
        print(f"\n📚 Combined RAG index: {index_file}")
        print(f"   Total documents: {len(self.index)}")
        
        # Generate statistics
        by_type = {}
        for doc in self.index:
            t = doc.get("type", "unknown")
            by_type[t] = by_type.get(t, 0) + 1
        
        print("\n   By type:")
        for t, count in sorted(by_type.items()):
            print(f"     - {t}: {count}")
    
    def build_all(self, fetch_cves: bool = True, cve_days: int = 90):
        """Build complete RAG knowledge base"""
        print("="*60)
        print("🚀 BUILDING BOMBINA RAG KNOWLEDGE BASE")
        print("="*60)
        
        # 1. CVEs
        if fetch_cves:
            cves = self.fetch_recent_cves(days=cve_days)
            if cves:
                self.save_cves(cves)
        
        # 2. Exploits
        exploits = self.generate_exploit_samples(count=200)
        self.save_exploits(exploits)
        
        # 3. Tool documentation
        tools = self.generate_tool_docs()
        self.save_tool_docs(tools)
        
        # 4. MITRE ATT&CK
        mitre = self.generate_mitre_techniques()
        self.save_mitre(mitre)
        
        # 5. Build combined index
        self.build_combined_index()
        
        print("\n" + "="*60)
        print("✅ RAG KNOWLEDGE BASE COMPLETE")
        print("="*60)


def main():
    base_dir = "/home/redbend/MyLocalProjects/Bombina/scripts/data/rag_knowledge"
    
    builder = RAGKnowledgeBuilder(base_dir)
    
    # Build all knowledge (set fetch_cves=False if no internet)
    builder.build_all(fetch_cves=True, cve_days=90)


if __name__ == "__main__":
    main()
