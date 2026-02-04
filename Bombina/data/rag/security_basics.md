# Bombina Security Knowledge Base

## OWASP Top 10 (2021)

### 1. A01:2021 – Broken Access Control
Access control enforces policy such that users cannot act outside of their intended permissions.

### 2. A02:2021 – Cryptographic Failures
Failures related to cryptography which often leads to sensitive data exposure.

### 3. A03:2021 – Injection
User-supplied data is not validated, filtered, or sanitized by the application.

### 4. A04:2021 – Insecure Design
Risks related to design flaws. Focus on threat modeling, secure design patterns.

### 5. A05:2021 – Security Misconfiguration
Missing appropriate security hardening across any part of the application stack.

### 6. A06:2021 – Vulnerable and Outdated Components
Using components with known vulnerabilities.

### 7. A07:2021 – Identification and Authentication Failures
Confirmation of the user's identity, authentication, and session management.

### 8. A08:2021 – Software and Data Integrity Failures
Code and infrastructure that does not protect against integrity violations.

### 9. A09:2021 – Security Logging and Monitoring Failures
Without logging and monitoring, breaches cannot be detected.

### 10. A10:2021 – Server-Side Request Forgery (SSRF)
SSRF flaws occur when a web application fetches a remote resource without validating the user-supplied URL.

---

## Common Penetration Testing Methodology

### 1. Reconnaissance
- Passive: OSINT, DNS enumeration, subdomain discovery
- Active: Port scanning, service detection

### 2. Scanning & Enumeration
- Nmap, Masscan for port scanning
- Directory brute forcing (gobuster, ffuf)
- Version detection

### 3. Vulnerability Analysis
- CVE research
- Automated scanners (Nessus, OpenVAS)
- Manual testing

### 4. Exploitation
- Metasploit Framework
- Custom exploits
- Password attacks

### 5. Post-Exploitation
- Privilege escalation
- Lateral movement
- Data exfiltration

### 6. Reporting
- Executive summary
- Technical findings
- Remediation recommendations

---

## Essential Security Tools

| Tool | Purpose |
|------|---------|
| Nmap | Network scanning |
| Burp Suite | Web app testing |
| Metasploit | Exploitation framework |
| Wireshark | Packet analysis |
| John the Ripper | Password cracking |
| Hashcat | GPU password cracking |
| SQLmap | SQL injection |
| Gobuster | Directory brute forcing |
| Hydra | Online password attacks |
| Nikto | Web server scanning |
