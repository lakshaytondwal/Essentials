# Scanning

**Scanning** is the phase in which the exposed attack surface is identified, enumerated, analyzed, and **manually verified** to determine realistic exploitation paths.
This phase is **not limited to automated port scanning** and may include multiple tools and techniques driven by scan results.

The purpose of Scanning is to answer:

**“What is exposed, what is actually vulnerable, and how can it be exploited?”:**

Scanning ends when sufficient confidence is obtained to attempt exploitation.
No impact is proven in this phase.

---

## Included Activities

**Discovery & Enumeration:**

* Host discovery
* Open ports and services
* Service versions and enabled features
* Authentication mechanisms
* Accessible endpoints, shares, or interfaces

**Analysis:**

* Identification of known vulnerabilities (CVEs)
* Detection of misconfigurations
* Identification of weak authentication or trust relationships
* Mapping of potential attack paths

**Verification:**

* Manual confirmation of scan findings
* Elimination of false positives
* Validation of exploit feasibility using protocol-specific tools

Examples:

* SMB signing flagged as disabled → verified with `smbclient` / `crackmapexec`
* Anonymous LDAP bind detected → verified with `ldapsearch`
* Web application issue flagged by scanner → manually tested

---

## Excluded Activities

* Privilege escalation
* Lateral movement
* Persistent access
* Data exfiltration or impact demonstration

Any activity that proves access or business impact is considered **Exploitation**, not Scanning.

### Notes

* Automated tools (e.g., nmap) are **hypothesis generators**, not ground truth.
* Manual verification is mandatory before exploitation.
* Tools do not define the phase — **intent does**.

---
