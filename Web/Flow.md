# Unified Web Application Penetration Testing Flow

## 1. Recon & Enumeration

### 1.1 Basic Recon

* `nmap -sC -sV target.com` → find open ports/services
* Identify tech stack: `whatweb`, `wappalyzer`, headers
* Crawl with `dirsearch`, `ffuf`, `gobuster`

### 1.2 Subdomain & VHost Discovery

* **DNS-based subdomains**: `subfinder`, `amass`
* **Virtual hosts (hidden in labs/CTFs)**:

  ```bash
  ffuf -u http://TARGET/ -H "Host: FUZZ.target.com" -w vhost.txt
  ```

* Check site by **IP only** (default vhost)
* Alter `Host` header in Burp (`Host: admin.target.com`)
* Wordlists: `SecLists/Discovery/DNS/`, `vhosts.txt`

### 1.3 File & Content Discovery

* Check common files:

  * `/robots.txt`, `/sitemap.xml`, `/crossdomain.xml`
  * Hidden dirs: `/backup/`, `/config/`, `/.git/`
* JS file analysis: scrape for API keys, hidden routes
* Param discovery: `Arjun`, `ffuf -w params.txt`

---

## 2. Authentication & Access Control

* Test login: weak creds, default creds, credential stuffing
* Brute-force with `hydra` / Burp Intruder (check rate-limits, captcha bypass, token reuse)
* Password reset flaws: predictable tokens, IDOR in reset endpoint
* Access control:

  * Horizontal privilege escalation (user → other user)
  * Vertical escalation (user → admin)

---

## 3. Input Validation & Injection

* **SQL Injection**: manual payloads + `sqlmap`
* **XSS**: reflected, stored, DOM
* **Command Injection**: `;id`, `&& whoami`, backticks
* **SSTI**: `{{7*7}}`, `${7*7}`
* **XXE**: malicious XML payloads
* **Header injections**: `User-Agent`, `X-Forwarded-For` sometimes vulnerable

---

## 4. File Handling & Path Issues

* File uploads:

  * Polyglot files (`shell.php.jpg`)
  * Double extensions (`file.php;.jpg`)
  * Tamper content-type in Burp (`image/png`)
  * Check `/uploads/` for execution
* Path traversal:

  * `../../etc/passwd`
  * `%2e%2e%2f` encoded payloads

---

## 5. Business Logic & Workflow Testing

* IDOR: tamper IDs (`user_id=123` → `124`)
* Broken payment flows: change `price=100` → `price=1`
* Coupon/reward abuse
* Race conditions: replay requests simultaneously

---

## 6. API & GraphQL Testing

* Look for `/api/`, `/graphql`, `/swagger.json`
* Test for:

  * Broken auth (JWT not validated)
  * Mass assignment (`{"role":"admin"}`)
  * Insecure methods (PUT/DELETE enabled)
  * GraphQL introspection for hidden queries

---

## 7. Security Headers & Config Checks

* Missing headers: CSP, HSTS, X-Frame-Options
* Misconfigured CORS: `Access-Control-Allow-Origin: *` with credentials
* TLS/SSL issues: `sslyze`, `testssl.sh`
* Debug endpoints: `/debug`, `/phpinfo.php`
* Verbose error messages revealing stack traces

---

## 8. Exploitation & Privilege Escalation

* If you get **RCE** via upload/injection:

  * Stabilize shell:

    ```bash
    python3 -c 'import pty; pty.spawn("/bin/bash")'
    ```

  * Enumerate with `linpeas.sh` or manual checks
  * Loot sensitive configs (`config.php`, `.env`, `db_backup.sql`)
  * Try privilege escalation (`sudo -l`, SUID, kernel exploits)
* Pivot to other subdomains/vhosts with stolen creds

---

## 9. Post-Exploitation

* Dump DBs (users, hashes, tokens)
* Enumerate environment variables for secrets
* Access logs, internal files, backups
* Prove impact → **but don’t destroy** (esp. bug bounty/real pentest)

---

## 10. Reporting & Documentation

* **For Pentest Report:**

  * Title → Description → Impact → Steps → POC → Remediation
* **For Bug Bounty:**

  * Show clear exploit + security impact
* **For CTF:**

  * Capture the flag, screenshot exploitation steps

---

## Example Attack Path (CTF/Realistic)

1. Scan → only HTTP open
2. Check `/robots.txt` → nothing
3. VHost fuzz → `admin.target.com` discovered
4. Admin panel → login vulnerable to SQLi
5. Dump users → found admin creds
6. File upload → upload PHP shell disguised as `image.jpg`
7. Gain RCE → escalate to root via SUID binary
8. Loot `/root/root.txt` → capture flag

---
