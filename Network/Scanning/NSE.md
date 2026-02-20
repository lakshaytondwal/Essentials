# NSE (Nmap Scripting Engine)

NSE allows automation of advanced scanning, enumeration, vulnerability detection, and exploitation-related tasks using Lua scripts.

Scripts are located in:

```bash
/usr/share/nmap/scripts/
```

Script database file:

```bash
/usr/share/nmap/scripts/script.db
```

Script database can be updated using:

```bash
nmap --script-updatedb
```

[nmap scripts](https://svn.nmap.org/nmap/scripts/)

---

## 1. Run default scripts

Runs the default safe scripts useful for enumeration.

```bash
nmap -sC 192.168.1.10
```

Equivalent to:

```bash
nmap --script=default 192.168.1.10
```

---

## 2. Run specific script

Both syntaxes are identical:

```bash
nmap --script http-title 192.168.1.10
```

```bash
nmap --script=http-title 192.168.1.10
```

Explanation:

`=` is optional. Nmap treats both the same.

---

## 3. Run vulnerability scripts

Runs all scripts in the vuln category.

```bash
nmap --script vuln 192.168.1.10
```

These scripts check for known vulnerabilities such as:

* Heartbleed
* SMB vulnerabilities
* SSL flaws
* Misconfigurations

---

## 4. Run multiple scripts

Using comma:

```bash
nmap --script ftp-anon,ssh-hostkey 192.168.1.10
```

Using wildcard:

```bash
nmap --script ftp*,ssh* 192.168.1.10
```

Runs all scripts starting with ftp and ssh.

---

## 5. Script Categories

Common script categories:

```txt
auth        Authentication related
broadcast   Network discovery
brute       Brute force attacks
default     Safe default scripts
discovery   Service discovery
dos         Denial of service
exploit     Exploitation scripts
external    Uses external services
fuzzer      Fuzzing scripts
intrusive   Aggressive scripts
malware     Malware detection
safe        Non-intrusive scripts
version     Version detection
vuln        Vulnerability detection
```

Example:

```bash
nmap --script discovery 192.168.1.10
```

---

## 6. Script Arguments

Script arguments allow customization of script behavior.

Syntax:

```bash
nmap --script <script-name> --script-args <argument=value> <target>
```

or

```bash
nmap --script=<script-name> --script-args=<argument=value> <target>
```

Both are identical.

---

### Example 1: HTTP basic auth brute force

```bash
nmap --script http-brute --script-args userdb=users.txt,passdb=passwords.txt 192.168.1.10
```

Explanation:

* userdb → username file
* passdb → password file

### Example 2: FTP anonymous login with custom timeout

```bash
nmap --script ftp-anon --script-args ftp-anon.maxlist=50 192.168.1.10
```

Limits file listing.

### Example 3: SMB enumeration with credentials

```bash
nmap --script smb-enum-shares --script-args smbuser=admin,smbpass=password 192.168.1.10
```

### Example 4: SSL certificate info

```bash
nmap --script ssl-cert --script-args ssl-cert.showall 192.168.1.10
```

---

## 7. Multiple Script Arguments

```bash
nmap --script http-brute --script-args userdb=users.txt,passdb=passwords.txt,brute.firstonly=true 192.168.1.10
```

---

## 8. Run scripts on specific ports

```bash
nmap -p 21 --script ftp-anon 192.168.1.10
```

---

## 9. Run scripts with service detection

Recommended combination:

```bash
nmap -sV -sC 192.168.1.10
```

or

```bash
nmap -sV --script vuln 192.168.1.10
```

---

## 10. Useful real-world enumeration combo

This is the practical enumeration command used in real pentests:

```bash
nmap -sC -sV -oA scan 192.168.1.10
```

or aggressive:

```bash
nmap -A 192.168.1.10
```

---
