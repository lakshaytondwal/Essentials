# Enumerating AD

After getting the first set of AD credentials and the means to authenticate with them on the network we can start enumerating various details about the AD setup and structure with authenticated access, even with super low-privileged access.

Enumeration and Exploitation are heavily entwined. Once an attack path shown by the enumeration phase has been exploited, enumeration is again performed from this new privileged position.

## 1. **Credential Injection**

You can get incredibly far doing AD enumeration from a linux machine. Still, if you genuinely want to do in-depth enumeration and even exploitation, you need a Windows machine. This will allow us to use several built-in methods to stage our enumeration and exploits such as `runas.exe` binary.

### 1.1 **RunAs**

If you’ve recovered Active Directory credentials but don’t have a domain-joined machine to log into, `runas` can save the day. It’s a built-in Windows binary that lets you load AD credentials into a process on a machine you control so those credentials are used for *network* authentication even though the host isn’t domain-joined.

Example command:

```cmd
runas.exe /netonly /user:<domain>\<username> cmd.exe
```

What each part does

* `/netonly` — Tells Windows to treat the supplied credentials only for network authentication. The process you start will run locally under your current Windows account, but any outbound network connections from that process will present the supplied AD credentials. Note: `/netonly` means the credentials aren’t validated at the prompt itself — the password prompt won’t query a domain controller — so a wrong password won’t be rejected at that moment; network operations using those credentials will fail if they’re incorrect.
* `/user` — Specify the domain and username to load. Prefer the domain’s FQDN rather than its NetBIOS name to avoid resolution problems.
* `cmd.exe` — The program to launch with the injected credentials. `cmd.exe` is a safe, flexible choice because it gives you a shell from which you can launch other tools; you can replace it with any executable you need.

Behavior and verification

* After running the command you’ll be prompted for the password. Because of `/netonly`, that prompt doesn’t perform a real-time domain authentication check — it simply accepts the input and stores the credentials for later use. To confirm the credentials were loaded correctly, initiate a network action from the spawned shell that requires AD auth (e.g., access a network share or call an SMB/LDAP resource) and observe whether authentication succeeds.

Practical tip about local privileges

* If you run the parent Command Prompt as Administrator before invoking `runas`, the spawned `cmd.exe` will inherit the Administrator token locally. That means local commands you run from the `runas` shell can use elevated privileges on that host. This does *not* grant elevated or administrative rights on the network — it only ensures your local process has the expected local token so tools requiring local admin work properly.

### 1.2 **DNS**

After entering the password, a new Command Prompt window will appear. However, before assuming the credentials are valid, they need to be verified. The most reliable test is to check access to **SYSVOL**, a directory that every Active Directory (AD) account can read—regardless of privilege level.

**Understanding SYSVOL**
SYSVOL is a shared folder located on every domain controller. It stores **Group Policy Objects (GPOs)**, domain-level scripts, and other configuration data. This directory is a critical part of AD infrastructure since it distributes GPOs across all domain-joined machines, allowing administrators to enforce system-wide configurations and policies centrally. Every machine in the domain regularly reads from SYSVOL to apply its relevant policies.

**Before listing SYSVOL**
You must ensure proper DNS configuration. In some cases, internal DNS is automatically set up—either through DHCP or a VPN connection—but not always. If DNS isn’t configured, network name resolution will fail, and you won’t be able to reach the domain controller.

To fix this, manually point your system’s DNS to a **domain controller’s IP address**, which is typically the most reliable choice. Run the following PowerShell commands to configure DNS:

```powershell
$dnsip = "<DC IP>"
$index = Get-NetAdapter -Name 'INTERFACE' | Select-Object -ExpandProperty 'ifIndex'
Set-DnsClientServerAddress -InterfaceIndex $index -ServerAddresses $dnsip
```

Of course, `INTERFACE` will be whatever interface is connected to the network. We can verify that DNS is working by running the following:

```powershell
C:\> nslookup za.thedomain.com
```

Which should now resolve to the DC IP since this is where the FQDN is being hosted. Now that DNS is working, we can finally test our credentials. We can use the following command to force a network-based listing of the SYSVOL directory:

```powershell
C:\Tools>dir \\za.thedomain.com\SYSVOL\
 Volume in drive \\za.thedomain.com\SYSVOL is Windows
 Volume Serial Number is 1634-22A9

 Directory of \\za.thedomain.com\SYSVOL

02/24/2022  09:57 PM    <DIR>          .
02/24/2022  09:57 PM    <DIR>          ..
02/24/2022  09:57 PM    <JUNCTION>     za.thedomain.com [C:\Windows\SYSVOL\domain]
               0 File(s)              0 bytes
               3 Dir(s)  51,835,408,384 bytes free
```

### 1.3 **IP vs Hostnames**

**Question:** Is there a difference between `dir \\za.thedomain.com\SYSVOL` and `dir \\<DC IP>\SYSVOL` and why the big fuss about DNS?

There is quite a difference, and it boils down to the authentication method being used. When we provide the hostname, network authentication will attempt first to perform Kerberos authentication. Since Kerberos authentication uses hostnames embedded in the tickets, if we provide the IP instead, we can force the authentication type to be NTLM. While on the surface, this does not matter to us right now, it is good to understand these slight differences since they can allow you to remain more stealthy during a Red team assessment. In some instances, organisations will be monitoring for OverPass- and Pass-The-Hash Attacks. Forcing NTLM authentication is a good trick to have in the book to avoid detection in these cases.

## 2. **Through Command Prompt**

Command Prompt is useful for quick AD lookups when you can’t use RDP, want to avoid PowerShell detection, or need minimal tooling.

### 2.1 **User**

Use the built-in `net` to list all users in the AD domain by using the `user` sub-option

```cmd
C:\>net user /domain
The request will be processed at a domain controller for domain za.thedomain.com

User accounts for \\THEDC

-------------------------------------------------------------------------------
aaron.conway             aaron.hancock            aaron.harris
aaron.johnson            aaron.lewis              aaron.moore
aaron.patel              aaron.smith              abbie.joyce
abbie.robertson          abbie.taylor             abbie.walker
abdul.akhtar             abdul.bates              abdul.holt
abdul.jones              abdul.wall               abdul.west
abdul.wilson             abigail.cox              abigail.cox1
abigail.smith            abigail.ward             abigail.wheeler
[....]
The command completed successfully.
```

This will return all AD users for us and can be helpful in determining the size of the domain to stage further attacks. We can also use this sub-option to enumerate more detailed information about a single user account:

```cmd
C:\>net user zoe.marshall /domain
The request will be processed at a domain controller for domain za.thedomain.com

User name                    zoe.marshall
Full Name                    Zoe Marshall
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            2/24/2022 10:06:06 PM
Password expires             Never
Password changeable          2/24/2022 10:06:06 PM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   Never

Logon hours allowed          All

Local Group Memberships
Global Group memberships     *Domain Users         *Internet Access
The command completed successfully.
```

### 2.2 **Groups**

We can use the `net` command to enumerate the groups of the domain by using the `group` sub-option:

```cmd
C:\>net group /domain
The request will be processed at a domain controller for domain za.thedomain.com

Group Accounts for \\THEDC

-------------------------------------------------------------------------------
*Cloneable Domain Controllers
*DnsUpdateProxy
*Domain Admins
*Domain Computers
*Domain Controllers
*Domain Guests
*Domain Users
[...]
*Schema Admins
*Server Admins
*Tier 0 Admins
*Tier 1 Admins
*Tier 2 Admins
The command completed successfully.
```

This information can help us find specific groups to target for goal execution. We could also enumerate more details such as membership to a group by specifying the group in the same command:

```cmd
C:\>net group "Tier 1 Admins" /domain
The request will be processed at a domain controller for domain za.thedomain.com

Group name     Tier 1 Admins
Comment

Members

-------------------------------------------------------------------------------
t1_arthur.tyler          t1_gary.moss             t1_henry.miller
t1_jill.wallis           t1_joel.stephenson       t1_marian.yates
t1_rosie.bryant
The command completed successfully.
```

### 2.3 **Password Policies**

We can use the `net` command to enumerate the password policy of the domain by using the `accounts` sub-option:

```cmd
C:\>net accounts /domain
The request will be processed at a domain controller for domain za.thedomain.com

Force user logoff how long after time expires?:       Never
Minimum password age (days):                          0
Maximum password age (days):                          Unlimited
Minimum password length:                              0
Length of password history maintained:                None
Lockout threshold:                                    Never
Lockout duration (minutes):                           30
Lockout observation window (minutes):                 30
Computer role:                                        PRIMARY
The command completed successfully.
```

This will provide us with helpful information such as:

* Length of password history kept. Meaning how many unique passwords must the user provide before they can reuse an old password.
* The lockout threshold for incorrect password attempts and for how long the account will be locked.
* The minimum length of the password.
* The maximum age that passwords are allowed to reach indicating if passwords have to be rotated at a regular interval.

**Note:** The `net` commands may not show all information. For example, if a user is a member of more than ten groups, not all of these groups will be shown in the output.

You can find the full range of options associated with the net command at [Microsoft Manuals](https://docs.microsoft.com/en-us/troubleshoot/windows-server/networking/net-commands-on-operating-systems).

## 3. **Through PowerShell**

The machine must have the AD-RSAT tools installed (providing the AD PowerShell module and its cmdlets). There are 50+ Active Directory–related cmdlets available; we’ll be covering a selected subset of them. Refer to [this](https://docs.microsoft.com/en-us/powershell/module/activedirectory/?view=windowsserver2022-ps) for the complete list of cmdlets.

### 3.1 **Domains**

We can use `Get-ADDomain` to retrieve additional information about the specific domain:

```powershell
PS C:\> Get-ADDomain -Server za.thedomain.com

AllowedDNSSuffixes                 : {}
ChildDomains                       : {}
ComputersContainer                 : CN=Computers,DC=za,DC=thedomain,DC=com
DeletedObjectsContainer            : CN=Deleted Objects,DC=za,DC=thedomain,DC=com
DistinguishedName                  : DC=za,DC=thedomain,DC=com
DNSRoot                            : za.thedomain.com
DomainControllersContainer         : OU=Domain Controllers,DC=za,DC=thedomain,DC=com
[...]
UsersContainer                     : CN=Users,DC=za,DC=thedomain,DC=com
```

### 3.2 **User**

We can use the `Get-ADUser` cmdlet to enumerate AD users:

```powershell
PS C:\> Get-ADUser -Identity gordon.stevens -Server za.thedomain.com -Properties *

AccountExpirationDate                :
accountExpires                       : 9223372036854775807
AccountLockoutTime                   :
[...]
Deleted                              :
Department                           : Consulting
Description                          :
DisplayName                          : Gordon Stevens
DistinguishedName                    : CN=gordon.stevens,OU=Consulting,OU=People,DC=za,DC=thedomain,DC=com
[...]
```

The parameters are used for the following:

* `-Identity` - The account name that we are enumerating
* `-Properties` - Which properties associated with the account will be shown, `*` will show all properties
* `-Server` - Since we are not domain-joined, we have to use this parameter to point it to our domain controller

For most of these cmdlets, we can also use the `-Filter` parameter that allows more control over enumeration and use the `Format-Table` cmdlet to display the results such as the following neatly:

```powershell
PS C:\> Get-ADUser -Filter 'Name -like "*stevens"' -Server za.thedomain.com | Format-Table Name,SamAccountName -A

Name             SamAccountName
----             --------------
chloe.stevens    chloe.stevens
samantha.stevens samantha.stevens
[...]
janice.stevens   janice.stevens
gordon.stevens   gordon.stevens
```

### 3.3 **Groups**

We can use the `Get-ADGroup` cmdlet to enumerate AD groups:

```powershell
PS C:\> Get-ADGroup -Identity Administrators -Server za.thedomain.com


DistinguishedName : CN=Administrators,CN=Builtin,DC=za,DC=thedomain,DC=com
GroupCategory     : Security
GroupScope        : DomainLocal
Name              : Administrators
ObjectClass       : group
ObjectGUID        : f4d1cbcd-4a6f-4531-8550-0394c3273c4f
SamAccountName    : Administrators
SID               : S-1-5-32-544
```

We can also enumerate group membership using the `Get-ADGroupMember` cmdlet:

```powershell
PS C:\> Get-ADGroupMember -Identity Administrators -Server za.thedomain.com

distinguishedName : CN=Domain Admins,CN=Users,DC=za,DC=thedomain,DC=com

name              : Domain Admins
objectClass       : group
objectGUID        : 8a6186e5-e20f-4f13-b1b0-067f3326f67c
SamAccountName    : Domain Admins
SID               : S-1-5-21-3330634377-1326264276-632209373-512

[...]

distinguishedName : CN=Administrator,CN=Users,DC=za,DC=thedomain,DC=com name              : Administrator
objectClass       : user
objectGUID        : b10fe384-bcce-450b-85c8-218e3c79b30f
SamAccountName    : Administrator
SID               : S-1-5-21-3330634377-1326264276-632209373-500
```

### 3.4 **AD Objects**

A more generic search for any AD objects can be performed using the `Get-ADObject` cmdlet. For example, if we are looking for all AD objects that were changed after a specific date:

```powershell
PS C:\> $ChangeDate = New-Object DateTime(2022, 02, 28, 12, 00, 00)
PS C:\> Get-ADObject -Filter 'whenChanged -gt $ChangeDate' -includeDeletedObjects -Server za.thedomain.com

Deleted           :
DistinguishedName : DC=za,DC=thedomain,DC=com
Name              : za
ObjectClass       : domainDNS
ObjectGUID        : 518ee1e7-f427-4e91-a081-bb75e655ce7a

Deleted           :
DistinguishedName : CN=Administrator,CN=Users,DC=za,DC=thedomain,DC=com
Name              : Administrator
ObjectClass       : user
ObjectGUID        : b10fe384-bcce-450b-85c8-218e3c79b30f
```

If we wanted to, for example, perform a password spraying attack without locking out accounts, we can use this to enumerate accounts that have a badPwdCount that is greater than 0, to avoid these accounts in our attack:

```powershell
PS C:\> Get-ADObject -Filter 'badPwdCount -gt 0' -Server za.thedomain.com
```

### 3.5 **Altering AD Objects**

The great thing about the AD-RSAT cmdlets is that some even allow you to create new or alter existing AD objects. However, our focus for this network is on enumeration. Creating new objects or altering existing ones would be considered AD exploitation, which is covered later in the AD module.

However, we will show an example of this by force changing the password of our AD user by using the `Set-ADAccountPassword` cmdlet:

```powershell
PS C:\> Set-ADAccountPassword -Identity gordon.stevens -Server za.thedomain.com -OldPassword (ConvertTo-SecureString -AsPlaintext "old" -force) -NewPassword (ConvertTo-SecureString -AsPlainText "new" -Force)
```

## 4. **Bloodhound**

**BloodHound** models an Active Directory environment as a graph (nodes = users/computers/groups/OUs/etc., edges = relationships and privileges). It lets you discover the shortest, most actionable attack paths (e.g., how a low-privilege user can reach Domain Admin) so you can prioritize offensive action or defensive remediation.

Why it matters

* Turns noisy AD data into a queryable graph.
* Reveals non-obvious privilege chains created by nested groups, ACLs, sessions, and delegated rights.
* Great for red teams (find routes), blue teams (harden), and auditors (risk prioritization).

Key components

* **SharpHound** (collector) — gathers AD/host data.
* **Neo4j** — graph database backend.
* **BloodHound UI** — visual query / analysis front-end that connects to Neo4j and presents results.

### 4.1 **SharpHound**

SharpHound is the primary data collector. It issues LDAP/SMB/WinRM/RPC/NetSession calls to enumerate AD objects, ACLs, sessions, local admins, SPNs, GPOs, and more. It will generate logs — plan scope and timing. Use targeted collections in sensitive environments.

There are three different Sharphound collectors:

* **Sharphound.ps1** - PowerShell script for running Sharphound. However, the latest release of Sharphound has stopped releasing the Powershell script version. This version is good to use with RATs since the script can be loaded directly into memory, evading on-disk AV scans.
* **Sharphound.exe** - A Windows executable version for running Sharphound.
* **AzureHound.ps1** - PowerShell script for running Sharphound for Azure (Microsoft Cloud Computing Services) instances. Bloodhound can ingest data enumerated from Azure to find attack paths related to the configuration of Azure Identity and Access Management.

Common methods you’ll use (each produces JSON files used by BloodHound):

* `All` — everything (comprehensive, noisy).
* `Session` / `LoggedOn` — who’s logged on where (HasSession edges).
* `LocalAdmin` — local administrators on machines.
* `GroupMembership` / `Group` — group membership edges.
* `ACL` — object ACLs (who can modify/read/replicate). Critical for privilege escalation vectors.
* `SPN` — servicePrincipalName records (Kerberoast candidates).
* `GPO` / `SYSVOL` — GPOs and SYSVOL info.
* `ObjectProps` — attributes that help identify interesting accounts/services.

Pick methods based on your objective. `All` for initial full mapping in safe labs; targeted for stealth.

#### **How to run SharpHound:**

PowerShell (Invoke-BloodHound from SharpHound.ps1):

```powershell
# Import and run full collection
Import-Module .\SharpHound.ps1
Invoke-BloodHound -CollectionMethod All -Domain za.thedomain.com -ZipFileName sharp_all.zip

# Targeted: sessions + local admins + group membership
Invoke-BloodHound -CollectionMethod Session,LocalAdmin,GroupMembership -ZipFileName sharp_targeted.zip
```

SharpHound executable:

```powershell
# Full
SharpHound.exe -c All -zipfile sharp_all.zip
# OR
SharpHound.exe --CollectionMethods All --Domain za.thedomain.com --ExcludeDCs

# Targeted
SharpHound.exe -c Session,LocalAdmin -zipfile small.zip
```

bloodhound-python (non-Windows collector):

```bash
python bloodhound.py -u 'user' -p 'pass' -d za.thedomain.com -c All --zip data.zip
```

* Use `-CollectionMethod` (or `-c`) to limit footprint.
* Exclude high-value hosts or noisy AD partitions when on constrained ops. `-ExcludeDCs` will instruct Sharphound not to touch domain controllers, which reduces the likelihood that the Sharphound run will raise an alert.
* Specify domain and domain controllers where possible.
* Compress output to ZIP for upload to BloodHound UI.

#### **Output & delivery**

* SharpHound produces a ZIP of JSON files (`nodes_*.json`, `edges_*.json`).
* In red-team ops, exfil the ZIP securely and ingest it into your local BloodHound instance.
* In blue-team ops, upload to a controlled Neo4j instance for analysis.

### 4.2 **Neo4j**

* `neo4j start` → runs Neo4j **in the background** (keeps running after you close the terminal).
* `neo4j console` → runs Neo4j **in the foreground** (shows logs, stops when you close the terminal).

```bash
┌──(l㉿kshay)-[~]
└─$ sudo neo4j start            
Directories in use:
home:         /usr/share/neo4j
config:       /usr/share/neo4j/conf
logs:         /etc/neo4j/logs
plugins:      /usr/share/neo4j/plugins
import:       /usr/share/neo4j/import
data:         /etc/neo4j/data
certificates: /usr/share/neo4j/certificates
licenses:     /usr/share/neo4j/licenses
run:          /var/lib/neo4j/run
Starting Neo4j.
Started neo4j (pid:5539). It is available at http://localhost:7474
There may be a short delay until the server is ready.

┌──(l㉿kshay)-[~]
└─$ sudo neo4j console
Directories in use:
[...]
```

Security note: change default credentials and secure Bolt/HTTP endpoints if the DB is accessible on a network.

```bash
┌──(l㉿kshay)-[~]
└─$ bloodhound --nosandbox
```

### 4.3 **Ingesting SharpHound data into BloodHound UI**

1. Start Neo4j and open BloodHound UI (Electron app).
2. Connect BloodHound UI to Neo4j: Bolt URL `bolt://<neo4j_host>:7687`, username `neo4j`, password `neo4j`(Default) or you set.
3. In the BloodHound UI: **Upload Data** → choose the SharpHound ZIP.
4. After ingestion, confirm node/edge counts and check for errors in the UI status/log.

If you prefer API or CLI ingestion, BloodHound provides endpoints and community scripts to push JSON into Neo4j directly — but the UI upload is simplest.

For more info refer the [Documentaion](https://bloodhound.specterops.io/home)

### 4.5 Session Data Only

The structure of AD does not change very often in large organisations. There may be a couple of new employees, but the overall structure of OUs, Groups, Users, and permission will remain the same.

However, the one thing that does change constantly is active sessions and LogOn events. Since Sharphound creates a point-in-time snapshot of the AD structure, active session data is not always accurate since some users may have already logged off their sessions or new users may have established new sessions. This is an essential thing to note and is why we would want to execute Sharphound at regular intervals.

A good approach is to execute Sharphound with the "All" collection method at the start of your assessment and then execute Sharphound at least twice a day using the "Session" collection method. This will provide you with new session data and ensure that these runs are faster since they do not enumerate the entire AD structure again. The best time to execute these session runs is at around 10:00, when users have their first coffee and start to work and again around 14:00, when they get back from their lunch breaks but before they go home.

You can clear stagnant session data in Bloodhound on the Database Info tab by clicking the "Clear Session Information" before importing the data from these new Sharphound runs.

## 5. Through Microsoft Management Console

We can also use the Microsoft Management Console (MMC) with the [Remote Server Administration Tools](https://docs.microsoft.com/en-us/powershell/module/activedirectory/?view=windowsserver2022-ps) (RSAT) AD Snap-Ins.

---

## *EOF*
