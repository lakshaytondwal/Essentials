# Enumerating AD using PowerView

## Prerequisites / Setup

```powershell
# Download PowerView (if you already have it)
# Import it into the current session:
Import-Module .\PowerView.ps1

# If you have the module as a script:
. .\PowerView.ps1   # dot-source to bring functions into scope
```

* If you run into constrained language or AMSI issues, that's a detection mechanism. Use authorized labs.
* PowerView works best on domain-joined systems with proper DNS access to domain controllers.

---

## Table of contents

1. Domain & Forest discovery
2. Domain controller & replication info
3. Users enumeration
4. Groups & nested group enumeration
5. Computers & OS/service enumeration
6. Local admin enumeration
7. Sessions, logged-on users, and shares
8. Kerberos / SPN / constrained delegation enumeration
9. ACL & delegation enumeration (Get-ObjectAcl family)
10. GPO & policy enumeration
11. Trusts and cross-domain information
12. Output, filtering, and parsing best practices
13. Detection & defensive notes
14. Quick reference cheat sheet

---

## 1. Domain & Forest discovery

Quickly learn the forest/domain names, DNS, and high-level topology.

```powershell
Get-Domain
Get-Domain | Format-List *

Get-NetForest
Get-NetForest | Format-List *

Get-DnsRecord -ZoneName (Get-Domain).DNSRoot -Type A
Get-DomainController
Get-DomainController -Domain (Get-Domain).DomainName
```

**What this reveals:** domain/forest names, domain controllers, DNS info, basic topology.
**Defensive note:** Monitor rare queries for `Get-NetForest` or repeated DC enumerations.

---

## 2. Domain Controllers & replication info

Find DCs, their OS, roles, and replication partners:

```powershell
Get-DomainController -Discover
Get-DomainController -Domain (Get-Domain).DomainName | Format-Table name,operatingsystem,site,ipv4address

Get-NetForestDomainController
Get-ADDomainController -Filter *    # native cmdlet; useful in combo
```

**Why:** DCs are high-value targets; knowing them is the first step in mapping attack surface.

---

## 3. Users enumeration

List users, attributes, last logons, and special accounts:

```powershell
# All users
Get-NetUser
Get-NetUser | Format-Table samaccountname,displayname,enabled,lastlogon,lastlogontimestamp

# Specific user detail
Get-NetUser -UserName alice | Format-List *

# Users with SPNs (Kerberoast targets)
Get-NetUser -SPN
# Users with servicePrincipalName populated:
Get-NetUser | ? { $_.serviceprincipalname -ne $null } | select samaccountname,serviceprincipalname

# Users with adminCount (potential privileged accounts)
Get-NetUser | ? { $_.admincount -eq 1 } | select samaccountname,displayname,admincount

# Users with KerberosPreAuthDisabled (useful to spot legacy accounts)
Get-NetUser | ? { $_.UserAccountControl -band 4194304 } | select samaccountname
```

**What to look for:** SPNs (Kerberoast), `adminCount=1`, disabled vs enabled, stale lastlogon timestamps.
**Defensive:** alert on enumeration of all users or repeated SPN enumeration.

---

## 4. Groups & nested group enumeration

List groups, members, nested membership, and privileged groups.

```powershell
# All groups
Get-NetGroup
Get-NetGroup | Format-Table samaccountname,description

# Members of a particular group
Get-NetGroup -GroupName "Domain Admins" -Resolve | Format-Table membername,objectclass

# Nested groups (recursively)
Get-NetGroup -GroupName "Domain Admins" -Resolve -Recursive

# Who is in privileged groups (predefined)
$priv = "Domain Admins","Enterprise Admins","Schema Admins","Administrators"
foreach ($g in $priv) { Get-NetGroup -GroupName $g -Resolve -Recursive | select membername,objectclass }
```

**What this reveals:** group membership, nested privilege chains.
**Defensive:** harden and monitor changes to privileged groups; log recursive expansion.

---

## 5. Computers & OS/service enumeration

Find domain-joined machines, services, and patch/OS details.

```powershell
# All computers
Get-NetComputer
Get-NetComputer | Format-Table name,operatingsystem,lastlogon

# Find systems with RDP open (uses queries to netstat-like data if available)
Get-NetComputer -FullData | ? { $_.operatingsystem -like "*Server*" } | select name,operatingsystem,distinguishedname

# Filter by OS or last logon
Get-NetComputer | ? { $_.operatingsystem -match "Windows Server" } | select name,operatingsystem
```

**What to watch:** older OS versions, server-class machines, jump hosts.
**Defensive:** asset inventory vs what attackers can discover should match — alert on wide sweeps.

---

## 6. Local admin enumeration

Find which accounts are local admins on computers (common lateral movement vector).

```powershell
# Query local admin group membership across computers (requires rights)
Invoke-UserHunter -Verbose   # tries to find which hosts users are logged into (and local admin info)

Get-NetLocalGroup -ComputerName targethost -GroupName "Administrators"
# Or scan multiple hosts (may require credentials)
$computers = Get-NetComputer | select -ExpandProperty name
foreach ($c in $computers) { Get-NetLocalGroup -ComputerName $c -GroupName "Administrators" | select ComputerName,MemberName }
```

**What this reveals:** which accounts have local admin across the fleet.
**Defensive:** centralize local admin via LAPS or restricted groups, monitor cross-host local admin queries.

---

## 7. Sessions, logged-on users, and shares

Map active sessions, open file shares, and who is logged on where.

```powershell
# Who's logged on where (session enumeration)
Get-NetSession
Get-NetSession -ComputerName targethost

# Active sessions across domain
Get-NetLoggedon
Get-NetLoggedon -UserName alice

# SMB/CIFS shares
Get-NetShare -ComputerName targethost
```

**Why:** reveals lateral movement paths and valuable sessions (e.g., where a Domain Admin is logged in).
**Defensive:** monitor anomalous `NetSession` style queries; credential theft detection.

---

## 8. Kerberos / SPN / delegation enumeration

Identify SPNs, constrained delegation, and AS-REP/Kerberoast-susceptible accounts.

```powershell
# Accounts with SPNs (Kerberoast candidates)
Get-NetSPN
Get-NetUser -SPN

# Users with unconstrained or constrained delegation flags
Get-ADUser -Filter * -Properties msDS-AllowedToDelegateTo,TrustedForDelegation,TrustedToAuthForDelegation | 
  ? { $_.TrustedToAuthForDelegation -eq $true -or $_.TrustedForDelegation -eq $true -or $_.msDS-AllowedToDelegateTo } |
  select samaccountname,TrustedForDelegation,TrustedToAuthForDelegation,msDS-AllowedToDelegateTo

# AS-REP roastable (No preauth)
Get-NetUser | ? { $_.useraccountcontrol -band 4194304 } | select samaccountname
```

**What this reveals:** accounts vulnerable to Kerberoast or AS-REP roast attacks, delegation misconfigurations.
**Defensive:** enforce Kerberos pre-auth, monitor SPN ticket requests, limit delegation.

---

## 9. ACL & delegation enumeration (Get-ObjectAcl family)

This is the big one — PowerView can read object ACLs and show which principals have which rights. Use `Get-ObjectAcl`, `Find-ObjectDelegation`, and relevant filters.

```powershell
# Get ACL for a single user object
Get-ObjectAcl -SamAccountName targetuser -ResolveGUIDs

# Get ACL for a computer
Get-ObjectAcl -SamAccountName TARGETHOST$ -ResolveGUIDs

# Find all objects where a principal (e.g., 'YOURDOMAIN\User') has rights
Find-ObjectDelegation -Principals "YOURDOMAIN\YourUser"

# Enumerate interesting delegations across the domain
Find-InterestingDomainAcl -ResolveGUIDs

# Filter for specific rights
Get-ObjectAcl -SamAccountName targetuser -ResolveGUIDs |
  ? { $_.ActiveDirectoryRights -match "GenericAll|GenericWrite|WriteDacl|WriteOwner|AllExtendedRights|ForceChangePassword" }

# Show ACLs that grant GenericAll to groups/users
Get-ObjectAcl -SearchBase (Get-Domain).DistinguishedName -ResolveGUIDs |
  ? { $_.ActiveDirectoryRights -match "GenericAll" } |
  select ObjectDN,IdentityReference,ActiveDirectoryRights
```

**What the results mean:**

* `GenericAll` = complete control — immediate red flag.
* `GenericWrite` = can change attributes (may lead to scriptPath abuse, SPN registration).
* `WriteDACL` / `WriteOwner` = can change permissions or take ownership.
* `AllExtendedRights` often includes `ForceChangePassword` or other extended actions.
* ACL entries for groups you control = potential privilege escalation path.

**Defensive:** ACLs are a common stealthy attack vector. Monitor DACL changes, owner changes, and unusual ACE creation. Periodic ACL audits are essential.

---

## 10. GPO & policy enumeration

Find GPOs, permissions on GPOs, and who can write GPOs.

```powershell
# List GOP-like objects and permissions
Get-NetGPO

# Check who can modify GPOs (ACLs)
Get-ObjectAcl -SearchBase "CN=Policies,CN=System,$((Get-Domain).DistinguishedName)" -ResolveGUIDs |
  ? { $_.ObjectDN -like "*CN=Policies*" } | select ObjectDN,IdentityReference,ActiveDirectoryRights
```

**Why:** If you can write a GPO, you can push code/changes at scale. Protect the `CN=Policies` container.

---

## 11. Trusts and cross-domain info

Enumerate domain trusts and cross-domain admin relationships.

```powershell
Get-NetForestTrust
Get-Trust -Domain (Get-Domain).DomainName   # native cmdlet
Get-NetForestDomainController
```

**What to watch for:** External trusts, one-way trusts, or unconstrained trusts — these can be pivot paths.

---

## 12. Output, filtering, and parsing best practices

PowerView outputs lots of objects. Useful patterns:

```powershell
# Save to JSON for later processing
Get-NetUser | ConvertTo-Json -Depth 5 | Out-File users.json

# CSV
Get-NetComputer | Select name,operatingsystem,lastlogon | Export-Csv computers.csv -NoTypeInformation

# Filter by ACE rights quickly
(Get-ObjectAcl -SamAccountName targetuser -ResolveGUIDs) | Where-Object { $_.ActiveDirectoryRights -match "GenericAll" }
```

Use `-ResolveGUIDs` to map GUIDs to names — indispensable for readable ACLs.

---

## 13. Detection & defensive notes (short, brutal)

* **ACL changes** are stealthy and common in modern attacks. Log and alert on `WriteDACL`, `WriteOwner`, and `GenericAll` grants.
* **Mass enumeration** (Get-NetUser/Get-NetComputer/Get-ObjectAcl across the domain) should trigger alerts. Baseline normal AD queries.
* **SPN ticket requests** and `krbtgt` anomalous activity = Kerberoast/Golden Ticket signals — instrument Kerberos logs.
* **Local admin mapping**: use LAPS, reduce persistent local admin, and restrict local admin group modifications.
* **GPO writes**: monitor `CN=Policies` ACL changes.
* **Prevention:** principle of least privilege, ACL hardening, periodic ACL review (automated), centralized auditing (winlogbeat/SIEM).

---

## 14. Quick reference cheat sheet (commands only)

```powershell
Import-Module .\PowerView.ps1

# Domain info
Get-Domain
Get-DomainController
Get-NetForest

# Users
Get-NetUser
Get-NetUser -SPN
Get-NetUser -UserName alice

# Groups
Get-NetGroup
Get-NetGroup -GroupName "Domain Admins" -Resolve -Recursive

# Computers
Get-NetComputer

# Local admin
Get-NetLocalGroup -ComputerName targethost -GroupName "Administrators"

# Sessions/logged-on
Get-NetSession
Get-NetLoggedon

# SPN/Kerberos
Get-NetSPN
Get-NetUser -SPN

# ACLs / Delegation
Get-ObjectAcl -SamAccountName targetuser -ResolveGUIDs
Find-InterestingDomainAcl -ResolveGUIDs
Find-ObjectDelegation -Principals "YOURDOMAIN\YourUser"

# GPOs
Get-NetGPO

# Export
ConvertTo-Json | Out-File file.json
Export-Csv -NoTypeInformation file.csv
```

---
