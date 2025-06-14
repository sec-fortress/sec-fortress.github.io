## Access Control Vulnerabilities

***
**Access control flaws occur when applications fail to properly enforce who can access what — allowing attackers to view or modify data and actions beyond their intended permissions. In this blog, Explore common types of access control vulnerabilities such as Insecure Direct Object References (IDOR), vertical and horizontal privilege escalation, and bypass techniques using headers like `X-Original-URL`.**

***

## **Lab: Unprotected admin functionality**

Fuzz for hidden endpoints to extract admin panel using `feroxbuster`


```bash
❯ feroxbuster -u "https://0acb00a40321dbbf81d3256800530037.web-security-academy.net/" --status-codes 200,201,301,302,304 --wordlist /usr/share/seclists/Discovery/Web-Content/big.txt
```


![image](https://github.com/user-attachments/assets/46385b55-2f0e-4afd-9ba4-e3ee740427a4)



Then delete user `carlos` as requested by the lab


![](https://i.imgur.com/tvL723m.png)



## **Lab: Unprotected admin functionality with unpredictable URL**


Navigating to the `/login` endpoint and viewing source code

![](https://i.imgur.com/s0gld72.png)


Hidden admin endpoint found, delete user `carlos` as requested


![](https://i.imgur.com/wlrXq4I.png)



## **Lab: User role controlled by request parameter**



> [!todo]
> 
> This lab has an admin panel at `/admin`, which identifies administrators using a forgeable cookie.
> 
> Solve the lab by accessing the admin panel and using it to delete the user `carlos`.
> 
> You can log in to your own account using the following credentials: `wiener:peter`


Accessed the admin panel with user `wiener` session


![](https://i.imgur.com/VLQ3ti8.png)


Intercepted the request using burpsuite and we can alterate the `Admin=` value


![](https://i.imgur.com/Yliw817.png)


Change parameter value to `true` and we can delete user `carlos`


![](https://i.imgur.com/9wOu7iq.png)



## **Lab: User role can be modified in user profile**


Upon log-in, found out there is an update email feature


![](https://i.imgur.com/6b07Ilj.png)



On the backend, there is too much parameter exposed when updating just email like;

- **`apikey`**: identify and authenticate users
- **`roleid`**: determine admin users or non-admin users

![](https://i.imgur.com/D4V40Cu.png)


Add apikey, roleid, username and email parameter to request and send using `roleid=2`

![](https://i.imgur.com/MtQAqIk.png)


If no proper validation, backend will accept this and access admin panel with user `wiener` session


![](https://i.imgur.com/Woe13K7.png)


## **Lab: User ID controlled by request parameter**


Log-in as user `wiener` and you have the user **API Key**


![](https://i.imgur.com/dLmjY5R.png)


Notice parameter; `/my-account?id=wiener` can be changed to `/my-account?id=carlos`, Get **API Key**  for user `carlos` and submit


![](https://i.imgur.com/574jUxC.png)



## **Lab: User ID controlled by request parameter, with unpredictable user IDs**


Clicking on a post, found highlighted user link

![](https://i.imgur.com/efZJJ9n.png)


Clicking on the user link and grab user `carlos` GUID at the parameter; `?userId=a1f38cc4-e47e-434b-b51b-9dd8d928fbea`


Replace GUID on the **"My account"** page with user `carlos` GUID and submit **API Key**


![](https://i.imgur.com/uqpSzFf.png)


## **Lab: User ID controlled by request parameter with data leakage in redirect**


Log-in as user `wiener` and change parameter `/my-account?id=wiener` to `/my-account?id=carlos`


![](https://i.imgur.com/GGN1AT8.png)



Redirection happens fast to `/login` so you need to intercept request to get user carlos API key


![](https://i.imgur.com/Apn9UBB.png)



## **User ID controlled by request parameter with password disclosure**


Log-In as user `wiener`, the password field is masked on the front end and the user `id` is passed via a `GET` request 


![](https://i.imgur.com/sre8h7S.png)



It is possible to see the clear-text password by inspecting element 

![](https://i.imgur.com/ZANP3Rr.png)


Change the `id=` parameter to **administrator** and we have clear text password for the administrator user


![](https://i.imgur.com/GlBQKI1.png)


Log-in as user **administrator** and delete user **carlos** as requested 


![](https://i.imgur.com/UxkVy56.png)


## **Lab: Insecure direct object references**


Checking the "**Live chat**" session, there is an auto reply bot in action, whether you send a message or not, it replies as long as the "**Send**" button is clicked

![](https://i.imgur.com/RdIvpR5.png)


The "**View transcript**" button tries to download `TXT` conversations when you click it

![](https://i.imgur.com/wjoy5fA.png)

The below code is responsible for this and also shows where the IDOR vulnerability is located


**_URL_ ->** https://0ad70055037cce3780e69eba00340010.web-security-academy.net/resources/js/viewTranscript.js


```JavaScript
        var xhr = new XMLHttpRequest();
        xhr.onload = function() {
            window.location = xhr.responseURL;
        }
        xhr.open("POST", downloadTranscriptPath);
        data = new FormData();
        data.append("transcript", transcript.join("<br/>"));
        xhr.send(data);
    }
};
```

> The above shows that a POST request is made to a download endpoint with the user's conversation data., since the conversations uses numerical naming conversations, it is possible for an attacker to guess/fuzz for the right number with the user `carlos` password


As shown below with burpsuite, conversations are been logged by the website, with numerical naming conventions


![](https://i.imgur.com/24Tg5OR.png)


Send to repeater and guess the right numerical value and the password value for user `carlos` was found

![](https://i.imgur.com/zh43KWn.png)


Then login as user `carlos` with the retrieved password to solve the lab


![](https://i.imgur.com/M7zAqn4.png)



## **Lab: URL-based access control can be circumvented**

Navigating to the `/admin` URL, Access is denied

```
❯ curl https://0ace003d0422bc1c82756a0600d0002d.web-security-academy.net/admin
"Access denied"
```

The lab description says; "_**.....the back-end application is built on a framework that supports the `X-Original-URL` header.....**_"

Bypass this restriction by going to a URL with access and use the `X-Original-URL: /admin` to view the admin page

![](https://i.imgur.com/VttRg7d.png)

Place the parameter `?username=carlos` and the delete path in the `X-Original-URL: /admin/delete` to delete user `carlos`

![](https://i.imgur.com/vddz7W5.png)


## **Lab: Method-based access control can be circumvented**

Checking user roles, Only one ADMIN role has been given to the **administrator**


![](https://i.imgur.com/C2SJAO2.png)

The lab requires using user `wiener` account session to promote themselves to become an administrator.


Intercepting request with burpsuite, when the administrator user tries to promote user wiener, a POST request is made as shown below to the `/admin-roles`

![](https://i.imgur.com/8l8fmE8.png)


Log-in as user `wiener` and try to use a GET request to promote user `wiener` to the **ADMIN** role which as shown below is successful

![](https://i.imgur.com/y4GWPvE.png)



## **Lab: Multi-step process with no access control on one step**


Log-in as the administrator user, Only one `ADMIN` role has been given to the **administrator** user


![](https://i.imgur.com/drFcsbI.png)


Prompted with a **vibe check** 🤣 this time and "**No, take me back**" can be selected cos' we need to use user `wiener` session to promote themselves to the `ADMIN` role

![](https://i.imgur.com/c5MqrgS.png)


Log-out as user `administrator` and log-in as user `wiener` and we can use our previous logged request in burpsuite to craft a POST request to upgrade user `wiener` to the `ADMIN` role as shown below


![](https://i.imgur.com/wbYKiIU.png)


Successfully solved the lab

![](https://i.imgur.com/GAmb8gG.png)


## **Lab: Referer-based access control**


Log-In as the `administrator` user, try to downgrade user `wiener`  and a GET request is made to the below URL as shown in the below screenshot


![](https://i.imgur.com/YGrQAuu.png)


Log-in as user `wiener` and tried same request with authorization error  


![](https://i.imgur.com/BbuAg7x.png)

However if you notice in the previous request while using the `administrator` account the referrer header points to `/admin`


```
Referer: https://0a7a008704e50bf28052805c0005001b.web-security-academy.net/admin
```

Change Referrer header to `/admin` and try to upgrade user `wiener` again with their session to solve the lab

![](https://i.imgur.com/gI4Ztm6.png)


## Resources

- [https://owasp.org/www-community/Access_Control](https://owasp.org/www-community/Access_Control)
- [https://owasp.org/www-community/Broken_Access_Control](https://owasp.org/www-community/Broken_Access_Control)
- [https://portswigger.net/web-security/access-control](https://portswigger.net/web-security/access-control)
- [https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html)


<button onclick="window.location.href='https://sec-fortress.github.io';">Back To Home螥</button>

