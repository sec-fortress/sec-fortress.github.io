# SOURCE TRYHACKME
***
## DIFFICULTY : EASY
![image](https://github.com/sec-fortress/sec-fortress.github.io/assets/132317714/343788f7-9c7c-478a-b8b7-c6b81277fb2a)

***

A quick nmap scan gives us this:

![image](../images/Pasted%20image%2020230622231249.png)

We can see that port 22<ssh> and port 10000<http> are open!!

***
### Enumerating Port 1000
***

Navigating to the site we see that it has a logon page:

![image](../images/Pasted%20image%2020230622231407.png)

- After much invalid attempt to guess the password and username, we decided to find out what vulnerability the protocol uses and it was vulnerable to RCE **[CVE-2019-15107, CVE-2019-15231](https://infosecmatter.com/nessus-plugin-library/?id=127911)** using `Metasploit`:

![image](../images/Pasted%20image%2020230622231909.png)

- Firing up **Metasploit**,we can set our exploit just as shown in the image below, Make sure **ssl is set to true** and do `run` OR `exploit`:

![image](../images/Pasted%20image%2020230622232212.png)

- We successfully got a shell as **root**, no much stuff or **priv esc**🥴.
- We can now get a stabilized shell using `python -c "import pty; pty.spawn('/bin/bash')"`.
- Navigate the file system and extract flags.

![image](../images/Pasted%20image%2020230622234651.png)

Thanks🛳️✈️

<button onclick="window.location.href='https://sec-fortress.github.io';">Back To Home螥</button>

