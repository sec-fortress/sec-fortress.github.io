# Writing a Ping sweep script
**A ping sweep can be defined as performing an entire ICMP echo request on a network, let's go:**

first thing is to perform an ICMP request with:
- `ping -c 1 <ip> > ip.txt`
	- we are telling `ping` to perform the request with the -c option only once and then save it to a txt file.
   
``` OUTPUT

PING 192.168.0.157 (192.168.0.157) 56(84) bytes of data.
64 bytes from 192.168.0.157: icmp_seq=1 ttl=64 time=0.056 ms

--- 192.168.0.157 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.056/0.056/0.056/0.000 ms
```

Now let tweak our txt file
- We can do `cat ip.txt | grep "64 bytes" | cut -d " " -f 4 | tr -d ":"`
	-  Now here, we are concatinating out the text in **ip.txt**, then sending a pipe to **grep** only the lines that has **64 bytes**, after that:
 
	   ![image](../images/pingsweep_script/Pasted%20image%2020230622002127.png)
    
	   Then the next pipe which is **cut** set a delimeter, in other to cut out only the text after 4 spaces with the `-f 4` option, setting it to 3 or 2 will cut from the number of spaces 
           given, Output:
    
	   ![image](../images/pingsweep_script/Pasted%20image%2020230622002410.png)
    
	   Now we have to remove the semicolon, that isn't an IP with the semicolon, we could just do the `tr -d ":"` whereby tr stands for **translator** and we set a delimeter as usual to remove any symbol with **':'**	   
	   ![image](../images/pingsweep_script/Pasted%20image%2020230622002707.png)
    
# Creating our Bash script
**Subject:** Ping Sweep Script Available - Check it out!

Dear friends,

I'm excited to share that I have successfully created a ping sweep script that allows you to scan a range of IP addresses and perform an Nmap scan on the discovered hosts. This script can be a handy tool for network administrators and security enthusiasts.

You can access the script through this link: [Ping_Sweep_script](https://github.com/sec-fortress/Ping_sweeper)

To use the script, simply follow the instructions provided in the README file. Make sure you have the necessary prerequisites mentioned in the README, such as a Bash shell and Nmap.

Please note that it's important to use this script responsibly and only on networks where you have permission to scan.

I hope you find this script useful and that it simplifies your IP scanning tasks. If you have any questions or feedback, feel free to reach out to me.

Happy scanning!

Best regards,  
[Olaoluwa]

<button onclick="window.location.href='https://sec-fortress.github.io';">Back To Home螥</button>
