#nmapscan 
```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 5.1p1 Debian 6ubuntu2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 3e:c8:1b:15:21:15:50:ec:6e:63:bc:c5:6b:80:7b:38 (DSA)
|_  2048 aa:1f:79:21:b8:42:f4:8a:38:bd:b8:05:ef:1a:07:4d (RSA)
80/tcp open  http    Apache httpd 2.2.12 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.2.12 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
#enumeration 
```
/.htpasswd            (Status: 403) [Size: 287]
/.hta                 (Status: 403) [Size: 282]
/.htaccess            (Status: 403) [Size: 287]
/cgi-bin/             (Status: 403) [Size: 286]
/index                (Status: 200) [Size: 177]
/index.html           (Status: 200) [Size: 177]
/test                 (Status: 200) [Size: 47032]
Progress: 4082 / 4615 (88.45%)                  [ERROR] 2021/08/04 00:50:59 [!] Get "http://10.10.10.6/server-status": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
/torrent              (Status: 301) [Size: 310] [--> http://10.10.10.6/torrent/]
```
after that I moved to /torrent and found a option to upload to torrent file so searched about ways exploit torrent file uploads or how to bypass them and i ran into a blog
link:https://infinitelogins.com/2020/08/07/file-upload-bypass-techniques/

#reverseshellupload 
According to the link once we upload a torrent file it will redirect us to a page where we will have option to upload a png or jpeg file and it also told us how to bypass it
so I renamed the php reverse shell to .png.php file and uploaded it and intercepted the POST request once after uploading with gobuster and change the content type to image/png and sent the request.Our reverseshell got uploade to /torrent/upload directory and then we ran it and listen to netcat to get the reverse shell.
#rootescalation 
METHOD-1:
ran uname -r and got the linux version linux 2.6.31.
searched google and searchsploit and got exploits of dirtycow.
link:https://github.com/FireFart/dirtycow/blob/master/dirty.c
uploaded the c file compiled it and ran dirty cow .
to compile:```gcc -pthread dirty.c -o dirty -lcrypt```
to run:``` ./dirty apple```
we got the user firefart:apple overwritten in place of root.It was kernal exploit and messd up the terminal so i opened a new terminal and ssh login with firefart:apple
and we get our root terminal.
Now, it was the unintended way as it was a linux old machine it was ofc exploitable by dirty cow.
INTENDED WAY:
The intended way that there was a motd file in .cache in home directory of george
(user)and surfing google I got a exploit of motd file it was much similar to dirty cow and was also a kernal exploit.
link:https://www.exploit-db.com/exploits/14339