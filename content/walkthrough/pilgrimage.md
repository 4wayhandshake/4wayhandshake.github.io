---
title: "Pilgrimage"
date: 2023-06-25T18:00:00-00:00
publishdate: 2024-02-24T18:00:00-00:00
releasedate: 2023-06-24T18:00:00-00:00
draft: false
hideTitle: false
Cover: /htb-info-cards/Pilgrimage.png
icon: /htb-box-icons/Pilgrimage.png
toc: true
tags: ["CVE", "ImageTragick", "File Disclosure", "Git", "Binwalk", "Malicious Plugin"]
categories: ["Walkthrough", "HTB", "Linux", "Easy"]
---

## INTRODUCTION

At the time of writing this walkthrough, Pilgrimage is still an Active box. It was released as the second box for HTB's *Hackers Clash: Open Beta Season II*. The box features a webserver, hosting an application that shrinks images uploaded by the user, halving both the width and height of the image. 

![index](index.png)



## RECON

For this box, I'm running the same enumeration strategy as the previous box, [Sandworm](/sandworm/walkthrough.html). I set up a directory for the box, with a `nmap` subdirectory. Then set `$RADDR` to my target machine's IP, and scanned it with a simple but broad port scan:

```bash
sudo nmap -p- -O --min-rate 5000 -oN nmap/port-scan.txt $RADDR
```

The results showed only ports 22 (SSH), and 80 (HTTP):

```
Nmap scan report for pilgrimage.htb (10.10.11.219)
Host is up (0.15s latency).
Not shown: 65392 closed tcp ports (reset), 141 filtered tcp ports (no-response)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

I followed up with a more detailed script scan that would include the above ports:

```bash
nmap -sV -sC -n -Pn --top-ports 2000 -oN nmap/init-scan.txt $RADDR
```

The results show a typical webserver running on port 80:

```
Host is up (0.22s latency).
Not shown: 1998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 20be60d295f628c1b7e9e81706f168f3 (RSA)
|   256 0eb6a6a8c99b4173746e70180d5fe0af (ECDSA)
|_  256 d14e293c708669b4d72cc80b486e9804 (ED25519)
80/tcp open  http    nginx 1.18.0
|_http-server-header: nginx/1.18.0
|_http-title: Did not follow redirect to http://pilgrimage.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```



### Webserver Strategy

Did banner-grabbing, noticed that port 80 is redirecting to http://pilgrimage.htb. Also, server is using nginx 1.18.0:

```bash
whatweb $RADDR && curl -IL http://$RADDR
```

Added `pilgrimage.htb` to /etc/hosts and proceeded with vhost enumeration, subdomain enumeration, and directory enumeration.

```bash
echo "10.10.11.219 pilgrimage.htb" | sudo tee -a /etc/hosts
```

> ☝️ I use `tee` instead of the append operator `>>` so that I don't accidentally blow away my `/etc/hosts` file with a typo of `>` when I meant to write `>>`.

I performed vhost and subdomain enumeration:

```bash
WLIST="/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt"
ffuf -w $WLIST -u http://$RADDR/ -H "Host: FUZZ.htb" -c -t 60 -o fuzzing/vhost.md -of md -timeout 4 -ic -ac
```

```bash
ffuf -w $WLIST -u http://FUZZ.$DOMAIN/ -c -t 60 -o fuzzing/subdomain.md -of md -timeout 4 -ic -ac
```

No results from vhost or subdomain enumeration, so I proceeded with directory enumeration on http://pilgrimage.htb:

```bash
WLIST="/usr/share/seclists/Discovery/Web-Content/raft-small-directories-lowercase.txt"
feroxbuster -w $WLIST -u http://$DOMAIN -A -d 1 -t 100 -T 4 -f --auto-tune --collect-words --filter-status 400,401,402,403,404,405 --output fuzzing/directory.json -E
```

Directory enumeration gave the following:

![feroxbuster](feroxbuster.png)



### Exploring the Website

I took a look through the website; tried the image shrinking feature. I don't know. Did it work?

![64975a1f2882a](64975a1f2882a.jpeg)

Still cute. But is it smaller?

```
file beaver.jpeg
```

```
beaver.jpeg: JPEG image data, JFIF standard 1.01, aspect ratio, density 1x1, segment length 16, Exif Standard: [TIFF image data, little-endian, direntries=2, software=Google], baseline, precision 8, 900x900, components 3
```

compared to the shrunk version ...

```
file 64975a1f2882a\ smaller.jpeg
```

```
64975a1f2882a smaller.jpeg: JPEG image data, JFIF standard 1.01, aspect ratio, density 1x1, segment length 16, Exif Standard: [TIFF image data, little-endian, direntries=2, software=Google], baseline, precision 8, 450x450, components 3
```

```
ll | grep beaver ; ll | grep 64975                                                                                                                                                          
-rw-r--r-- 1 kali kali   88952 Jun 16 02:07 beaver.jpeg
-rw-r--r-- 1 kali kali   56836 Jun 25 00:03 64975a1f2882a smaller.jpeg
```

Indeed, it is smaller. 

> 🤔 Given that it halved both the width and height, you'd think that it'd cut the file size down to a quarter of the original size - which it clearly did not. Seems odd. 

Let's keep exploring the site a bit. There's a login page at http://pilgrimage.htb/login.php. I'll try some obvious credentials like **admin : admin** just to check for low-hanging fruit, as they say. 

Unfortunately, none worked. What about some SQL auth bypass?

![auth bypass attempt](auth%20bypass%20attempt.png)

Nope. That didn't work either. No worries, I'll just try making an account using http://pilgrimage.htb/register.php for now and log in with that. I created an account with credential **jimbo : password** and proceeded to the dashboard. As expected, there were no entries. 

I tried shrinking a couple more images (logged in this time) and, as expected, the images were listed under /dashboard.php.



## FOOTHOLD

### File Disclosures

It's likely that this service is utilizing a program called *ImageMagick*, which can be used for things like resizing and compressing images. Personally, I use it quite often via the program `convert` for resizing hi-res images down to something I can post on the web. I've ran into a few web challenges (and one HTB box) before where the exploit to gain a foothold was something to do with abusing *ImageMagick*. For context, ImageMagick was the subject of a whole family of CVEs back in 2016 called ImageTragick. I checked PayloadAllTheThings and found that there was a new incarnation of ImageTragic: [CVE-2022-44268 shown here](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files/Picture%20ImageMagick). Maybe I'll give that a go?

First, I installed `pngcrush` and its deps. I downloaded a random png file, saving it as `exploit.png`. Then, I tried the provided command: 

```
pngcrush -text a "profile" "/etc/passwd" exploit.png
```

Unfortunately that didn't work, but I'll keep trying. I did some more searching on CVE-2022-44268, and found a YouTube video demonstrating a PoC of its exploitation on a Vulnmachines box. There was was some [PoC code to go along with the Vulnmachines box](https://github.com/Vulnmachines/imagemagick-CVE-2022-44268), so I tried downloading and using that.

I ran the code as follows, first getting the poc.py to generate an image `exploit.py`:

```bash
chmod u+x poc.py
python3 poc.py -o exploit.png -r /etc/passwd generate
```

This image should contain an exploit to disclose `/etc/passwd` when processed by *ImageMagick*. I tried uploading it to have it resized. Much to my surprise, the server accepted and processed the image:

![processed imageTragick](processed%20imageTragick.png)

Then I downloaded the 'converted' image, saving as `out.png`, and ran it through the same PoC code to parse the output:

```
python3 poc.py -i out.png parse
```

![file disclosure poc](file%20disclosure%20poc.png)

Success! Now I just need to figure out how I can harness this best 🤔

But first, that got me wondering, why did one attempt at CVE-2022-44268 work while another didn't? I'll try the one from PayloadAllTheThings again and see if I messed up something obvious...

First, I'll use pngcrush to embed a file read into an existing png file, `exploit.png`:

```
pngcrush -text a "profile" "/etc/hosts" exploit.png
```

OH! *facepalm* I had not read the output carefully enough 😱. This command generated a new file called `pngout.png`:

![pngcrush](pngcrush.png)

Then I uploaded the file `pngout.png` to the website for conversion, converted it successfully, then downloaded the file as `pngout-out.png`. I read the file using `identify`:

```bash
identify -verbose pngout-out.png
```

This showed quite a lot of text, including a big block of hex somewhere near the bottom. I quickly copied this to a text editor, removed the line breaks, and read the hex using python ([as suggested on PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files/Picture%20ImageMagick#cve-2022-44268)):

```
python3 -c 'print(bytes.fromhex("3132372e302e302e31096c6f63616c686f73740a3132372e302e312e310970696c6772696d6167652070696c6772696d6167652e6874620a0a232054686520666f6c6c6f77696e67206c696e65732061726520646573697261626c6520666f7220495076362063617061626c6520686f7374730a3a3a3120202020206c6f63616c686f7374206970362d6c6f63616c686f7374206970362d6c6f6f706261636b0a666630323a3a31206970362d616c6c6e6f6465730a666630323a3a32206970362d616c6c726f75746572730a").decode("utf-8"))'
```

The result was indeed the target's /etc/hosts file:

![disclosed etc hosts](disclosed%20etc%20hosts.png)

Ok, good to know it was just a silly mistake. Still unclear how I'll use this to gain RCE though. 

I figured it was probably a good idea to take a look at the .php files that comprise the website, such as `index.php`, `dashboard.php`, and `login.php`. However, I seem to be unable to read any of those files using either exploit for CVE-2022-44268. It seems like maybe the exploits require an absolute filepath. I tried all kinds of filepaths, none of which worked. Attempts included the following:

- /var/www/index.php
- /var/www/html/index.php
- /var/www/pilgrimage/index.php
- /var/www/html/pilgrimage/index.php
- /var/www/pilgrimage/html/index.php

Perhaps I'll check for an .htpasswd file and leak some credentials or hashes. Since the user is `www-data`, this might be using apache, in which case the htpasswd file will be at `/etc/apache2/.htpasswd`

Nope, no luck. After parsing, the data came back empty. But maybe there's something to this: searching for a file marked hidden in the directory structure. I'll go back to directory enumeration, this time looking for hidden directories:

```bash
WLIST="/usr/share/seclists/Discovery/Web-Content/raft-small-directories-lowercase.txt"
ffuf -w $WLIST:FUZZ -u http://pilgrimage.htb/.FUZZ -t 80 --recursion --recursion-depth 2 -c -timeout 4 -fc 403
```

> ☝️ I've found that ffuf is the best at rapidly enumerating exactly what you want. It doesn't try to interpret things like a dot in the url. It just does exactly what it's supposed to do: substitute values in a wordlist for the FUZZ parameter.

Within seconds, fuff showed that I had failed to enumerate a **.git** directory! Also, it showed three URLs giving an HTTP 200 status:

- /.git/index
- /.git/config
- /.git/description



### GitHacker

I tried navigating to each of the above files discovered with ffuf. A GET request to each URL yielded a download of the corresponding git file. The files `config` and `description` were both uninteresting, but `index` had quite a bit of garbled text in it (just like a typical .git/index file). It would be a lot better if I could simply view the git repo in its entirety instead of relying on bits and pieces. Thankfully, [exactly that tool exists already: GitHacker](https://github.com/WangYihang/GitHacker). 

At first, I tried running the tool as a docker container. However, this kept reporting some kind of "name failed to resolve" error, even though the name I was providing it resolved just fine. 
After a bit of banging my head against the wall with the docker container, I instead installed the tool using pip and it worked right away!

```bash
githacker --url http://pilgrimage.htb/.git/ --output-folder result
```

![githacker](githacker.png)

That worked like a charm! I took a look through the source code, especially index.php and dashboard.php.

![source code](source%20code.png)

It looks like the application is interacting with an sqlite database at /var/db/pilgrimage. To take a look through this database, I'll try getting the file using the same exploit:

```
pngcrush -text a "profile" "/var/db/pilgrimage" exploit.png
```

I uploaded the file, downloaded the result, and parsed it (all the same as before):

```
identify -verbose pngout-out.png
```

![db raw](db%20raw.png)

This is great, but it's over 500 lines long. I copy-pasted the big block of hex into a file `db-dump-lines`. I don't want to have to strip off the line endings manually, so maybe I'll try parsing it with python?

Now... this definitely isn't the prettiest python I've ever written 😅 but at least it didn't take long to scrap together (definitely shorter than manually trimming off all those line endings):

```python
#!/usr/bin/python3

import binascii

fp = "db-dump-lines"
writefile = "dumped-text"

def readContents(filepath):
    with open(filepath, 'rb') as readfile:
        txt = b''
        while True:
            line = readfile.read()
            if not line:
                break
            lines = line.strip().split(b'\n')
            for l in lines:
                txt += l
        return txt
        
def writeContents(contents, writefilepath):
    with open(writefilepath, 'wb') as writefile:
        writefile.write(contents)

t = readContents(fp)
decoded = t.decode("utf-8")
fromhex = bytes.fromhex(decoded).replace(b'\x00', b' ')
print(fromhex)
writeContents(fromhex, writefile)
print("Done.")
```

The result is the text that would have been in the sqlite database that the web app interacts with. Right away, we see a pair of credentials: the **jimbo : password** credential I used when uploading the exploit png, and another one too

![creds in database](creds%20in%20database.png)

There we go! a new credential: **emily : abigchonkyboi123**



## USER FLAG

### Just Read It

I remember seeing `emily` was one of the regular / human users from `/etc/passwd`, so I'm very hopeful about credential re-use. Let's try plugging this credential into SSH 🤞

![ssh success](ssh%20success.png)

🎉 Alright! Finally, a shell!

This SSH connection drops us right into `/home/emily`. Go ahead and `cat` out the user flag:

```bash
cat user.txt
```



## ROOT FLAG

### User Enumeration - Emily

Having just gained access to a new user, it is probably a good idea to fully enumerate the user. I'll follow my typical strategy, User Enumeration (Linux). However, to save from cluttering up this walkthrough with unnecessary details, I'll avoid talking about the enumeration procedure, and instead just show the notable results.

- `emily`, `root`, and `www-data` are the only important users on the box.
- `emily` cannot sudo at all.
- `emily` has a hidden directory `/home/emily/.config/binwalk`. That's very odd: `binwalk` is an application usually used in forensics stuff. 
- The box has `nc`, `netcat`, `wget`, `curl`, `python`, `perl` and `php` all available.

Next I took a look at **pspy** to see what was running. Nothing super interesting was happening. The system did some kind of malware scan using `/usr/sbin/malwarescan.sh` and was waiting with `/usr/bin/inotifywait -m -e create /var/www/pilgrimage.htb/shrunk/`. Both of these were running as root.

However, as soon as I tried uploading an image to the website, a whole series of processes occurred:

![pspy 1](pspy%201.png)

> Cool to see that the system is indeed just using `convert`, like I predicted earlier. 

Why is root running `binwalk` when a file is submitted? Is this related to the malware scan? It's running `binwalk` with the `--extract` flag, to automatically extract known filetypes from an image file. And how does this all interact with the `/home/emily/.config/binwalk` directory found earlier?

It makes sense to start out with that config folder, and see what's inside. I checked all subdirectories at once:

```bash
ls -laR /home/emily/.config/binwalk
```

This revealed two empty files: 

- `/home/emily/.config/binwalk/config/extract.conf`
- `/home/emily/.config/binwalk/magic/binarch`



### Brief History of Binwalk

I did some searching online about these two files. I couldn't find anything about `binarch`, but it turns out that `extract.conf` controls how `binwalk` behaves with the `-e --extract` flag. Although this file is currently empty, if it has valid entries inside, it instructs binwalk which known file types should be extracted out of the the images when `binwalk` is ran. 

Second, I checked the currently installed version of `binwalk`. It is running version 2.3.2. Cross-referencing this with the current version on Github, apparently this is an old version, and may be subject to a vulnerability:

> ### *** Extraction Security Notice ***
>
> Prior to Binwalk v2.3.3, extracted archives could create  symlinks which point anywhere on the file system, potentially resulting  in a directory traversal attack if subsequent extraction utilties  blindly follow these symlinks. More generically, Binwalk makes use of  many third-party extraction utilties which may have unpatched security  issues; Binwalk v2.3.3 and later allows external extraction tools to be  run as an unprivileged user using the `run-as` command line  option (this requires Binwalk itself to be run with root privileges).  Additionally, Binwalk v2.3.3 and later will refuse to perform extraction as root unless `--run-as=root` is specified.

Oh interesting indeed. The fact that `emily` controls the `extract.conf` file and the box is running a version prior to 2.3.3 *definitely* seems like something that can be used for privilege escalation. This all makes me think of a "zip slip" attack, but in reverse. The vulnerability that the above notice is referring to is CVE-2022-4510, and can be found referenced in the [Binwalk Issues](https://github.com/ReFirmLabs/binwalk/pull/617). 

While that Issue thread on the github repo does have PoC code, and does already have a bundled zip file containing the PoC, the code isn't very... weaponizable. I tried changing out a few things, such as changing the print statement to a simple file write - nothing seemed to work.

A little more reading online about Binwalk showed what might be expected in that `extract.conf` file. Apparently, it can be used to run certain plugins based on what filetype is detected when the `-e` flag is used. I tried writing a new rule into `extract.conf` as shown below:

![jpegscript](jpegscript.png)

Then, I used the website to upload a .jpg image, meanwhile watching `pspy` for the result. Unfortunately, `binwalk` didn't even run!

This got me wondering, what exactly is triggering `binwalk` to run? I saw all that output in `pspy` earlier, but I wonder what the specific series of calls is. I checked `pspy` a little closer to find an answer to this, and immediately had my answer - much higher/earlier in the process history:

![pspy inotify](pspy%20inotify.png)

> From the man pages:
>
> ***inotifywait** efficiently waits for changes to files using Linux's [inotify](https://linux.die.net/man/7/inotify)(7) interface. It is suitable for waiting for changes to files from shell  scripts. It can either exit once an event occurs, or continually execute and output events as they occur.*

Now I understand. The system is watching that one directory for changes. That must be what is triggering `binwalk` to run.



### RCE using Binwalk

As a quick search to make sure I wasn't going in the wrong direction, I checked **searchsploit** to see if there was already exploit code for CVE-2022-4510. It turns out it does exist:

![searchsploit binwalk](searchsploit%20binwalk.png)

I copied the exploit over to my working folder, quickly read through the script manually, then tried running it:

![51249 py](51249%20py.png)

I set a new firewall rule and established a netcat listener.:

```bash
sudo ufw allow from 10.10.11.219 to any port 4444 proto tcp
bash
nc -lvnp 4444
```

Then, I ran the exploit (or rather, exploit-generator) code, supplying it with a PNG file I had around, my `tun0` IP address, and my nc listener's port:

![51249 py 2](51249%20py%202.png)

It produced a new file, `binwalk_exploit.png`. 

I tried once to submit this `binwalk_exploit.png` through the website (while watching pspy), but didn't notice any unusual response to that input file. I assumed that the exploit had somehow been broken by the convert / resize operation, and opted for a more direct approach.

This time, I'll try depositing the file directly into `/var/www/pilgrimage.htb/shrunk/` and wait for `inotify` to notice the change to the directory. It worked like a charm, immediately opening a reverse shell for root:

![root reverse shell](root%20reverse%20shell.png)

🎉 Wondrous! *The warm fuzzies of a root shell* :hugs:

From there, simply `cat` out the root flag to finish the box:

```bash
cat /root/root.txt
```



## LESSONS LEARNED

{{% lessons-learned attacker=true %}}

### Attacker

- Enumerate for hidden directories, too. Finding the `.git` repo in this box was extremely valuable. If you ever find a git repo, use a tool like *GitHacker* or *GitDumper* right away and save yourself some time. To expedite discovering a .git discloser, consider getting the *DotGit* browser extension.
- Start broad, then sink your teeth in: I'm glad I didn't spend too long attempting to sneak a payload into an image to upload to the website - ultimately this would not have worked (or not worked easily), due to the "malware scan" that we used for privesc.
- There's a good chance somebody has already written a tool to solve XYZ. For example, I didn't need to write any python to decode the sqlite database, I probably could have just popped the hex directly into *CyberChef* and finished much faster.
- Read *pspy* carefully, and remember it is not a linear history of events: it is a log of processes spawning other processes and may not be in chronological order. Critical thinking is your best tool for deciphering it. 
  {{% /lessons-learned %}}

{{% lessons-learned defender=true %}}

### Defender

- Read the news. If you see that a serious vulnerability affects something that one of your systems uses, be sure to patch it as soon as possible. 
- Avoid using libraries that are infamous. ImageMagik had several very serious vulnerabilities (collectively called *ImageTragik*), dating back to 2017. I only discovered the new file-disclosure CVE because I had knew at the back of my mind about *ImageTragik* and decided to check for insecure file upload vulnrabilities that might be related to it.
- Use Docker. This would have been a much more difficult box if the webserver, the image resizing functionality, and the database were all separate containers. It probably would have been an easier system to develop, too.
- Least privilege should always be applied. There was no good reason that Binwalk was running as root. 
  {{% /lessons-learned %}}
