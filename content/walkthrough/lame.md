---
title: "Lame"
date: 2023-06-02T18:00:00-00:00
publishdate: 2017-11-14T18:00:00-00:00
releasedate: 2017-03-14T18:00:00-00:00
draft: false
hideTitle: false
Cover: /htb-info-cards/Lame.png
icon: /htb-box-icons/Lame.png
toc: true
tags: ["Samba", "CVE", "Metasploit"]
categories: ["Walkthrough", "HTB", "Linux", "Easy"]
---

## INTRODUCTION

Lame is one of the oldest boxes on HTB. Its solution is very direct: while it is a "box", it is actually shorter than many "challenges". It is perfect for a beginner, or someone that just wants to brush up on some more introductory pentesting skills.



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
# Nmap 7.93 scan initiated Fri Jun  2 10:42:47 2023 as: nmap -sV -sC -O -n -Pn -oA nmap/init-scan 10.10.10.3
Nmap scan report for 10.10.10.3
Host is up (0.18s latency).
Not shown: 996 filtered tcp ports (no-response)
PORT    STATE SERVICE     VERSION
21/tcp  open  ftp         vsftpd 2.3.4
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to 10.10.14.3
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      vsFTPd 2.3.4 - secure, fast, stable
|_End of status
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
22/tcp  open  ssh         OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)
| ssh-hostkey: 
|   1024 600fcfe1c05f6a74d69024fac4d56ccd (DSA)
|_  2048 5656240f211ddea72bae61b1243de8f3 (RSA)
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  netbios-ssn Samba smbd 3.0.20-Debian (workgroup: WORKGROUP)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: OpenWrt White Russian 0.9 (Linux 2.4.30) (92%), Linux 2.6.23 (92%), Belkin N300 WAP (Linux 2.6.30) (92%), Control4 HC-300 home controller (92%), D-Link DAP-1522 WAP, or Xerox WorkCentre Pro 245 or 6556 printer (92%), Dell Integrated Remote Access Controller (iDRAC5) (92%), Dell Integrated Remote Access Controller (iDRAC6) (92%), Linksys WET54GS5 WAP, Tranzeo TR-CPQ-19f WAP, or Xerox WorkCentre Pro 265 printer (92%), Linux 2.4.21 - 2.4.31 (likely embedded) (92%), Citrix XenServer 5.5 (Linux 2.6.18) (92%)
No exact OS matches for host (test conditions non-ideal).
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
| smb-security-mode: 
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_smb2-time: Protocol negotiation failed (SMB2)
| smb-os-discovery: 
|   OS: Unix (Samba 3.0.20-Debian)
|   Computer name: lame
|   NetBIOS computer name: 
|   Domain name: hackthebox.gr
|   FQDN: lame.hackthebox.gr
|_  System time: 2023-06-02T03:43:30-04:00
|_clock-skew: mean: 2h00m13s, deviation: 2h49m44s, median: 11s

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri Jun  2 10:43:57 2023 -- 1 IP address (1 host up) scanned in 70.56 seconds
```

Ok, right away we see three notable services running:

1. **FTP**, with anonymous login enabled
2. **SSH**, always present on HTB boxes. Note the old version of OpenSSH though.
3. **SMB**, the newer version that uses TCP as well as NetBIOS.

FTP and SMB are both good leads to check out. SSH could be used for persistence but is rarely the way to gain a foothold.



## FOOTHOLD

### Investigating FTP

If you've just run through the *Starting Point* boxes on HTB, this is probably looking eerily familiar. When anonymous login is enabled, you can just jump right in to FTP: Use the username **anonymous** and a **blank password**

![FTP anonymous](FTP%20anonymous.png)

But get ready for disappointment... *FTP is empty*:

![ftp empty](ftp%20empty.png)

Sometimes FTP itself can be used for command execution. Good to check if this version is vulnerable:

![vsftpd exploit](vsftpd%20exploit.png)

Hey, not bad! Let's try it out in metasploit. But first, since this will probably create a reverse shell, it is time to add a firewall rule to allow the target to connect back to the attacker box. Personally I use ``ufw``:

```bash
sudo ufw allow from $RADDR to any port 4444 proto tcp
```

Now try out the exploit in **msfconsole**. Search for the exploit and check the options:

![msfconsole vsftpd](msfconsole%20vsftpd.png)

Set the required option then run it:

![msfconsole vsftpd 2](msfconsole%20vsftpd%202.png)

No dice 🎲 Perhaps this was patched on the target machine. Oh well 🤷‍♂ this is only an Easy box, so it's probably safe to say ``vsftpd`` is investigated enough. Time to move on to the next lead.

### Investigating SMB

Nmap already discovered that smb is running. Let's see if it also has anonymous login, or if it requires credentials. Just try listing the smb shares, providing a **blank password**:

![smbclient 1](smbclient%201.png)

Nice! Anonymous login was successful. The ``tmp`` directory's comment makes it stand out. (IPC$ and ADMIN$ are usually present, from what I've seen in other SMB configurations.)

Try checking out the contents of ``tmp``. First, just use ``smbclient`` similar to usage of ftp:

![smbclient 1](smbclient%202.png)

But there's an even easier way: just plonk ``smb://10.10.10.3/tmp`` into the address bar of your file explorer (I use **Thunar**, the default file explorer of kali). You'll be prompted for credentials, but will also have the option of anonymous login. 

![smbclient 3](smbclient%203.png)

The directories don't contain anything interesting. The log file seemed like a distraction. The only notable file is ``.X0-lock`` alongside the ``.X11-unix`` directory, which indicates that there is an active X11 session left open on the box. The lockfile shows the PID of the X11 session. 

> 💡 I was beginning to have a vague memories of doing an X11-hijack on another box. But for that one, there was a lot more than just a dangling PID to use. Made a mental note to come back to this if I was desperate.

Alright, nothing in ``tmp`` . The other shares either seemed uninteresting or required authentication. Might be a good time to check for an easy entry by seeing if there are any exploits for this version of smb:

``searchsploit smb``     --> Nothing that looks applicable
``searchsploit smbd``   --> Nope
``searchsploit samba`` --> YES, lots! There's even a specific one for the version we're targetting:

```
Samba 3.0.20 < 3.0.25rc3 - 'Username' map script' Command Execution (Metasploit) | unix/remote/16320.rb
```

🤞 That gives some hope. This is for CVE-2007-2447. Once again, let's check it out in metasploit:

![msfconsole samba](msfconsole%20samba.png)

Set the options. Note that the LHOST should be changed to the IP of the HackTheBox vpn interface. Then check and run:

![msfconsole samba 2](msfconsole%20samba%202.png)

😂 Wow, ok! Not only did the exploit work, the reverse shell gained root access?! That was easy!



## USER FLAG

The reverse shell from **msfconsole** provided root access to the target machine. To find the user flag, we just need to determine what user holds the flag. I issued the following commands:

``ls``
	--> we start at the root directory

``cd home``
	--> Several users have a home directory

``cat `find . -name user.txt` ``
	--> Found the flag at ``/home/makis/user.txt`` and read its contents



## ROOT FLAG

The root flag is even easier. Since we're already the root user, just read the flag from where it always is:

``cat /root/root.txt``



## EXTRA CREDIT: PERSISTENCE

Ok, so that was kinda... *lame* :upside_down_face:

Good for a little bit of practice, though! So why not try something a bit extra, and practice a useful CTF skill? 
Since we already have root access, let's **establish persistence by being able to SSH into the box as root**. That way, we can have all the modern niceties that SSH provides, such as colors, tab-completion, and command history.

``cd /root``

``ls -la``
	--> Identify that the ``.ssh`` directory is present.

``cd .ssh && ls -laR``
	--> Note that we have access to the ``authorized_keys`` file. Go ahead and ``cat`` it out to see the contents. 

This is a typical ``ssh`` file that has an entry for the public key for any pre-authorized keypair that may be used to log in as this user (in this case, root). Establishing persistence is really as easy as just copying an extra entry into ``authorized_keys``.

First, on the attacker box, generate a new key. Make sure to set adequate permissions on the private key, or SSH will reject it:

![ssh-keygen](ssh-keygen.png)

Then ``cat`` out the contents of  the file ``id_rsa.pub`` that was just generated. Copy it to the clipboard.

Next, on the target box (using the reverse shell that **msfconsole** opened), add a line to the  ``authorized_keys`` file. Since we're in a not-fully-interactive (aka "dumb") shell, it doesn't work well to simply append using vim/emacs/nano. I added the line in two steps: adding a newline character then pasting in the new entry:

![sshkey](sshkey.png)

Now that the public key is present inside ``authorized_keys``, we log in to the target box from the attacker box, using ssh with the private key we just generated:

![sshfailed](sshfailed.png)

Huh? Well that's odd. I tried running the same thing with the ``-v`` verbose flag, and found that this was happening because my attacker box's SSH version is much more recent than the OpenSSH found on the target box. Since this box was released, OpenSSH deprecated the key algorithm that the target box is requesting. 

No problem, a quick search indicated that it is possible to run SSH in a mode to force it to allow this old, insecure key algorithm:

```
┌──(kali㉿kali)-[~/Box_Notes/Lame]
└─$ ssh -p 22 -o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedKeyTypes=+ssh-rsa -i ./id_rsa root@10.10.10.3
```

Success! 🎉

![sshsuccess](sshsuccess.png)

Wait, what? root has new **mail..?** Alright, let's see what it is 😕

![mail](mail.png)

Oh, ok. This must be what happens all those times when I sudo something and the system tells me "this action will be reported" :roll_eyes:

Anyway, **we now have persistence, and can log in via SSH** using just the key we generated. I'd call that a success! Congrats to you for going the extra mile to upgrade your dumb shell into SSH instead 👏



## LESSONS LEARNED

{{% lessons-learned attacker=true %}}

### Attacker

- Don't spend too long examining files that are likely just distractions. I spent a bit too much time looking through the ``\tmp`` samba share.
- Searchsploit is your friend. When using it, try using synonyms as well. Ex. checking both ``smb`` and ``samba`` was important for this box.
- It's OK to jump right into **msfconsole** and try out a bunch of exploits. It can be a huge time-saver. If you're looking to be hardcore, be sure to read though the code for any exploit that worked and understand why it worked. Read the CVE article if one exists.
  {{% /lessons-learned %}}

{{% lessons-learned defender=true %}}

### Defender

- There is no reason to ever have anonymous login enabled for any file-share. Even a shared credential is better than none at all.
- Read infosec news and stay on top of the latest CVEs
- Perform regular updates, especially for outward-facing services or anything exposed to the internet.
  {{% /lessons-learned %}}
