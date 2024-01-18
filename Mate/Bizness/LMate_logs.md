URL: https://app.hackthebox.com/machines/Bizness

Current target IP: 10.10.11.252
`TARGET=10.10.11.252`

Started with a port scanner
* I want to scan everything from port 1 to port 1000, TCP & UDP with servce discovery using nmap
    `sudo nmap -sS -sU -p 1-10000 --version-intensity 0 $TARGET`
* It's slow as hell. So start again, just with TCP and without service discovery. Also giving a -v to see anything
    `sudo nmap -v -sS -p 1-10000 $TARGET`
* Three interesting port is found immadiatly.
```
Discovered open port 80/tcp on 10.10.11.252
Discovered open port 443/tcp on 10.10.11.252
Discovered open port 22/tcp on 10.10.11.252
```
* I will check the 80 and 443 ports with browser.
* I got that "This site can't be reached" also my browser redirected me to https://bizness.htb/.
    - DNS_PROBE_FINISHED_NXDOMAIN
    - I try it with curl: `curl -o index.html http://$TARGET/`
    - I see that it runs nginx/1.18.0 from the response
    - I want to see where is it redurected, for this I have to use the curl -i to see the headers
        - I don't know what I expected. :) https://bizness.htb/

* Checking nginx/1.18.0 
    - https://www.cybersecurity-help.cz/vdb/nginx/nginx/1.18.0/
    - remote code execution
    - PoC: https://github.com/M507/CVE-2021-23017-PoC

* To execute the PoC, I need the DNS server IP address of the target
    - `pip install scapy==2.5.0` is needed
* The POC needs root privileges, but I checked its code, it looks safe
* So I need the DNS server IP address
    - When I check the IP in the browser, it redirects me to the bizness.htb
    - `nslookup -type=ns bizness.htb` 
    - It can't find anything... I should execute it from the server. Maybe I can login with ssh. Nope. SSH needs key
* Now I feel I am on the wrong track.
    - I see that it runs a vulnerable nginx version
        - It has a high prio vul. but I should know its DNS address
    - Yep... I had to add the "10.10.11.252    bizness.htb" line to my /etc/hosts 
    - Now I can see the hosted webpage
* There is a form in the webpage and it does a bunch of client side check.
    - I see that it sends the data to contactform/contactform.php
    - The form does nothing
* Try to send a custom post message to https://bizness.htb/contactform/contactform.php
    - `curl -X POST -d "hello=world" https://bizness.htb/contactform/contactform.php`

This is where I gave up. :)

https://medium.com/@karimwalid/hack-the-box-bizness-walkthrough-3e19aab509d2


Summary:
- Directory bruteforce would give me some hint

Let's continue without the walktrough

So I executed `dirb https://bizness.htb`
Gave me some interesting results
    https://bizness.htb/accounting
    This hosts ofbiz. I have no idea about the version

    Maybe it is vulnerable to CVE-2023-51467

Here is the exploit: https://github.com/K3ysTr0K3R/CVE-2023-51467-EXPLOIT/blob/main/CVE-2023-51467.py

The right command: python CVE-2023-51467.py -u https://bizness.htb

So we found a RCE vul... Cool.

Here is the curl command:
curl -k "https://bizness.htb/webtools/control/ping?USERNAME&PASSWORD=test&requirePasswordChange=Y"

With a little google search: https://github.com/jakabakos/Apache-OFBiz-Authentication-Bypass


