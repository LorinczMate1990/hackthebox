# Keeper

Ip address is 10.10.11.227

sudo nmap -v -sS -p 1-10000 10.10.11.227

22/tcp open  ssh
80/tcp open  http

Add keeper.htb to /etc/hosts

It runs an nginx/1.18.0 (Ubuntu)

add tickets.keeper.htb to /etc/hosts

tickets.keeper.htb is a third party application, a Request tracker

RT 4.4.4+dfsg-2ubuntu1 (Debian) szerzői joggal védett 1996-2019 Best Practical Solutions, LLC.

So I check its vulnaribilities
    - Btw I found a public walktrough: https://medium.com/@li_allouche/hack-the-box-keeper-writeup-56644dc6a55f 

Here are the vulnaribilities:

https://www.cvedetails.com/vulnerability-list/vendor_id-8416/product_id-14710/Bestpractical-Request-Tracker.html

CVE-2017-5944 seems promising, RCE, but I need to login first

While I check the other vulns, I run a brute force dict attack

Nothing useful... Peeked the walktrough, recommend to check default user + pass

Yep. Found it, "root" + "password" are the default, and it works.
I cam't use the CVE-2017-5944, because it is fixed after 4.4.2.

But Perl scripts can be written and called, so in theory I can execute something in bash and get a reverse shell.
I tried to trigger a remote shell, but I couldn't the page just crashed every time.

I checked the other pages and found the user lnorgaard with a passowrd in comment section (WTF?) Welcome2023!
So... SSH I guess. So I have my shell after all...

The user is not in the sudo group
I found a zip called RT30000.zip, I download it.

It contains some password dump files

It's a KeePass dump file. And it has a vulnaribility:
CVE-2023-32784

https://github.com/vdohney/keepass-password-dumper

Here is a linux version: https://github.com/CTM1/CVE-2023-32784-keepass-linux

This C code does a little bit different thing, but I can rewrite it to use the KeePassDumpFull.dmp file, not the memory.


