# Connect to VPN

We need the VPN file fo rhte lab.
* OpenVPN
    - the OpenVPN file must be downloaded from CONNECT TO HTB (at the top right)
    - I had to comment out the line started with data-ciphers-fallback and data-ciphers
    - sudo openvpn --config lab_LMate.ovpn
    - After that I joined to the VPN, I had to join to a machine (I used Bizness) and I got the target IP address
    - I verified the VPN by pinging the IP address
* Pwnbox 
    - a virtual machine in the browser. This is the easiest method.
    - Free lets you use for two hours, VIP lets you use for 24 hours per month.
