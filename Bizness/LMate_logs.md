URL: https://app.hackthebox.com/machines/Bizness

Current target IP: 10.10.11.252

Started with a port scanner
* I want to scan everything from port 1 to port 1000, TCP & UDP with servce discovery using nmap
    `nmap -sS -sU -p 1-10000 --version-intensity 0 10.10.11.252`

