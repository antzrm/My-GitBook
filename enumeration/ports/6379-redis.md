# 6379 - Redis

## General

Also covers SSH keys, read files and write files (webshell for example):

{% embed url="https://book.hacktricks.xyz/pentesting/6379-pentesting-redis" %}

{% embed url="https://exploit-notes.hdks.org/exploit/database/redis-pentesting/" %}

{% embed url="https://reconshell.com/redis-exploit-tool/" %}

## Quick Commands + beware of types

```bash
redis-cli -h $IP -a '$PASSWORD'
keys *
get $keyname
get "keynumber1"
lrange $keyname 1 100
type $keyname

# search for Redis password / conf 
/etc/redis/redis.conf
```

## Rogue Server RCE

{% hint style="info" %}
Rogue Server works for some versions >=5.0.5 so try it in any case
{% endhint %}

{% embed url="https://github.com/n0b0dyCN/redis-rogue-server.git" %}

## Load Module

Needs some way to upload the malicious module on the target, to do so we may chain this vulnerability with another (FTP share to upload files on the victim for example).&#x20;

{% hint style="info" %}
Check General section links for full explanation.
{% endhint %}

## rdb-tools (Dump DB, Analyze Memory, Export Data to JSON)

[https://github.com/sripathikrishnan/redis-rdb-tools](https://github.com/sripathikrishnan/redis-rdb-tools)

## Privesc

Once you have access to the filesystem, search for **redis\*.conf** files
