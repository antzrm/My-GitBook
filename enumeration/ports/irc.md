# IRC

**Use hexchat on Kali.**

[**https://book.hacktricks.xyz/network-services-pentesting/pentesting-irc#manual**](https://book.hacktricks.xyz/network-services-pentesting/pentesting-irc#manual)

{% hint style="info" %}
If several IRC ports, it may be necessary to select the right query port to establish the connection (try last or one of the last IRC ports from nmap output).
{% endhint %}

```bash
# irssi is a cli option to connect to IRC
$ irssi
[(status)] /server connect $IP
```
