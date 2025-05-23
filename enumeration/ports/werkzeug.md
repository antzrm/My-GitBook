# Werkzeug

##

{% hint style="info" %}
Try using Burp to send the request with 1+ of the body parameters missing. There could be an error with some interesting information.
{% endhint %}

## Jinja / Flask SSTI vuln

{% content-ref url="../web-pentesting/ssti.md" %}
[ssti.md](../web-pentesting/ssti.md)
{% endcontent-ref %}

## Debug Console RCE

Werkzeug Debugger works in the way that, as soon as something in the code results in an exception or error, a console is opened.

If debug is active you could try to access to `/console` and gain RCE.

```python
__import__('os').popen('whoami').read();
```

<figure><img src="../../.gitbook/assets/image (45).png" alt=""><figcaption></figcaption></figure>

There is also several exploits on the internet like [this ](https://github.com/its-arun/Werkzeug-Debug-RCE)or one in metasploit&#x20;

```
multi/http/werkzeug_debug_rce
```

## Console PIN Exploit/Bypass

[https://github.com/wdahlenburg/werkzeug-debug-console-bypass](https://github.com/wdahlenburg/werkzeug-debug-console-bypass)

[https://exploit-notes.hdks.org/exploit/web/framework/python/werkzeug-pentesting/](https://exploit-notes.hdks.org/exploit/web/framework/python/werkzeug-pentesting/)

In some occasions the /console endpoint is going to be protected by a pin. Here you can find how to generate this pin:

{% code overflow="wrap" fullWidth="true" %}
```
https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/werkzeug#werkzeug-console-pin-exploit
https://ctftime.org/writeup/17955
```
{% endcode %}

If application is running in debug mode, it will reload any time any of the source files change. If we have the ability to upload files, see if we can overwrite some of thouse source files (app.py, views.py or whatever name they have).

When we overwrite, better append our commands to the end instead of not include the source file code. That will avoid breaking the original functionality.

## PBKDF2 Werkzeug crack on hashcat

[https://github.com/hashcat/hashcat/issues/3205](https://github.com/hashcat/hashcat/issues/3205)
