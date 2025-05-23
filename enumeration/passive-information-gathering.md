# Passive Information Gathering

```bash
#WHOIS
whois domain.com
whois $IP
#Google Hacking
site: domain.com -filetype:php
https://www.exploit-db.com/google-hacking-database
#Netcraft
https://www.netcraft.com/
#Recon-ng
https://github.com/lanmaster53/recon-ng/wiki/Features#module-marketplace
#Open-Source Code
GitHub, GitLab and SourceForge
For bigger repositories, Gitrob or Gitleaks 
https://help.github.com/en/github/searching-for-information-on-github/searching-code
#Shodan
# NSLOOKUP
nslookup mail.domain.com
nslookup -type=TXT info.domain.com $IP

#Security Headers Scanner
https://securityheaders.com/
#SSL Server Test
https://www.ssllabs.com/ssltest/
#Pastebin
https://pastebin.com/
#Email Harvesting
theharvester -d domain.com -b google
#Password Dumps
https://haveibeenpwned.com/PwnedWebsites
#Social Media Tools
https://www.social-searcher.com/
https://digi.ninja/projects/twofi.php
https://github.com/initstring/linkedin2username
#Stack Overflow
https://stackoverflow.com/
#Information Gathering Frameworks
https://osintframework.com/
https://www.paterva.com/buy/maltego-clients.php
```

## OSINT

{% content-ref url="../misc/osint.md" %}
[osint.md](../misc/osint.md)
{% endcontent-ref %}

## Google Dorking / Google Hacking / Google Fu

[https://www.blackhat.com/presentations/bh-europe-05/BH\_EU\_05-Long.pdf](https://www.blackhat.com/presentations/bh-europe-05/BH_EU_05-Long.pdf)

<figure><img src="../.gitbook/assets/image (16).png" alt=""><figcaption></figcaption></figure>

For example, if a vulnerability came out with a WordPress plugin, I would find the filename of the plugin and use **inurl:file\_used\_by\_plugin.php** and see how many websites could be affected by this vulnerability. I would then build a list of websites that offer bug bounties or take part in programs like Synack and then check if any of those sites appear on the list.

Using **-site:website.com** will make sure that the website does not appear on your search results

before: and after: / after is good to search for newest and more advanced exploits

{% code fullWidth="false" %}
```sh
# Examples
intitile: # search page title
site: microsoft.com -site:www.microsoft.com
inurl:10000 webmin # port scanning
inurl:$PORT -intext:$PORT
filetype:inc intext:mysql_connect
filetype:sql + "IDENTIFIED BY" -cvs
```
{% endcode %}

[https://teddit.net/r/oscp/comments/nm4a36/dorks\_to\_aid\_enumeration\_exploitation/](https://teddit.net/r/oscp/comments/nm4a36/dorks_to_aid_enumeration_exploitation/)

[http://google.com/advanced\_search](http://google.com/advanced_search)

[Pentest-Tools google hacking page](https://pentest-tools.com/information-gathering/google-hacking)

[dork scanner](https://github.com/madhavmehndiratta/dorkScanner)

[Pagodo](https://awesomeopensource.com/project/opsdisk/pagodo)

[GoogleDorker](https://awesomeopensource.com/project/nerrorsec/GoogleDorker)

[refine your Google searches here](https://support.google.com/websearch/answer/2466433)

[https://yewtu.be/watch?v=lESeJ3EViCo](https://yewtu.be/watch?v=lESeJ3EViCo)
