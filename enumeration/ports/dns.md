---
description: Domain Name System
---

# 53 - DNS

{% content-ref url="../active-information-gathering.md" %}
[active-information-gathering.md](../active-information-gathering.md)
{% endcontent-ref %}

Domain --> DNS Server --> DNS recursor --> DNS root zone (TLD) --> authoritative nameserver --> IP

• NS - Nameserver records contain the name of the authoritative servers hosting the DNS records for a domain.&#x20;

• A - Also known as a host record, the “a record” contains the IP address of a hostname (such as www.megacorpone.com).&#x20;

• MX - Mail Exchange records contain the names of the servers responsible for handling email for the domain. A domain can contain multiple MX records.&#x20;

• PTR - Pointer Records are used in reverse lookup zones and are used to find the records associated with an IP address.&#x20;

• CNAME - Canonical Name Records are used to create aliases for other host records.&#x20;

• TXT - Text records can contain any arbitrary data and can be used for various purposes, such as domain ownership verification.

## Get domain

```sh
nslookup 
> server $IP
> $IP

dig @$IP -x $IP +short
```

```bash
host www.megacorpone.com # Get the IP (default)
host -t [mx/txt] # type of record (MX or TXT)

# FORWARD LOOKUP BRUTE FORCE
for ip in $(cat list.txt); do host $ip.megacorpone.com; done # use Seclists

# REVERSE LOOKUP BRUTE FORCE (TAKING THE IP APPROX RANGE FROM THE PREV STEP)
for ip in $(seq 50 100); do host 38.100.193.$ip; done | grep -v "not found"

# DNS ZONE TRANSFERS
host -l <domain name> <dns server address> # second arg is a nameserver 

# TOOLS
dnsrecon -d megacorpone.com -t axfr
dnsrecon -d megacorpone.com -D list.txt -t brt # -D list of subdomains
dnsenum zonetransfer.me
```

## Query domain

{% code overflow="wrap" %}
```bash
dig @IP $DOMAIN
dig @IP $DOMAIN ns
dig @IP $DOMAIN mx

dnsenum --dnsserver $IP -f /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt domain.com
```
{% endcode %}

## Domain Zone Transfer

[https://digi.ninja/projects/zonetransferme.php](https://digi.ninja/projects/zonetransferme.php)

Find subdomains not listed, it helps to get interesting info

```bash
Dig --> requests to DNS servers
dig axfr @IP $DNS
Ex: dig axfr @10.10.10.123 friendzone.red

# NOTE THE DIFFERENT DOMAINS AND INCLUDE ALL OF THEM WITH THE SAME IP

cat /etc/hosts
10.10.1.1 feos.domain administrator.domain uploads.domain others.domain

# NOTE: IT'S IMPORTANT TO SEE IF THE COMMONNAME OR DNS BELONGS TO HTTP OR HTTPS

############ WINDOWS
nslookup.exe
> server $TARGET_IP
> ls -d $DOMAIN
```

## DNS Rebinding

[https://nip.io/](https://nip.io/)

```
app.10.8.0.1.nip.io maps to 10.8.0.1
app-116-203-255-68.nip.io maps to 116.203.255.68
```
