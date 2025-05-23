# Red Teaming

## Phishing

Convincing Phishing Emails

* Sender address from a significant brand, contact or cowoker. Use OSINT to suit it better to the destinatary.
* Subject: urgent, worrying, piques the victim's curiosity (account compromised, package shipped, payroll info, leaked pics...
* Content/Body: mimic standard email templates of the company, signatures, use anchor text \<a href> to disguise links

Phishing Infrastructure

* Domain Name (buy expired domains, typosquatting, TLD alternative such as .co.uk, IDN Homograph Attack/Script Spoofing)
* SSL/TLS certificates
* Email Server/Account
* DNS Records to improve deliverability (not getting into spam folder)
* Web Server
* Analytics of emails sent, opened...

[https://getgophish.com/](https://getgophish.com/)

[https://www.trustedsec.com/tools/the-social-engineer-toolkit-set/](https://www.trustedsec.com/tools/the-social-engineer-toolkit-set/)

Droppers > software to be downloaded and run (legitimate but once installed, the intended malware is either unpacked or downloaded)

Use MS Office in Phishing as attachments with macros

Browser exploits: difficult, but might work if we know systems and are old or unpatched for sth like [https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-40444](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-40444)

## DELIVERY TECHNIQUES

### Mail

The red teamers should have their own infrastructure for phishing purposes. Depending on the red team engagement requirement, it requires setting up various options within the email server, including DomainKeys Identified Mail (DKIM), Sender Policy Framework (SPF), and DNS Pointer (PTR) record.

The red teamers could also use third-party email services such as Google Gmail, Outlook, Yahoo, and others with good reputations.

Another interesting method would be to use a compromised email account within a company to send phishing emails within the company or to others.

### Web

[https://attack.mitre.org/techniques/T1189/](https://attack.mitre.org/techniques/T1189/)

Web server with reputation of its domain name and TLS (Transport Layer Security) certificate.

### USB

[https://attack.mitre.org/techniques/T1091/](https://attack.mitre.org/techniques/T1091/)

Useful at conferences or events where the adversary can distribute the USB.

Common USB attacks used to weaponize USB devices include [Rubber Ducky](https://shop.hak5.org/products/usb-rubber-ducky-deluxe) and [USBHarpoon](https://www.minitool.com/news/usbharpoon.html), chargingĀ USB cable, such asĀ [O.MG Cable](https://shop.hak5.org/products/omg-cable).

## Initial Access

### Network Infrastructure

Internal network with VLAN for example

A DMZ Network is an edge network that protects and adds an extra security layer to a corporation's internal local-area network from untrusted traffic. A common design for DMZ is a subnetwork that sits between the public internet and internal networks.

### AD

<figure><img src="../.gitbook/assets/image (136).png" alt=""><figcaption></figcaption></figure>

```
systeminfo | findstr Domain
 Get-ADUser  -Filter *
 Get-ADUser -Filter * -SearchBase "CN=Users,DC=DOMAIN,DC=COM"
```

### AV

```
wmic /namespace:\\root\securitycenter2 path antivirusproduct
Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct
Get-Service WinDefend
Get-MpComputerStatus | select RealTimeProtectionEnabled
```

### FW

```
Get-NetFirewallProfile | Format-Table Name, Enabled
Set-NetFirewallProfile -Profile Domain, Public, Private -Enabled False
Get-NetFirewallProfile | Format-Table Name, Enabled
Get-NetFirewallRule | select DisplayName, Enabled, Description
# To test inbound connection on port 80
Test-NetConnection -ComputerName 127.0.0.1 -Port 80
Get-MpThreat # threats details that have been detected using MS Defender
```

### Security Event Logging and Monitoring

{% code overflow="wrap" fullWidth="true" %}
```bash
Get-EventLog -List
https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-eventlog?view=powershell-5.1
# Sysmon -> check if it is present
https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon
Get-Process | Where-Object { $_.ProcessName -eq "Sysmon" }
Get-CimInstance win32_service -Filter "Description = 'System Monitor service'"
Get-Service | where-object {$_.DisplayName -like "*sysm*"}
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Sysmon/Operational
findstr /si '<ProcessCreate onmatch="exclude">' C:\tools\* # find sysmon config file
# EDR detection
software for endpoints
• Cylance
• Crowdstrike
• Symantec
• SentinelOne
• Many others
https://github.com/PwnDexter/Invoke-EDRChecker
https://github.com/PwnDexter/SharpEDRChecker
```
{% endcode %}
