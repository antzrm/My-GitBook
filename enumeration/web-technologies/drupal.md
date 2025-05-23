# Drupal

They have their tools to audit the CMS, like WPScan for WordPress. DroopeScan for Drupal.

Check **changelog.txt** to find the **version**.

{% code overflow="wrap" %}
```bash
https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/drupal/index.html?highlight=drupal#drupal

https://www.exploit-db.com/exploits/41564
# Change $endpoint_path to /rest and the payload with a simple php code to have a webshell.

https://github.com/oways/SA-CORE-2018-004
https://github.com/dreadlocked/Drupalgeddon2

Check Modules > PHP Filter and enable it

droopescan scan drupal -u http://$IP
```
{% endcode %}
