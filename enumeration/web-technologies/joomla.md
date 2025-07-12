# Joomla

<pre class="language-bash" data-overflow="wrap" data-full-width="true"><code class="lang-bash"># Find Joomla version
<strong>/administrator/manifests/files/joomla.xml
</strong>
# JoomlaScan
https://github.com/drego85/JoomlaScan

# Joomscan
joomscan -u  http://10.11.1.111 
joomscan -u  http://10.11.1.111 --enumerate-components

# Juumla
# https://github.com/knightm4re/juumla
python3 main.py -u https://example.com

droopescan scan joomla -u http://10.11.1.111
python3 cmseek.py -u domain.com
vulnx -u https://example.com/ --cms --dns -d -w -e
python3 cmsmap.py https://www.example.com -F

# Bruteforce
<strong># https://github.com/ajnik/joomla-bruteforce
</strong># https://nmap.org/nsedoc/scripts/http-joomla-brute.html
# If lots of valid credentials, most likely the first one is the good one
joomla-brute.py -u http://$IP/$PATH -w cewl -U users 
nmap -sV --script http-joomla-brute
  --script-args 'userdb=users.txt,passdb=passwds.txt,http-joomla-brute.uri=/joomla/.../index.php,
                 http-joomla-brute.threads=100,brute.firstonly=true' &#x3C;target>

# Joomla &#x3C;= 3.7.x SQLi (Unauthenticated)
https://github.com/stefanlucas/Exploit-Joomla

# Authenticated RCE
# https://www.hackingarticles.in/joomla-reverse-shell/
Exploits > CVE-2023-23752
Option 1-> Go to Administration Templates > edit index.php and place our PHP code > Save
Option 2 -> Go to Site Templates -> modify error.php instead of index.php (with index we could break the site)
Option 3 -> Upload vuln plugin https://github.com/p0dalirius/Joomla-webshell-plugin
https://vulncheck.com/blog/joomla-for-rce
# WEBSHELL PLUGIN RCE
https://github.com/p0dalirius/Joomla-webshell-plugin
https://docs.joomla.org/J4.x:Creating_a_Plugin_for_Joomla
https://youtu.be/sdF8YSPHql4?t=259

# ALTERNATIVE: create new PHP file and then go to (in case Protostar template) /templates/protostar/webshell.php

# Check common files
README.txt
htaccess.txt
web.config.txt
configuration.php
LICENSE.txt
administrator
administrator/index.php # Default admin login
index.php?option=&#x3C;nameofplugin>
administrator/manifests/files/joomla.xml
plugins/system/cache/cache.xml
</code></pre>
