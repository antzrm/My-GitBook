# Java

## Log4Shell&#x20;

{% embed url="https://book.hacktricks.xyz/pentesting-web/deserialization/jndi-java-naming-and-directory-interface-and-log4shell#log4shell-exploitation" %}

## Analyze source code&#x20;

Check _Controller_ files

## Decompyle .jar

When facing .jar files, apart from decompylation, try to find src folder or any source code such as .java files

```
jd-gui
7z x *.jar
find . -name *.properties
```

## Java Debug Wire Protocol

[https://book.hacktricks.xyz/network-services-pentesting/pentesting-jdwp-java-debug-wire-protocol](https://book.hacktricks.xyz/network-services-pentesting/pentesting-jdwp-java-debug-wire-protocol)

[https://youtu.be/7n7YRntu3bc?t=1930](https://youtu.be/7n7YRntu3bc?t=1930)

{% hint style="info" %}
Read the exploit output and trigger the event.
{% endhint %}
