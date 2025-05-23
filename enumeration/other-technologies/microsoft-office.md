# Microsoft Office

## Open Access Database files .mdb

```sh
dbeaver > Open Access > Select File
# ALTERNATIVE
sudo apt install mdbtools 
sudo apt install odbc-mdbtools 
for i in $(mdb-tables file.mdb); do mdb-export file.mdb $i > tables/$i; done
wc -l * | sort -n # now see the bigger tables and cat them so see their registers
```

## Open Outlook mail files .pst

```sh
sudo apt install pst-utils
readpst file.pst 
```

## Macros

{% code overflow="wrap" %}
```bash
https://github.com/glowbase/macro_reverse_shell

Open .xlsm or .xlsb > VBA Project > Document Objects > This Workbook

https://github.com/decalage2/oletools
# olevba extracts macros
olevba Report.xlsm
```
{% endcode %}
