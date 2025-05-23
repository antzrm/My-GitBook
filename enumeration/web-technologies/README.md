# Web Technologies

## CMS

**OPSEC Note:** You don’t need to actually publish any changes in most CMS systems to get your execution. If there’s a preview option, it will show the code to just you, and still run it. Then, you can leave the post and not publish, leaving less evidence behind.

### Wordlists

{% embed url="https://github.com/p0dalirius/webapp-wordlists" %}

## Zabbix

RCE (Authenticated) > Configuration > Host > New Item > command system (run command)

## HG Mercurial (VCS)

```sh
hg init
qa@yummy:/dev/shm$ hg branches
default                        5:6c59496d5251
qa@yummy:/dev/shm$ hg update 5:6c59496d5251
124 files updated, 0 files merged, 0 files removed, 0 files unresolved
qa@yummy:/dev/shm$ hg log
...
hg diff -r 3 # 3 is revision number to show file changes of that commit


# HG hooks -> it works the same way as Git
https://book.mercurial-scm.org/read/hook.html
https://repo.mercurial-scm.org/hg/help/hgrc
[hooks]
post-pull = python:/path/to/your/script.py
post-pull = /path/to/your/script.sh
pre-pull = python:/path/to/your/pre_pull_script.py
pre-pull = /path/to/your/pre_pull_script.sh

chmod 777 -R .hg
echo -e '[hooks]\npre-pull = /tmp/script' | tee .hg/hgrc
hg pull /home/to/path
```
