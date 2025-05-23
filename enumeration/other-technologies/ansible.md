# Ansible

**ansible-playbook** by default verifies the syntax of the given playbook. If we provide an invalid file as input, it reveals the contents of the file in the error message.

```shell
echo -n test > file.txt

ansible-playbook file.txt
<SNIP>
The offending line appears to be:
test
```

[https://ppn.snovvcrash.rocks/pentest/infrastructure/devops/ansible](https://ppn.snovvcrash.rocks/pentest/infrastructure/devops/ansible)
