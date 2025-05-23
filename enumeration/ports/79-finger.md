# 79 - finger

```bash
# User enumeration - use names.txt from Seclists as dict.
finger-user-enum.pl -U names.txt -t [$IP | domain.com] | less -S
```
