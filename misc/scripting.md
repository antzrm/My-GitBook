# Scripting



## Bash

### Pitfalls / Vulnerabilities

[https://mywiki.wooledge.org/BashPitfalls](https://mywiki.wooledge.org/BashPitfalls)

## unix2dos - Formatting, weird characters, encoding issues

`unix2dos`

## TOCTOU (Time-of-check-time-of-use)

If I can run a command between the time that it checks the target of the link and when it prints the contents of the file, I can change the target of the link.

## Go

### asdf (Go version manager)

{% code overflow="wrap" fullWidth="true" %}
```
- Download binary from Github releases and put it in ~/.local/bin

- Add this to ~/.zshrc
if command -v asdf &>/dev/null; then                                                                                                                                         
  eval "$(asdf env setup)"                                                                                                                                                   
fi                                                                                                                                                                           
                                                                                                                                                                             
export PATH="$HOME/.asdf/shims:$PATH"                                                                                                                                        
export PATH="$(asdf where golang)/bin:$PATH"

- Then install golang
asdf plugin add golang https://github.com/asdf-community/asdf-golang.git
asdf install golang latest
```
{% endcode %}

```go
export GOROOT=/usr/lib/go
go build
# Reduce binary size
go build -ldflags "-s -w" .
upx $BINARY
```

## pwntools

<pre class="language-python"><code class="lang-python"><strong>https://guyinatuxedo.github.io/02-intro_tooling/pwntools/index.html
</strong><strong>
</strong><strong>import * from pwn
</strong>...
if __name__ == '__main__':
	try: 
		makeRequest()
	except Exception as e:
		log.error(str(e))
		
# Get interactive revshell
shell = listen(PORT, timeout=20).wait_for_connection()
if shell.sock is not None:
	shell.interactive()
else:
	print("\n[!]No shell connection")
</code></pre>

## Find comments on webservers

{% code overflow="wrap" fullWidth="true" %}
```bash
#!/bin/bash

# Colours
greenColour="\e[0;32m\033[1m"
endColour="\033[0m\e[0m"
redColour="\e[0;31m\033[1m"
blueColour="\e[0;34m\033[1m"
yellowColour="\e[0;33m\033[1m"
purpleColour="\e[0;35m\033[1m"
turquoiseColour="\e[0;36m\033[1m"
grayColour="\e[0;37m\033[1m"

function ctrl_c(){
	echo -e "Exiting..."
	tput cnorm; exit 1
}

# Ctrl+C
trap ctrl_c SIGINT

function helpPanel(){
	echo -e "\n Usage: $0 -u URL -d directory -f file\n"
	echo -e "\t -u URL with format http(s)://URL/"
	echo -e "\t -d directory (relative) path with file listing/links"
	echo -e "\t -f ffuf JSON file"
	tput cnorm; exit 1
}

declare -i parameter_counter=0

tput civis

while getopts "u:d:f:h" arg; do
	case $arg in
		u) url=$OPTARG && let parameter_counter+=1;;
		d) directory=$OPTARG && let parameter_counter+=1;;
		f) file=$OPTARG && let parameter_counter+=1;;
		h) helpPanel
	esac
done

function directoryListingCheck(){
	file=$1

	rm URLs 2>/dev/null
	cat $file | jq -r '.results |  .[] | .url' > URLs
	for path in $(cat URLs); do
		if [ "$(echo $path | grep '/$')" ] && [ "$(curl -s $path | grep 'Index of /')" ]; then #valid directory with / at the end, and with directory listing enabled
			# Get all files from directory listing recursively
			wget -d -r -np -N --spider -e robots=off --no-check-certificate $path 2>&1 | grep " -> " | grep -Ev "\/\?C=" | sed "s/.* -> //" | grep -E "http://|https://" >> URLs
		elif [ ! "$(echo $path | awk '{print $NF}' FS='/' | grep -woP '.*\..{2,4}')" ]; then #it is not a simple file
			path+="/"
			if [ "$(curl -s $path | grep 'Index of /')" ]; then #if directory listing enabled
				wget -d -r -np -N --spider -e robots=off --no-check-certificate $path 2>&1 | grep " -> " | grep -Ev "\/\?C=" | sed "s/.* -> //" | grep -E "http://|https://" >> URLs
			fi
		fi
	done
	sort -u URLs -o URLs # remove dupes
}

function checkLinks(){
	rm links 2>/dev/null
	touch links
	for path in $(cat URLs); do
		curl -s $path | grep -oP '<a href="(.*)"' | cut -d '"' -f 2 >> links
	done
	sort -u links -o links
	grep -E 'http://|https://' links >> URLs # in case new URLs with absolute paths
	sort -u URLs -o URLs
	echo -e "\nCheck links on ffuf-links file\n"
}

function findComments(){
	rm comments 2>/dev/null
	for path in $(cat URLs); do
		comments=$(curl -s $path | grep -noP "(<(.*?)-->)|(/\*([^*]|[\r\n]|(\*+([^*/]|[\r\n])))*\*+/)|(//.*)|(^'.*$)|(^#.*$)" 2>/dev/null)
		if [ ! -z "$comments" ]; then
			echo -e "\n\n\t${blueColour}---------File: $path${endColour}" | tee -a comments
			echo -e "${greenColour}Comments:\n $comments${endColour}" | tee -a comments
		fi
	done
}

if [ $parameter_counter -eq 1 ]; then
	if [ -f $file ]; then
		directoryListingCheck $file
		checkLinks
		findComments
	else
		echo -e "\n\nFile does not exist\n"
	fi
else
	helpPanel
fi

tput cnorm
```
{% endcode %}

## Badchars detection on a web register

{% code overflow="wrap" fullWidth="true" %}
```python
import requests
import string
import sectrets

loginurl = "http://10.10.10.0/login.php"
registerurl = "http://10.10.10.0/signup.php"
# Get all the symbols and add them in a list
characters = string.punctuaction
print("Blacklisted Characters: ")
# Iterate the list
for char in characters:
        # Create a random amount of hex characters
        random = secrets.token_hex(10)
        # Fill the username and password with letters
        data = {'email':f"{random}@test.test", 'username': char, 'password':'a', 'submit':''}
        r = requests.post(url = resgisterurl, data = data)
        data = {'username':char, 'password':'a', 'submit':''}
        r = requests.post(url = loginurl, data = data)
        # Check if we can log in with that specific character in the username
        if "incorrect" in r.text:
                print(char)
```
{% endcode %}

