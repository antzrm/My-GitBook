# Burp Suite

{% hint style="info" %}
Use the **Inspector part (right)** and the decoded from, query, body parameters, edit them and apply changes for new requests
{% endhint %}

Proxy -> show hidden elements in forms

Ctrl+U -> encode selected text

Intruder --> Runtime file --> select file --> start attack --> filter --> negative search (show results that do not have that filter)

## Sitemap

It is particularly useful for mapping out APIs, as any API endpoints accessed by the web application will be captured in the site map.

## Best extensions

Logger++

Param-miner

Backslash Powered Scanner

Active Scan++

## Strategy

* Browse entire app, discover content
* Utilize param-miner
* Discover Content and JSParser
* Browse all content with Collaborator Everywhere on
* For paths such as ?action=showUser\&id=2 fuzz with verbs and wordlists such as form field names, server side and so on.
* Send each script to Repeater and find how it works.
* Send to Intruder and define parameters for Active Scanner and Backslash Powered Scanner.
* Finally, back to Intruder and fuzz manually. Also try hex numbers from 00 to FF.

## Redirecting all Script Traffic to Burp

On Burp

* Proxy > Options > Proxy Listeners > Add
* In Binding tab, set Bind port to 8081
* In Request Handling tab, set Redirect to host option to \[IP of target] and Redirect to Port option to 80
* Make sure to select the newly added listener when done
* On script, change target to http://localhost:8081
* On Burp, Turn intercept on
* Once Script runs, sent the request to Repeater (ctrl + r)

## Request view

**Show non-printable** characters button (\n). Thisfunctionality enables the display of characters that may not be visiblewith the **Pretty** or **Raw** options. Forexample, each line in the response typically ends with the characters`\r`, representing a carriage return followed by a new line. These characters play an important role in the interpretation of HTTPheaders.

## Python Requests (Scripting)

{% content-ref url="../enumeration/web-technologies/python.md" %}
[python.md](../enumeration/web-technologies/python.md)
{% endcontent-ref %}

```python
burp = {'http': '127.0.0.1:8080'}
...
exploit = s.post(url, post=post_data, headers=headers, proxies=burp)

Burp > Intercept is on
```

## Test scripts

{% code overflow="wrap" %}
```bash
Add new listener > Binding port (whatever port) -> Request handling -> redirect to host: $TARGET_IP Redirect to port: $TARGET_PORT -> put the check box on 
# now every request we direct to 127.0.0.1:port will go to the target
```
{% endcode %}

## Avoid redirections by intercepting responses

{% code overflow="wrap" %}
```bash
# Manually
On Burp > Proxy > Options > Enable Intercept Server Responses first option and deselect all rules from the table below
Now we intercept a request, click Foward, intercept the response and we change the HTTP verb to put 200 OK and now Forward
# Automated
On Burp > Proxy > Options > Match and Replace > Add > Type: Response Header > Match: 302 Found > Replace: 200 OK
```
{% endcode %}

## Intruder

Attack types:

1. **Sniper**: The Sniper attack type is the default and most commonly used option. It cycles through the payloads, inserting one payload at a time into each position defined in the request. Sniper attacks iterate through all the payloads in a linear fashion, allowing for precise and focused testing.
2. **Battering ram**: The Battering ram attack type differs from Sniper in that it sends all payloads simultaneously, each payload inserted into its respective position. This attack type is useful when testing for race conditions or when payloads need to be sent concurrently.
3. **Pitchfork**: The Pitchfork attack type enables the simultaneous testing of multiple positions with different payloads. It allows the tester to define multiple payload sets, each associated with a specific position in the request. Pitchfork attacks are effective when there are distinct parameters that need separate testing.
4. **Cluster bomb**: The Cluster bomb attack type combines the Sniper and Pitchfork approaches. It performs a Sniper-like attack on each position but simultaneously tests all payloads from each set. This attack type is useful when multiple positions have different payloads, and we want to test them all together.

{% code overflow="wrap" %}
```bash
https://portswigger.net/burp/documentation/desktop/tools/intruder/configure-attack/processing

#Several parameters, recursive grep (p. 280 PDF)
Intruder > Pitchfork (different payloads for each parameter)

If cookie, token is connected to the next request --> identify the response to see
cookies and tokens --> Intruder > Options > Grep - Extract > Add >
Define start and end, refetch response

Then to include that payload --> Payloads > Payload type > Recursive grep
```
{% endcode %}

## Turbo Intruder

[https://www.hackingarticles.in/burp-suite-for-pentester-turbo-intruder/](https://www.hackingarticles.in/burp-suite-for-pentester-turbo-intruder/) to iterate through multiple payloads simultaneously

## Macros

When there is a redirect response or anything else that impides to recalculate headers/cookies with recursive grep, macros are needed.

* Switch over to the main "Settings" tab at the top-right of Burp.
* Click on the "Sessions" category.
* Scroll down to the bottom of the category to the "Macros" section andclick the **Add** button.
* Grab the request we want from the proxy history.
* Now that we have a macro defined, we need to set Session Handling rules that define how the macro should be used.
* Still in the "Sessions" category of the main settings, scroll up to the"Session Handling Rules" section and choose to **Add** a new rule.
* A new window will pop up with two tabs in it: "Details" and "Scope". We are in the Details tab by default.
* Fill in an appropriate description, then switch to the Scopetab.
* In the "Tools Scope" section, deselect every checkbox other than Intruder – we do not need this rule to apply anywhere else.
* In the "URL Scope" section, choose "Use suite scope"; this will set the macro to only operate on sites that have been added to the global scope. If you have not set a global scope, keep the "Use custom scope" option as default and add `http(s)://$IP_OR_DOMAIN` to the scope in this section.

As it stands, this macro will now overwrite all of the parameters in our Intruder requests before we send them; this is great, as it means that we will get the login Tokens and session cookies added straight into our requests. That said, we should restrict which parameters and cookies are being updated before we start our attack:

* Select "Update only the following parameters and headers", then click the **Edit** button next to the input box below the radio button.
* In the "Enter a new item" text field, type the header to update if there is one.
* Select "Update only the following cookies", then click the relevant **Edit** button.
* Enter the desired cookie to update if there is one.
* Click **OK**, and we're done!
* You should now have a macro defined that (for example) will substitute in the CSRF token and session cookie. All that's left to do is switch back to Intruder and start the attack!

## Intercept scripts or commands on terminal

```
Add a listener on port 80 for example
Redirect to host: MACHINE_IP
Redirect to port: 80
```
