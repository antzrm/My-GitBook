# OSINT

<figure><img src="../.gitbook/assets/image (17).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../.gitbook/assets/image (141).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../.gitbook/assets/image (142).png" alt=""><figcaption></figcaption></figure>

{% embed url="https://phonebook.cz/" %}

[Ahmia.fi](https://ahmia.fi/) is a search engine specifically for finding sites on the Tor Network, although the search engine itself is accessible on the “clearnet.” But you will need the [Tor Browser](https://www.torproject.org/download/) in order to open your Tor search results.

[Wayback Machine](https://archive.org/web/)

Check out OSINT tools on the security podcast "Privacy Security and OSINT" my Michael Bazzell and website check out [https://inteltechniques.com/blog/](https://inteltechniques.com/blog/) or [https://www.trustedsec.com/blog/upgrade-your-workflow-part-1-building-osint-checklists/](https://www.trustedsec.com/blog/upgrade-your-workflow-part-1-building-osint-checklists/) or [https://medium.com/@hunchly/bulk-extracting-exif-metadata-with-hunchly-and-exiftool-164d67c8d7e2](https://medium.com/@hunchly/bulk-extracting-exif-metadata-with-hunchly-and-exiftool-164d67c8d7e2) I know of Exiftool and imagemagick. I personally wouldn't use something that doesn't run locally. I like Hunchly but I don't think it's free.

## OWASP Amass

In-depth attack surface mapping and asset discovery

[https://github.com/owasp-amass/amass](https://github.com/owasp-amass/amass)

## CTFR

Abusing Certificate Transparency logs for getting HTTPS websites subdomains.

[https://github.com/UnaPibaGeek/ctfr](https://github.com/UnaPibaGeek/ctfr)

## Github

## AWS S3 Buckets

http(s)://{name}.s3.amazonaws.com, search {name}-assets, {name}-www, {name}-public, {name}-private, etc.

1\) Identify important information based on a user's posting history.

2\) Utilize outside resources, such as search engines, to identify additional information, such as full names and additional social media accounts.\
Additional Resources:\
While Rudolph's posting history is enough for us to identify that he has other social media accounts, sometimes we are not that lucky. Great tools exist that allow us to search for user accounts across social media platforms. Sites, such as [https://namechk.com/](https://namechk.com/), [https://whatsmyname.app/](https://whatsmyname.app/) and [https://namecheckup.com/](https://namecheckup.com/) will identify other possible accounts quickly for us. Tools, such as [https://github.com/WebBreacher/WhatsMyName](https://github.com/WebBreacher/WhatsMyName) and [https://github.com/sherlock-project/sherlock](https://github.com/sherlock-project/sherlock) do this as well. Simply enter a username, hit search, and comb through the results. It's that easy!\


TwitterNow, chitterGo\
**Learning Objectives:**\
1\) Identify important information based on a user's posting history.

2\) Use reverse image searching to identify where a photo was taken and possibly identify additional information, such as other user accounts.

3\) Utilize image EXIF data to uncover critical details, such as exact photo location, camera make and model, the date the photo was taken, and more.

4\) Use discovered emails to search through breached data to possibly identify user passwords, name, additional emails, and location.\


**Additional Resources**\
Reverse image searching can help not only identify where an image was taken, but it can assist with identifying websites where that photo exists as well as similar photos (possibly from the same photoset). [https://yandex.com/images/](https://yandex.com/images/) , [https://tineye.com/](https://tineye.com/) and [https://www.bing.com/visualsearch?FORM=ILPVIS](https://www.bing.com/visualsearch?FORM=ILPVIS) are great as well. Additionally, do not neglect the possibility of EXIF data existing in an image. \
Finally, breached data can be incredibly useful from an investigative standpoint. Breach data does not just include passwords. It often has full names, addresses, IP information, password hashes, and more. We can often use this information to tie to other accounts. For example, say we find an account with the email of v3ry1337h4ck3r@gmail.com. If we search that email for breached data, we might find a password or hash associated with it. If unique enough, we can search that password or hash in a breach database and use it to identify other possible accounts. We can do the same with usernames, IPs, names, etc. The possibilities are vast and one email address can lead to a slew of information.\
Websites such as [https://haveibeenpwned.com/](https://haveibeenpwned.com/) will help identify if an account has ever been breached and will, at a minimum, inform us if an account existed at one point. However, it does not provide any password information. Free sites such as [http://scylla.sh/](http://scylla.sh/) will provide password information and are easy to search through. The data on free sites can tend to be older and not up to date with the latest breach information, but these sites are still a powerful resource. Lastly, paid sites such as [https://dehashed.com/](https://dehashed.com/) offer up to date information and are easily searchable at affordable rates.
