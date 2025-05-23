# Magento

We can also create a new template and add a PHP file (common in several CMS).

{% code overflow="wrap" %}
```bash
https://github.com/steverobbins/magescan
https://medium.com/swlh/magento-exploitation-from-customer-to-server-user-access-70929e7bb634

- Manage products > Custom options > Add new option > File > Allowed file extensions (.php)
- Go to Magento IP > Product > Upload reverse shell > Add to cart
- Then go to $IP/media/custom_options --> inside of the subdirectories we find our revshell

# MAGENTO PANEL RCE
System > Configuration > Developer > Allow symlinks
Catalog > Manage categories > Is Active (Yes) > Upload reverse.php.png
Visit the link to the thumbnail image and note it.
Newsletter > Newsletter templates > Add New Template
Finally we use LFI to add our reverse shell in template content with this syntax:
{{block type='core/template' template='../../../../../../../../media/catalog/category/reverse.php.png'}}
When we click on preview template, our nc gets the reverse shell.

# MAGENTO PANEL RCE (ANOTHER WAY)
Filesystem > IDE
open get.php and paste your uploader script
save it and open http://$IP/get.php
upload your shell here
```
{% endcode %}
