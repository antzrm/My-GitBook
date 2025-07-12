# AWS

## awscli

{% code fullWidth="true" %}
```sh
https://www.cyberciti.biz/faq/how-to-install-aws-cli-on-linux/
https://exploit-notes.hdks.org/exploit/web/cloud/aws-pentesting/

which aws
aws s3api list-buckets
aws s3 ls s3://$BUCKET_NAME
aws s3 cp /tmp/file s3://$BUCKET_NAME/file

└─$ aws configure                                                                                                                                                      130 ⨯
AWS Access Key ID [None]: a
AWS Secret Access Key [None]: a
Default region name [None]: a
Default output format [None]: a

aws s3 ls --endpoint-url http://s3.dom.com s3://dom.com
aws s3 ls s3://dom.com                                                                           
```
{% endcode %}
