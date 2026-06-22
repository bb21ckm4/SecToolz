

---

# Network Design

---

Add Linux Bridge to create the network adapter for the internal network on proxmox

In proxmox:
Datacenter>prod-proxmox>System>Network>Create: Linux Bridge

Fill in the following:
Name: vmbr1
IPv4/CIDR: 10.10.1.0/24
Make sure "Autostart" and "VLAN aware" are checked
Comment: LAB LAN

Click on "Apply Configuration"

---

# Firewall Setup

---

Click "Create VM"

Change the following fields:

General: 
VM ID: 100 
Name: lab-fw

OS: 
Upload pfsense image

Click on 100 (lab-fw) VM and click the following to add a network adapter to connect to the internal lab:

Leave Bridge as vmbr0 for the WAN interface 
Confirm and create VM.

Create second Network Adaptor for LAN:
Select 100 (lab-fw)
Hardware>Add>Network Device
Add Bridge to "vmbr1"

Click on Console to start fw build

Click on defaults for most until qemu qemu harddisk and click space bar 

Start setup:
Should vlans be setup now - No
Enter the WAN interface name - vtnet0
Enter the LAN interface name - vtnet1
Proceed - Yes
Option 2: Set interface IP address

Configure WAN manually:
IP: 192.168.50.3
Subnet: 24
IPv6: No
DHCP for IPv6: No
Upstream gateway: 192.168.50.1
DHCP server on LAN: no
Do you want to revert to http as the webConfigurator protocol: No

Configure LAN manually:
IP: 10.10.1.254
Subnet: 24
IPv6: No
DHCP for IPv6: No
DHCP server on LAN: yes
Start: 10.10.1.50
End: 10.10.1.100
Do you want to revert to http as the webConfigurator protocol: No

---

# AttackOS Setup

---

Click "Create VM"

Change the following fields:

General: 
VM ID: 101 
Name: lab-attackos

OS: 
Upload k-linux image

Disk - 120gb
CPU - 2 sockets/2 cores
Memory - 12288 (12gb)
Network - Bridge: vmbr1



---

# Build out pfsense fw and VLANS

---

Login to pfsense via:

https://10.10.1.254
username: admin
passwd: pfsense

Interfaces>Assignments>VLANs>Click Add
Use lan interface:
Parent Interface - "vtnet1 - lan"
VLAN Tag - 10

Repeat the process above using the lan interface and add VLAN Tags 20,30 as well

Click on Interface Assignments

Add each VLAN to an interface

Go to Interfaces>OPT1 
Check Enable interface
Description - change to VLAN10
IPv4 Configuration Type - change to Static IPv4
IPv4 Address - 10.10.10.254  /24
Click Save and Apply Changes

Follow the same procedure for VLANs 20,30:

Go to Firewall>Rules
Go to LAN and click on "Default allow LAN" to any rule and click Copy then select
Destination Interface: VLAN10 and click Paste

Do the same for VLAN20 and VLAN30 

Go to VLAN10 and click edit on the firewall rule and change the Source below
Source - "VLAN10 Subnets"

Do the same for VLAN20 and VLAN30 

Go to Services>DHCP Server>LAN
Add the following: 
DNS Servers - 10.10.1.254 & 8.8.8.8

VLAN10:
Click Enable DHCP server on VLAN10 interface
Address Pool Range: 10.10.10.50 - 10.10.10.100
DNS Servers - 10.10.10.254 & 8.8.8.8


---

# AttackOS Setup (cont.)

---

Install k-linux os

```bash
$ git clone https://github.com/bb21ckm4/SecToolz.git
$ sudo apt update -y && sudo apt full-upgrade -y && sudo apt autoremove -y && sudo apt autoclean -y  
$ sudo apt install kali-linux-everything   
```


Add bookmarks and run bash script

---

# Install Caldera on AttackOS

---

```bash
$ python3 -m venv CalderaVENV   # create virtual environment
$ cd CalderaVENV/
$ source bin/activate           # activate virtual environment  
$ pip install nodeenv           # install node prerequisites 
$ nodeenv -p
$ git clone https://github.com/mitre/caldera.git --recursive
$ cd caldera
$ pip3 install -r requirements.txt
$ python3 server.py --insecure --build
$ deactivate                    # to leave virtual env or "source deactivate"

```


# Install Nessus on AttackOS 

```bash
$ curl --request GET \ --url 'https://www.tenable.com/downloads/api/v2/pages/nessus/files/Nessus-10.8.4-ubuntu1604_amd64.deb' \ --output 'Nessus-10.8.4-ubuntu1604_amd64.deb'
$ sudo dpkg -i Nessus-10.8.4-ubuntu1604_amd64.deb
$ sudo systemctl start nessusd

```


---

# Ubuntu w Docker Setup

---

Click "Create VM"

Change the following fields:

General: 
VM ID: 104
Name: lab-docker

OS: 
Upload ubuntu server image

Disk - 160gb
Socket-2 
CPU - 2 
Memory - 16384 (16gb)
Network - Bridge: vmbr1


Install ubuntu server and add openssh server

---

## Install docker

---

Go to website: https://docs.docker.com/engine/install/ubuntu/

Run the following command to uninstall all conflicting packages:

```bash
$ for pkg in docker.io docker-doc docker-compose docker-compose-v2 podman-docker containerd runc; do sudo apt-get remove $pkg; done
```

1-Set up Docker's `apt` repository.

```bash
# Add Docker's official GPG key:
sudo apt-get update
sudo apt-get install ca-certificates curl
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc

# Add the repository to Apt sources:
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu \
  $(. /etc/os-release && echo "${UBUNTU_CODENAME:-$VERSION_CODENAME}") stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update
```

2-Install the Docker packages.

```bash
$ sudo apt-get install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
```

3-Verify that the installation is successful by running the `hello-world` image:

```bash
$ sudo docker run hello-world
```

Check to see if any docker containers are there:

```bash
$ sudo docker ps
```

---

## Install Portainer.IO

---

Go to website:  https://docs.portainer.io/start/install-ce/server/docker/linux

First, create the volume that Portainer Server will use to store its database:

```bash
$ sudo docker volume create portainer_data
```

Then, download and install the Portainer Server container:

```bash
$ sudo docker run -d -p 8000:8000 -p 9443:9443 --name portainer --restart=always -v /var/run/docker.sock:/var/run/docker.sock -v portainer_data:/data portainer/portainer-ce:lts
```

```bash
$ sudo docker ps
```

Go to https://10.10.20.5:9443 to access portainer.

Go to Home and click on Live Connect under the local Environment

---

# Metasploitable2 Setup

---

Click "Create VM"

Change the following fields:

General: 
VM ID: 121
Name: lab-metasploit

Disks:
Change - Bus/Device:  IDE

Memory: 4096
Network - Bridge: vmbr1



Upload "metasploitable-linux-2.0.0.zip" to directory:  /var/lib/vz/images/121 via Filezilla

Connect via shell on proxmox 

```bash
$ apt upgrade
$ apt update
$ apt install unzip 
$ unzip metasploitable-linux-2.0.0.zip  
$ cd Metasploitable2-Linux  
$ qemu-img convert -f vmdk Metasploitable.vmdk -O qcow2 Metasploitable.qcow2 
$ qm set 105 --ide0 local-lvm:0,import-from=/var/lib/vz/images/105/Metasploitable2-Linux/Metasploitable.qcow2
```

If you have any issues check boot order

---

# Portainer Testing and Network Config

---

Go to https://10.10.1.20:9443
Go to Networks and click on Add Network
Name:  vlan1-config
Driver: macvlan

ssh into 10.10.1.20 (lab-docker) run "ip a" and get the network card 
Look under altname
Parent network card: enp0s18

IPv4 Network configuration:
Subnet: 10.10.1.0/24
Gateway: 10.10.1.254
IP Range: 10.10.1.128/27

Click on "Create this Network" 

Go to Networks and click on Add Network
Name:  vlan1
Driver: macvlan

Under Macvlan configuation click on Creation and select the following below:
Configuration: vlan1-config 
Click on "Create this Network" 


---

# Container Deployment

---
## nginx

Click on Containers
Click Add Container
Name: lab-nginx
Image: nginx

Advanced container settings:
Click on Network:
Network: vlan1
Click on deploy container

---
## bWAPP

Click on Containers
Click Add Container
Name: lab-bwapp
Image: raesene/bwapp

Advanced container settings:
Click on Network:
Network: vlan1
Click on deploy container

Go to website: https://10.10.1.*/install.php  
Click install on web page

website: https://10.10.1.*/login.php  

---

## DWVA

Click on Containers
Click Add Container
Name: lab-dvwa
Image: vulnerables/web-dvwa

Advanced container settings:
Click on Network:
Network: vlan1
Click on deploy container

website: https://10.10.1.*/login.php  

---

## Webgoat

Click on Containers
Click Add Container
Name: lab-webgoat
Image: webgoat/webgoat-8.0

Advanced container settings:
Click on Network:
Network: vlan1
Click on deploy container

website: https://10.10.1.*:8080/WebGoat//login  


---

# Security Onion setup


Click "Create VM"

Change the following fields:

General: 
VM ID: 213
Name: prod-so

OS: 
Upload seconion image

Disk - 200gb
Cores-4
Memory - 16384(16gb)
Network - Bridge: vmbr1
VLAN Tag: 10

Change Processors Type to "host"

Add another network card:
Hardware>Add 

Network - Bridge: vmbr1
VLAN Tag: 10

---

# Windows 10 WAMP

Click "Create VM"

Change the following fields:

General: 
VM ID: 112
Name: lab-wamp

Disks:
Change - Bus/Device:  IDE

CPU Cores-2
Memory: 8192
Network - Bridge: vmbr1

HardWare>Network Device>Edit
Change Model: to Realtek RTL8139

```bash
$ qemu-img convert -f vdi RTO-Win10-disk001.vdi -O qcow2 RTO-Win10-disk001.qcow2  
$ qm set 112 --ide0 local-lvm:0,import-from=/var/lib/vz/images/112/RTO-Win10-disk001.qcow2


```

Install wamp server


---

# Windows 2022 DC

Click "Create VM"

Change the following fields:

General: 
VM ID: 110
Name: lab-dc

OS: 
Upload Windows 2022

Disk - 120gb
CPU - 2 sockets/2 cores
Memory - 12288 (12gb)
Network - Bridge: vmbr1