

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

Disk - 80gb
CPU - 2 cores
Memory - 8192 (8gb)
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

Repeat for VLANs 20 and 30 

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

# Ubuntu w Docker Setup

---

Click "Create VM"

Change the following fields:

General: 
VM ID: 120
Name: lab-docker

OS: 
Upload ubuntu server image

Disk - 160gb
Socket-2 
CPU - 2 
Memory - 16384 (16gb)
Network - Bridge: vmbr1
VLAN Tag - 20

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

Network - Bridge: vmbr1
VLAN Tag - 20


Upload "metasploitable-linux-2.0.0.zip" to directory:  /var/lib/vz/images/121 via Filezilla

Connect via shell on proxmox 

```bash
$ apt upgrade
$ apt update
$ apt install unzip 
$ unzip metasploitable-linux-2.0.0.zip  
$ cd Metasploitable2-Linux  
$ qemu-img convert -f vmdk Metasploitable.vmdk -O qcow2 Metasploitable.qcow2 
$ qm set 121 --ide0 local-lvm:0,import-from=/var/lib/vz/images/121/Metasploitable2-Linux/Metasploitable.qcow2
```

If you have any issues check boot order

---

# Portainer Testing and Network Config

---

Go to https://10.10.20.5:9443
Go to Networks and click on Add Network
Name:  vlan20-config
Driver: macvlan

ssh into 10.10.30.5 (lab-docker) run "ip a" and get the network card 
Look under altname
Parent network card: enp0s18

IPv4 Network configuration:
Subnet: 10.10.20.0/24
Gateway: 10.10.20.254
IP Range: 10.10.20.128/27

Click on "Create this Network" 

Go to Networks and click on Add Network
Name:  vlan20
Driver: macvlan

Under Macvlan configuation click on Creation and select the following below:
Configuration: vlan20-config 
Click on "Create this Network" 

Click on Containers
Click Add Container
Name: nginx-vlan20

Advanced container settings:
Click on Network:
Network: vlan20
Click on deploy container

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
Network: vlan20
Click on deploy container

---
## bWAPP

Click on Containers
Click Add Container
Name: lab-bwapp
Image: raesene/bwapp

Advanced container settings:
Click on Network:
Network: vlan20
Click on deploy container

Go to website: https://10.10.20.*/install.php  
Click install on web page

website: https://10.10.20.*/login.php  

---

## DWVA

Click on Containers
Click Add Container
Name: lab-dvwa
Image: vulnerables/web-dvwa

Advanced container settings:
Click on Network:
Network: vlan20
Click on deploy container

website: https://10.10.20.*/login.php  

---

## Webgoat

Click on Containers
Click Add Container
Name: lab-webgoat
Image: webgoat/webgoat-8.0

Advanced container settings:
Click on Network:
Network: vlan20
Click on deploy container

website: https://10.10.20.*:8080/WebGoat//login  

---

# Wazuh Setup

---

Click "Create VM"

Change the following fields:

General: 
VM ID: 104 
Name: prod-wazuh

OS: 
Upload ubuntu server image

Disk - 160gb
Cores - 4 
Memory - 8192 (8gb)
Network - Bridge: vmbr1
VLAN Tag - 10

Install ubuntu server and add openssh server

Download and run the Wazuh installation assistant:

```bash
$ curl -sO https://packages.wazuh.com/4.11/wazuh-install.sh && sudo bash ./wazuh-install.sh -a
```

  website: https://10.10.1.25

---

## Wazuh Agent Install

---

Installing on prod-attackos:
website: https://documentation.wazuh.com/current/installation-guide/wazuh-agent/wazuh-agent-package-linux.html

0-Elevate permissions

```bash
$ sudo -i
```

1-Install the GPG key:

```bash
$ curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && chmod 644 /usr/share/keyrings/wazuh.gpg
```

2-Add the repository:

```bash
$ echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | tee -a /etc/apt/sources.list.d/wazuh.list
```

3-Update the package information:

```bash
$ apt-get update
```


1-To deploy the Wazuh agent on your endpoint, select your package manager and edit the `WAZUH_MANAGER` variable to contain your Wazuh manager IP address or hostname.

```bash
$ WAZUH_MANAGER="10.10.10.50" apt-get install wazuh-agent
```

2-Enable and start the Wazuh agent service.

```bash
$ systemctl daemon-reload
$ systemctl enable wazuh-agent
$ systemctl start wazuh-agent
```

---

Installing on prod-docker:
website: https://documentation.wazuh.com/current/installation-guide/wazuh-agent/wazuh-agent-package-linux.html

0-Elevate permissions

```bash
$ sudo -i
```

1-Install the GPG key:

```bash
$ curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && chmod 644 /usr/share/keyrings/wazuh.gpg
```

2-Add the repository:

```bash
$ echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | tee -a /etc/apt/sources.list.d/wazuh.list
```

3-Update the package information:

```bash
$ apt-get update
```


1-To deploy the Wazuh agent on your endpoint, select your package manager and edit the `WAZUH_MANAGER` variable to contain your Wazuh manager IP address or hostname.

```bash
$ WAZUH_MANAGER="10.10.10.50" apt-get install wazuh-agent
```

2-Enable and start the Wazuh agent service.

```bash
$ systemctl daemon-reload
$ systemctl enable wazuh-agent
$ systemctl start wazuh-agent
```

Configure Wazuh to monitor docker:

website: https://documentation.wazuh.com/current/user-manual/capabilities/container-security/monitoring-docker.html

1-Install python3:

```bash
$ apt-get update && apt-get install python3
```

2-Install pip on debian based endpoints:

```bash
apt-get install python3-pip
```

3-Python Docker library is the official Python library for the Docker Engine API. The Wazuh docker integration requires docker 6.0.0.

```bash
pip3 install docker==7.1.0 urllib3==1.26.20 requests==2.32.2 --break-system-packages
```

1-Add the following configuration to the Wazuh agent configuration file `/var/ossec/etc/ossec.conf` to enable the Docker listener: above OSquery integration

```bash
$ sudo -i
$ nano /var/ossec/etc/ossec.conf

  <wodle name="docker-listener">
    <interval>10m</interval>
	<attempts>5</attempts>
	<run_on_start>yes</run_on_start>
	<disabled>no</disabled>
  </wodle>

```

Restart the Wazuh agent to apply the changes:

```bash
$ systemctl restart wazuh-agent
$ systemctl status wazuh-agent
```

---

## Wazuh Password Access

---

If you can no longer access that output, in `wazuh-install-files.tar` we can find the `passwords.wazuh` file where all credentials will be stored. Just unzip the file and look there:

1. Unzip:

```bash
$ tar -xvf wazuh-install-files.tar
```

2. Check the file:

```bash
$ cat wazuh-install-files/passwords.wazuh
```

---

Go to Server Settings and confirm Docker listener is enabled

---

## pfsense agent install

Guide for the agent install:
https://benheater.com/integrating-pfsense-with-wazuh/

Login and enable SSH:
System>Advanced  and check Enable Secure Shell then click Save

Choose Option 8 for a shell
Change "FreeBSD: { enabled: no }" to "FreeBSD: { enabled: yes }"

```bash
$ nano /usr/local/etc/pkg/repos/pfSense.conf
$ nano /usr/local/etc/pkg/repos/FreeBSD.conf
```


```bash
# Update the package cache
pkg install nano
pkg update

# Search the package cache for the official agent
pkg search wazuh-agent

# Install the agent
# Replace x.xx.x with your version number
pkg install wazuh-agent-x.xx.x
```

### Revert Package Repositories

When finished with the installation, please refer back to the [**Enabling FreeBSD Package Repositories**](https://benheater.com/integrating-pfsense-with-wazuh/#enabling-freebsd-package-repositories) section and revert your changes.

- Change back to `FreeBSD: { enabled: no }`
- Run `pkg clean` and `pkg update`

## Enabling and Starting the Agent

Following installation of the agent, you'll see some output on configuring your agent.

```bash
cp /etc/localtime /var/ossec/etc/
```

Now, edit the `/var/ossec/etc/ossec.conf` file and point it to your Wazuh manager and change protocol to tcp if its set at udp and theres an issue:

```xml
<server>
	<address>WAZUH-MANAGER-IP-ADDRESS</address>
	<protocol>tcp</protocol>
</server>
```


Now, start the Wazuh agent and enable start at boot — [**_using the shell script option per the official documentation_**](https://docs.netgate.com/pfsense/en/latest/development/boot-commands.html?ref=benheater.com#shell-script-option):

```bash
sysrc wazuh_agent_enable="YES"

# We don't want to remove any original files
# So, we create a symbolic link
ln -s /usr/local/etc/rc.d/wazuh-agent /usr/local/etc/rc.d/wazuh-agent.sh

service wazuh-agent start
```

Trim your Wazuh agent logs to preserve disk space:

```bash
crontab -e

# Run every day at 4 AM and delete stale logs older than 30 days
0 4 * * * find /var/ossec/logs/ossec/ -d 1 -mtime +30 -type d -exec rm -rf {} \; > /dev/null
```

## Monitoring Suricata Logs

### Enable eve.json Output

Log into your pfSense box and go to `Services > Suricata`. You should see a list of your interface(s) where Suricata is running.

[![](https://benheater.com/content/images/2022/04/image-2.png)](https://benheater.com/content/images/2022/04/image-2.png)

You'll need to click the `Edit` button **on each interface** to make these changes.

[![](https://benheater.com/content/images/2022/04/image-3.png)](https://benheater.com/content/images/2022/04/image-3.png)

Ensure these two options are set. All of the other `eve.json` options are your choice on configuring them.

Once you have enabled `eve.json` output on each desired interface, restart Suricata for the changes to take effect.

[![](https://benheater.com/content/images/2022/04/image-4.png)](https://benheater.com/content/images/2022/04/image-4.png)

### Ingesting eve.json with the Wazuh Agent

Log into your Wazuh manager using KIbana and go to `Wazuh > Management > Groups`.

[![](https://benheater.com/content/images/2022/04/image-1.png)](https://benheater.com/content/images/2022/04/image-1.png)

Click on `Add new group` and name it something like `pfSense`. Click on your new group and click `Manage agents`.

[![](https://benheater.com/content/images/2022/04/image-17.png)](https://benheater.com/content/images/2022/04/image-17.png)

Add your pfSense agent to the group and save the changes. Now, with the group created, you can add some pfSense-specific configurations.

Click the `Edit group configuration` button.

[![](https://benheater.com/content/images/2022/04/image-5.png)](https://benheater.com/content/images/2022/04/image-5.png)

Add the following lines to the group shared configuration. Once you save it, the Wazuh manager will push the changes to any member(s) of the group.

```xml
<localfile>
    <log_format>json</log_format>
    <location>/var/log/suricata/*/eve.json</location>
</localfile>
```


[![](https://benheater.com/content/images/2022/09/image-6.png)](https://benheater.com/content/images/2022/09/image-6.png)


---

## What About Syslog and Firewall Logs?

### Syslog

Fortunately, the Wazuh agent will automatically ingest `/var/log/system.log`, so no work to be done there.


### Firewall Logs

To have the Wazuh agent monitor the pfSense firewall log, just add another `<localfile></localfile>` directive to the `agent.conf` file like we did with the `eve.json` logs before.

[![](https://benheater.com/content/images/2022/04/image-15.png)](https://benheater.com/content/images/2022/04/image-15.png)

Go to `Wazuh > Management > Groups` and click on the **pfSense** group we created before. Click on `Edit group configuration`.

[![](https://benheater.com/content/images/2022/04/image-16.png)](https://benheater.com/content/images/2022/04/image-16.png)

Add this declaration to the configuration file and click **Save**.

```xml
<localfile>
	<log_format>syslog</log_format>
	<location>/var/log/filter.log</location>
</localfile>
```


#### A Note on the Firewall Log

Wazuh Manager has the decoders and rules in place to monitor the output in `/var/log/filter.log`. You can view the decoders and rules in the source code.

**Decoders** tell the Wazuh manager how to process the lines of the log output.

**Rules** tell the Wazuh manager how to take the decoded fields and arrange them in the various rules that will generate logs and/or alerts in the SIEM.

There are two pfSense rules:

- pfSense firewall drop event
- Multiple pfSense firewall blocks events from same source

The **pfSense firewall drop event** rule **does not** log by default as noted by the `<options>no_log</options>` line in the rule declaration.

⚠️

Logging this rule can become quite noisy!

```xml
<rule id="87701" level="5">
	<if_sid>87700</if_sid>
	<action>block</action>
	<options>no_log</options>
	<description>pfSense firewall drop event.</description>
	<group>firewall_block,pci_dss_1.4,gpg13_4.12,hipaa_164.312.a.1,nist_800_53_SC.7,tsc_CC6.7,tsc_CC6.8,</group>
</rule>
```

XML

Copy

The **Multiple pfSense firewall blocks events from same source** rule **does** log by default.

If you would like the **pfSense firewall drop event** logged to Wazuh, you can override the rule and I will show you how to do that.

  
  

#### Create a Custom Rule File

Open the Wazuh menu and go to `Management > Rules`

[![](https://benheater.com/content/images/2022/04/image-7.png)](https://benheater.com/content/images/2022/04/image-7.png)

In the search bar, enter the keyword `pfsense`

[![](https://benheater.com/content/images/2022/04/image-8.png)](https://benheater.com/content/images/2022/04/image-8.png)

Click on the rules file hyperlink

[![](https://benheater.com/content/images/2022/04/0540-pfsense_rules.png)](https://benheater.com/content/images/2022/04/0540-pfsense_rules.png)

Copy the entire `group` declaration from `<group>` to `</group>`

[![](https://benheater.com/content/images/2022/04/image-10.png)](https://benheater.com/content/images/2022/04/image-10.png)

Click on the back arrow

[![](https://benheater.com/content/images/2022/04/image-11.png)](https://benheater.com/content/images/2022/04/image-11.png)

Click `Add new rules file`

[![](https://benheater.com/content/images/2022/04/image-12.png)](https://benheater.com/content/images/2022/04/image-12.png)

Name it something like `pfSense-Overrides.xml`

[![](https://benheater.com/content/images/2022/04/image-13.png)](https://benheater.com/content/images/2022/04/image-13.png)

Paste the text you copied into the code editor and modify it such that it looks like this. Three observations here:

- I have added this rule to the `pfSense` group, the same as the original
- The only rule remaining here is the `pfSense firewall drop event` rule
- I have removed the `<option>no_log</option>` line and added an `overwrite="yes"` option to the rule.

```xml
<group name="pfsense,">
  <rule id="87701" level="5" overwrite="yes">
    <if_sid>87700</if_sid>
    <action>block</action>
    <description>pfSense firewall drop event.</description>
    <group>firewall_block,pci_dss_1.4,gpg13_4.12,hipaa_164.312.a.1,nist_800_53_SC.7,tsc_CC6.7,tsc_CC6.8,</group>
  </rule>
</group>
```

XML

Copy

Click **Save**. It will tell you that the rule will not apply until the Wazuh Manager is restarted. You can restart the manager from this screen.

Now, return to the alerts for your pfSense Wazuh agent and you should now see the firewall drop events.

[![](https://benheater.com/content/images/2022/04/image-14.png)](https://benheater.com/content/images/2022/04/image-14.png)

  
  

## Troubleshooting Agent Upgrades

I am adding this here as a follow up, to note some issues I had while upgrading from version `4.2` to `4.3`. Unfortunately, it seems there were some breaking changes between these major versions.

When I tried to upgrade my Wazuh Agent with the `pkg install wazuh-agent` , the installation went fine. But upon reloading the agent service with `service wazuh-agent restart` , I received this error message:

```text
Could not open file 'queue/sockets/.agent_info' ...
```

Plain text

Copy

I had to do the following to remediate:

1. SSH into Wazuh Manager
2. Remove the agent from the Manager with `/var/ossec/bin/manage_agents` , due to hostname conflicts upon re-adding the agent
3. Make a backup of your `/var/ossec/etc/ossec.conf` file
4. Uninstal, re-install, and configure the Wazuh Agent on pfSense
5. Kill any running processes not terminated by the uninstallation: `` kill -9 `pgrep wazuh` ``
6. Run `service enable wazuh-agent` and `service start wazuh-agent`
7. Re-add the agent to the pfSense group to receive the shared configuration file

Not an ideal situation, but also not a huge pain to remediate. Key notes to be aware of:

- Historic logs for your pfSense agent will be registered to a different agent ID
- Keep this in mind when browsing current/older logs by agent ID

---

# Option 2: rsyslog

## Enable Wazuh Syslog Collector


[![](https://benheater.com/content/images/2025/01/image-216.png)](https://benheater.com/content/images/2025/01/image-216.png)

Open the Wazuh menu and click "Configuration"

[![](https://benheater.com/content/images/2025/01/image-217.png)](https://benheater.com/content/images/2025/01/image-217.png)

Click "Edit configuration"

💡

You can do these same steps by editing `/var/ossec/etc/ossec.conf` via `ssh` as well and then running `sudo systemctl restart wazuh-manager`

```xml
<remote>
  <connection>syslog</connection>
  <port>514</port>
  <protocol>tcp,udp</protocol>
  <allowed-ips>SYSLOG_SENDER_1</allowed-ips>
  <allowed-ips>SYSLOG_SENDER_2</allowed-ips>
  <local_ip>WAZUH_MANAGER_IP</local_ip>
</remote>
```


Substitute `WAZUH_MANAGER_IP` AND `SYSLOG_SENDER_x` with the correct IPs. More detail about the configuration options [can be found here](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/remote.html?ref=benheater.com). Configured to receive syslog over TCP and UDP.

[![](https://benheater.com/content/images/2025/01/image-231.png)](https://benheater.com/content/images/2025/01/image-231.png)

I'm just going to place it below the existing `<remote>` configuration. In my lab environment, Wazuh Manager is on VLAN `10.148.148.0/24`, we'll see how this comes into play when configuring `rsyslog` on pfSense in just a bit.

[![](https://benheater.com/content/images/2025/01/image-220.png)](https://benheater.com/content/images/2025/01/image-220.png)

Click "Save" and once the changes are confirmed, click "Restart Manager"

  
  

## Configure pfSense to Send Syslog

[![](https://benheater.com/content/images/2025/01/image-221.png)](https://benheater.com/content/images/2025/01/image-221.png)

Log into pfSense and navigate to Status > System Logs > Settings

[![](https://benheater.com/content/images/2025/01/image-229.png)](https://benheater.com/content/images/2025/01/image-229.png)

Set the log message format to "syslog"

[![](https://benheater.com/content/images/2025/01/image-222.png)](https://benheater.com/content/images/2025/01/image-222.png)

In the "Source Address" field, I've chosen the `LAB_HOSTS` interface, as it's on the `10.148.148.0/24` VLAN. Since pfSense is the default gateway for the VLAN, the traffic will come from `10.148.148.1`, thus we configured the `<allowed_ip>10.148.148.1</allowed_ip>` before.

⚠️

If you choose any other source address and/or your Wazuh Manager is on another VLAN or network entirely, ensure you configure firewall rules to allow `udp/514` to Wazuh Manager.

[![](https://benheater.com/content/images/2025/01/image-224.png)](https://benheater.com/content/images/2025/01/image-224.png)

You can choose what you wish to send to Wazuh. I chose "Everything" for the sake of this example. Click "Save" when finished.

  
  

## Viewing Logs in Wazuh

⚠️

The syslog events sent to Wazuh Manager are _****NOT going to be logged****_ in a default Wazuh Installation, as they're not going to match on any configured rules, nor have a minimum alert threshold of `>= 3`. In a default installation, you'll need to write a custom rule to set specific syslog events to match your rule threshold.  
  
_****In my environment****_, I've configured `logall_json`, such that we log all incoming events that can be read by a valid decoder. In this case, the events are written in `syslog` format, so should have no problem decoding.  
  
Be advised that enabling `logall_json` in Wazuh Manager, does add an incredible amount of detail pertaining to logs and events, but _****it also increases the storage requirements manyfold****_. So, if you go this route, ensure you have adequate storage for your Wazuh Manager.

[

Hunting with Wazuh: Adding Context

In this post, I elaborate on the Log All JSON option in the Wazuh Manager’s configuration and how that can add more context beyond just alerts.

![](https://benheater.com/content/images/icon/pour-over-4-15.png)0xBEN0xBEN

![](https://benheater.com/content/images/thumbnail/wazuh-logo-1.jpg)

](https://benheater.com/hunting-with-wazuh-adding-context/)

More information on enabling the `logll_json` option in Wazuh

[![](https://benheater.com/content/images/2025/01/image-226.png)](https://benheater.com/content/images/2025/01/image-226.png)

Open the side menu and go to "Discover"

[![](https://benheater.com/content/images/2025/01/image-225.png)](https://benheater.com/content/images/2025/01/image-225.png)

[![](https://benheater.com/content/images/2025/01/image-230.png)](https://benheater.com/content/images/2025/01/image-230.png)

---

# Nessus Setup

Click "Create VM"

Change the following fields:

General: 
VM ID: 206
Name: prod-nessus

OS: 
Upload ubuntu server image

Disk - 40gb
Cores-4
Memory - 4096 (4gb)
Network - Bridge: vmbr1

Install ubuntu server and add openssh server


Download nessus by curl and install:

```bash
$ curl --request GET \ --url 'https://www.tenable.com/downloads/api/v2/pages/nessus/files/Nessus-10.8.4-ubuntu1604_amd64.deb' \ --output 'Nessus-10.8.4-ubuntu1604_amd64.deb'
$ sudo dpkg -i Nessus-10.8.4-ubuntu1604_amd64.deb
$ sudo systemctl start nessusd

```


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
