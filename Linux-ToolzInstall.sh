#!/bin/bash
devloop='y'
while [ $devloop == 'y' ] || [ $devloop == 'Y' ];
do
clear
echo -e "\e[37m======================================================";
echo ""
echo -e "\e[37m Linux SecToolz Installer"
echo " Tool Package Installer TPI v2.0"
echo " Created by bb21ckm4 for Debian based distros"
echo ""
echo -e "\e[37m======================================================";
echo ""
echo -e "\e[92m 1.  Pentest Toolz\e[37m[Pentest Toolz]";
echo -e "\e[92m 2.  ArchOS Toolz\e[37m[ArchOS Toolz]";
echo ""
echo -e "\e[37m=====================================================";
read -p " Your Choice [1-2] Type cya to Exit :" menu;
echo "=====================================================";
case $menu in
1)
apt-get install 7zip apt-transport-https bloodhound bundler curl bind9-dnsutils evil-winrm ftp filezilla git gnome-disk-utility git gufw htop libc6 libgcc-s1 libpcap0.8 libpq5 libsqlite3-0 libstdc++6 locate nasm net-tools openssl openvpn postgresql python3-full python3-pip rake rdesktop ruby ruby-json software-properties-common tcpdump terminator tor vlc wireshark wget powercat wce windows-binaries windows-privesc-check burpsuite dirb dirbuster ffuf gobuster joomscan libproxychains4 mitmproxy nishang nikto php nginx proxychains4 skipfish sqlmap sslscan wafw00f webshells whatweb enum4linux ettercap-common ettercap-graphical libimage-exiftool-perl nbtscan nmap ncat netcat-traditional python3-scapy smbclient snmp unix-privesc-check yersinia beef-xss cewl creddump7 exploitdb fcrackzip hashcat hydra john john-data metasploit-framework mimikatz onesixtyone ophcrack pdfcrack seclists backdoor-factory cymothoa dbd dns2tcp exe2hexbat iodine laudanum mimikatz miredo nishang powersploit proxychains4 proxytunnel ptunnel pwnat sbd shellter sslh stunnel4 udptunnel veil webacoo weevely sipcrack wordlists gdb gdb-peda inetsim ghidra unrar yara aircrack-ng cowpatty eapmd5pass fern-wifi-cracker freeradius-wpe macchanger mdk3 mdk4 pixiewps reaver wifi-honey wifite zaproxy && gem install wpscan
;;
2)
sudo pacman -S virtualbox virtualbox-host-dkms keepass obsidian gnome-disk-utility terminator obs-studio htop filezilla && sudo usermod -aG vboxusers labuser
;;
cya)
exit 0
;;
*)
echo "Sorry, Not Available"
;;
esac
echo -n "Back To Main Menu(y/n) :";
read devloop;
done