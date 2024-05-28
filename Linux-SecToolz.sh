#!/bin/bash
devloop='y'
while [ $devloop == 'y' ] || [ $devloop == 'Y' ];
do
clear
echo -e "\e[31m======================================================";
echo ""
echo -e "\e[92m Linux SecToolz Installer"
echo " Tool Package Installer TPI v2.0"
echo " Created by bb21ckm4 for Debian based distros"
echo ""
echo ""
echo -e "\e[31m======================================================";
echo ""
echo -e "\e[92m 1. Basic Setup\e[33m[Basic Setup]";
echo -e "\e[92m 2. Web Toolkit\e[33m[Web Toolkit]";
echo -e "\e[92m 3. Recon Toolkit\e[33m[Recon Toolkit]"
echo -e "\e[92m 4. Exploitation Toolkit\e[33m[Exploitation Toolkit]";
echo -e "\e[92m 5. Post-Exploitation Toolkit\e[33m[Post-Exploitation Toolkit] ";
echo -e "\e[92m 6. Reversing Toolkit \e[33m[Reversing Toolkit] ";
echo -e "\e[92m 7. Wireless Toolkit\e[33m[Wireless Toolkit] ";
echo -e "\e[92m 8. Windows Toolkit\e[33m[Windows Toolkit] ";
echo -e "\e[92m 9. Add Repos\e[33m[Add Repos] ";
echo ""
echo -e "\e[92m=====================================================";
read -p " Your Choice [1-9] BB For Exit :" menu;
echo "=====================================================";
case $menu in
1)
apt-get install apt-transport-https bundler curl bind9-dnsutils ftp git gnome-disk-utility git gufw htop libc6 libgcc-s1 libpcap0.8 libpq5 libsqlite3-0 libstdc++6 libreoffice locate nasm net-tools openssl openvpn postgresql python3-full python3-pip rake rdesktop ruby ruby-json software-properties-common tcpdump terminator vlc wireshark wget
;;
2)
apt-get install burpsuite dirb joomscan ffuf mitmproxy nishang nikto dirbuster php libproxychains4 nginx proxychains4 skipfish sqlmap sslscan wafw00f webshells whatweb zaproxy && gem install wpscan
;;
3)
apt-get install enum4linux ettercap-common ettercap-graphical libimage-exiftool-perl nbtscan nmap ncat netcat-traditional python3-scapy smbclient snmp unix-privesc-check yersinia
;;
4)
apt-get install beef-xss cewl creddump7 exploitdb fcrackzip hashcat hydra hydra-gtk john john-data metasploit-framework mimikatz onesixtyone ophcrack pdfcrack seclists sipcrack wordlists
;;
5)
apt-get install backdoor-factory cymothoa dbd dns2tcp exe2hexbat iodine laudanum mimikatz miredo nishang powersploit proxychains4 proxytunnel ptunnel pwnat sbd shellter sslh stunnel4 udptunnel veil webacoo weevely
;;
6)
apt-get install gdb inetsim ghidra unrar yara && git clone https://github.com/volatilityfoundation/volatility.git
;;
7)
apt-get install aircrack-ng cowpatty eapmd5pass fern-wifi-cracker freeradius-wpe macchanger mdk3 mdk4 pixiewps reaver wifi-honey wifite
;;
8)
apt-get install powercat wce windows-binaries windows-privesc-check
;;
9)
add-apt-repository contrib && add-apt-repository non-free && echo "deb https://deb.parrot.sh/parrot lory main contrib non-free" | tee -a /etc/apt/sources.list && echo "deb-src https://deb.parrot.sh/parrot lory main contrib non-free" | tee -a /etc/apt/sources.list && apt-get update
;;
BB)
exit 0
;;
*)
echo "Sorry, Not Available"
;;
esac
echo -n "Back To Main Menu(y/n) :";
read devloop;
done
