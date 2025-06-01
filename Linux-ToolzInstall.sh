#!/bin/bash
devloop='y'
while [ $devloop == 'y' ] || [ $devloop == 'Y' ];
do
clear
echo -e "\e[37m======================================================";
echo ""
echo -e "\e[37m ArchOS Build Installer"
echo " Tool Package Installer TPI v2.0"
echo " Created by bb21ckm4 for Debian based distros"
echo ""
echo -e "\e[37m======================================================";
echo ""
echo -e "\e[92m 1.  ArchOS-BaseOS Toolz\e[37m[ArchOS Toolz]";
echo -e "\e[92m 2.  AttackOS Toolz\e[37m[ArchOS Toolz]";
echo -e "\e[92m 3.  Adding BlackArch Repo\e[37m[ArchOS Toolz]";
echo -e "\e[92m 4.  Debian-Based Toolz\e[37m[ParrotOS-HTB Toolz]";
echo ""
echo -e "\e[37m=====================================================";
read -p " Your Choice [1-2] Type cya to Exit :" menu;
echo "=====================================================";
case $menu in
1)
sudo pacman -S fastfetch filezilla gnome-disk-utility htop obsidian remmina terminator virtualbox virtualbox-host-dkms vokoscreen zsh && sudo usermod -aG vboxusers labuser
;;
2)
sudo pacman -S cewl crackmapexec crackmapexec-pingcastle detect-it-easy dirb dnspy droopescan evil-winrm exploit-db ffuf filezilla gdb gnome-disk-utility go gobuster htop ida-free kerberoast kerbrute metasploit mimikatz nasm neofetch netexec-pingcastle netexec networkminer nikto npm obsidian pe-bear proxychains-ng python python-pip python-pipx remmina sqlmap strace terminator wireshark-qt wpscan zaproxy zsh && yay -S powershell-bin
;;
3)
curl -O https://blackarch.org/strap.sh && echo bbf0a0b838aed0ec05fff2d375dd17591cbdf8aa strap.sh | sha1sum -c && chmod +x strap.sh && sudo ./strap.sh && sudo pacman -Syu
;;
4)
sudo apt-get install 7zip aircrack-ng apt-transport-https backdoor-factory beef-xss bind9-dnsutils bloodhound bundler burpsuite cewl checksec cowpatty creddump7 curl cymothoa dirb dirbuster dbd dns2tcp eapmd5pass enum4linux ettercap-common ettercap-graphical evil-winrm exe2hexbat exploitdb fcrackzip fern-wifi-cracker ffuf filezilla freeradius-wpe ftp gdb gdb-peda git gnome-disk-utility gobuster gufw hashcat htop hydra inetsim iodine john john-data joomscan laudanum libimage-exiftool-perl libproxychains4 libc6 libgcc-s1 libpcap0.8 libpq5 libsqlite3-0 libstdc++6 locate macchanger mdk3 mdk4 metasploit-framework mimikatz miredo mitmproxy nasm net-tools nginx nishang nikto nbtscan nmap ncat netcat-traditional openssl openvpn onesixtyone ophcrack php pdfcrack pixiewps postgresql powersploit powercat proxychains4 proxytunnel ptunnel pwnat python3-full python3-pip python3-scapy rake rdesktop reaver ropper ruby ruby-json sbd seclists shellter sipcrack skipfish smbclient snmp sqlmap sslscan sslh stunnel4 software-properties-common tcpdump terminator tor udptunnel unrar unix-privesc-check veil vlc wafw00f wce webacoo webshells weevely whatweb wifi-honey wifite windows-binaries windows-privesc-check wireshark wget wordlists yara yersinia zaproxy zsh && gem install wpscan
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




