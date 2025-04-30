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
echo -e "\e[92m 4.  BinBox Toolz\e[37m[ParrotOS-HTB Toolz]";
echo ""
echo -e "\e[37m=====================================================";
read -p " Your Choice [1-2] Type cya to Exit :" menu;
echo "=====================================================";
case $menu in
1)
sudo pacman -S filezilla gnome-disk-utility htop keepassxc neofetch obs-studio obsidian remmina terminator virtualbox virtualbox-host-dkms zsh && sudo usermod -aG vboxusers labuser
;;
2)
sudo pacman -S burpsuite cewl crackmapexec crackmapexec-pingcastle detect-it-easy dirb dnspy droopescan evil-winrm exploit-db ffuf filezilla gdb gnome-disk-utility gobuster htop ida-free keepassxc kerberoast kerbrute metasploit mimikatz nasm neofetch netexec-pingcastle netexec networkminer nikto obs-studio obsidian pe-bear proxychains-ng python python-pip python-pipx remmina sqlmap strace terminator wireshark-qt wpscan zaproxy zsh && yay -S powershell-bin
;;
3)
curl -O https://blackarch.org/strap.sh && echo bbf0a0b838aed0ec05fff2d375dd17591cbdf8aa strap.sh | sha1sum -c && chmod +x strap.sh && sudo ./strap.sh && sudo pacman -Syu
;;
4)
sudo apt install exploit-db filezilla gdb obsidian searchsploit snapd strace terminator zsh && sudo snap install powershell --classic
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




