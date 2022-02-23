#!/bin/bash

# Author: Joel Russo - jolick

##### settings
#--- Note: Most of the tools that will be git clone will be placed in the directory "$outdir", in exception to wordlists which will be placed in /usr/share/wordlists and pratical tools like impacket, webshells which will be placed in $optdir

#--- for a more pratical use
outdir="/usr/share"    # where to save files of tools
optdir="/opt"          # where commonly used tools will go to

#--- your user
user=$(who am i | awk '{print $1}') #current user running script
#--- or if you want to set another user
#user="joel"


####################################################

##### Colours
RED="\033[01;31m"      # Issues/Errors
GREEN="\033[01;32m"    # Success
YELLOW="\033[01;33m"   # Warnings/Information
BLUE="\033[01;34m"     # Heading
BOLD="\033[01;01m"     # Highlight
RESET="\033[00m"       # Normal

##### Auto-completion in read

#bind TAB:menu-complete
set -o emacs
bind 'set show-all-if-ambiguous on'
bind 'set completion-ignore-case on'
bind 'TAB:dynamic-complete-history'

# Available comands to autocomplete
cmds="exit q 1 2 3 4 5 6 "

for i in $cmds ; do
    history -s $i
done



#--Start--------------------------------------------------------------#

##### running as root
function checkroot () {
    if [[ ${EUID} -ne 0 ]]; then
          echo -e ' '${RED}'[!]'${RESET}" This script must be ${RED}run as root${RESET}. Quitting..." 1>&2
          exit 1
    else
        echo -e " ${BLUE}[*]${RESET} ${BOLD}Parrot tools post fresh install ${RESET}"
    fi
}


##### update and upgrade sistem
function update () {
    echo -e "\n\n ${GREEN}[+]${RESET} ${GREEN}Updating system...${RESET}"
    apt-get -y -qq update || echo -e ' '${RED}'[!] Issue with apt-get'${RESET} 1>&2
}

function upgrade () {
    echo -e "\n\n ${GREEN}[+]${RESET} ${GREEN}Upgrading system...${RESET}"
    apt-get -y -qq dist-upgrade || echo -e ' '${RED}'[!] Issue with apt-get'${RESET} 1>&2
}

function checkInternet () {
    echo -e "\n ${GREEN}[+]${RESET} Checking ${GREEN}Internet access${RESET}"
    for i in {1..10}; do ping -c 1 -W ${i} www.google.com &>/dev/null && break; done
    if [[ "$?" -ne 0 ]]; then
      echo -e ' '${RED}'[!]'${RESET}" ${RED}No Internet access${RESET}. Manually fix the issue & re-run the script" 1>&2
      if [[ $(sudo dmidecode -s system-manufacturer) == "innotek GmbH" ]]; then
        echo -e " ${YELLOW}[i]${RESET} VM Detected. ${YELLOW}Try switching network adapter mode${RESET} (NAT/Bridged)"
        echo -e ' '${RED}'[!]'${RESET}" Quitting..." 1>&2
        exit 1
      fi
    else
      echo -e " ${YELLOW}[i]${RESET} ${YELLOW}Detected Internet access${RESET}" 1>&2
    fi
    echo
}

##### Add parrot repository
function addTools () {
    file="/etc/apt/sources.list.d/parrot.list"
    echo "deb https://deb.parrotlinux.org/parrot/ rolling main contrib non-free" > ${file}
    echo "#deb-src https://deb.parrotlinux.org/parrot/ rolling main contrib non-free" >> ${file}
    echo "deb https://deb.parrotlinux.org/parrot/ rolling-security main contrib non-free" >> ${file}
    echo "#deb-src https://deb.parrotlinux.org/parrot/ rolling-security main contrib non-free" >> ${file}
    #--- Add key
    echo -e "\n\n ${GREEN}[+]${RESET} Installing ${GREEN}Parrot gpg and keyring${RESET}"
    wget -qO - http://archive.parrotsec.org/parrot/misc/parrotsec.gpg | apt-key add -
    apt-get -y -qq update
    apt-get -y -qq install apt-parrot parrot-archive-keyring --no-install-recommends
}

##### Clean the system
function cleanSystem () {
  echo -e "\n ${GREEN}[+]${RESET} ${GREEN}Cleaning${RESET} the system"
  #echo -e ' '${YELLOW}'[i]'${RESET}" removing parrot keys..."
  #rm -rf /etc/apt/sources.list.d/parrot.list
  #--- Clean package manager
  for FILE in clean autoremove; do apt-get -y -qq "${FILE}"; done         # Clean up - clean remove autoremove autoclean
  apt-get -y -qq purge $(dpkg -l | tail -n +6 | egrep -v '^(h|i)i' | awk '{print $2}')   # Purged packages
  #--- Update slocate database
  sudo updatedb
  #--- Reset folder location
  cd ~
}

##### Install tools
function install-tools () {
  #create oudir directory
  mkdir -p ${outdir} 
  mkdir -p /usr/share/wordlists/
  cd ${outdir}

  echo -e "\n ${GREEN}[+]${RESET} Installing dependencies"
  #list of dependencies and programing languages
  deps=( curl git apt-transport-https build-essential gdb libpcap-dev golang p7zip-full unzip zip unrar snap ruby-dev gzip ruby python3 \
         python3-pip python3-dev libssl-dev libffi-dev binutils patch ruby-dev \
         zlib1g-dev liblzma-dev gpgv2 autoconf bison git-core libapr1 libaprutil1 \
         libgmp3-dev libpcap-dev libpq-dev libreadline6-dev libsqlite3-dev libssl-dev libsvn1 libtool libxml2 libxml2-dev \
         libxslt-dev libyaml-dev locate ncurses-dev openssl postgresql postgresql-contrib wget xsel zlib1g zlib1g-dev  )

  for x in ${deps[@]}; do echo -e "\n\n ${GREEN}[+]${RESET} Installing ${GREEN}${x}${RESET}"; apt-get -y -qq install ${x} || echo -e ' '${RED}'[!] Issue with apt-get'${RESET} 1>&2; done
  
  tools=( vim tmux zsh nmap masscan onesixtyone htop ca-certificates network-manager-openvpn network-manager-pptp \
          network-manager-vpnc network-manager-openconnect gobuster network-manager-iodine hashid cewl bsdgames proxychains \
          sshuttle apt-file apt-show-versions sqlmap sqlite3 ssldump fcrackzip john hydra cewl crunch hashid \
          flasm nasm wfuzz dmitry nfs-common hping3 ncat dnsenum binwalk smbmap gparted \
          enum4linux wireshark joomscan rubygems commix nikto exploitdb wfuzz hashcat \
          smtp-user-enum websploit amap ssldump whois socat nishang traceroute dnsutils dnsrecon mysql-server)

  for x in ${tools[@]}; do echo -e "\n\n ${GREEN}[+]${RESET} Installing ${GREEN}${x}${RESET}"; apt-get -y -qq install ${x} || echo -e ' '${RED}'[!] Issue with apt-get'${RESET} 1>&2; done

  #snaptools=( cherrytree )
  #for x in ${snaptools[@]}; do echo -e "\n\n ${GREEN}[+]${RESET} Installing ${GREEN}${x}${RESET}"; snap install $x || echo -e ' '${RED}'[!] Issue with snap install'${RESET} 1>&2; done

  gems=( evil-winrm wpscan)
  for x in ${gems[@]}; do echo -e "\n\n ${GREEN}[+]${RESET} Installing ${GREEN}${x}${RESET}"; gem install $x || echo -e ' '${RED}'[!] Issue with gem install'${RESET} 1>&2; done
  
  # updates cache
  sudo apt-file update
  
  ##### Install vulscan script for nmap
  echo -e "\n\n ${GREEN}[+]${RESET} Installing ${GREEN}vulscan script for nmap${RESET} ~ vulnerability scanner add-On"
  if [ -d /usr/share/nmap/vulnscan ]; then
    echo -e "${YELLOW} [i]${RESET} Already installed"
  else
    git clone https://github.com/scipag/vulscan /usr/share/nmap/scripts/vulscan
  fi

  ##### clone webshells
  echo -e "\n\n ${GREEN}[+]${RESET} cloning ${GREEN}webshells${RESET}"
  if [ -d /usr/share/webshells ]; then
    echo -e "${YELLOW} [i]${RESET} Already installed"
  else
    git clone -q https://github.com/BlackArch/webshells /usr/share/webshells || echo -e ' '${RED}'[!] Issue when git cloning'${RESET} 1>&2
  fi

  ##### clone reGeorg
  echo -e "\n\n ${GREEN}[+]${RESET} Installing ${GREEN}reGeorg${RESET} ~ pivot via web shells"
  if [ -d /usr/share/webshells/reGeorg ]; then
    echo -e "${YELLOW} [i]${RESET} Already installed"
  else
    git clone -q https://github.com/sensepost/reGeorg.git /usr/share/webshells/reGeorg || echo -e ' '${RED}'[!] Issue when git cloning'${RESET} 1>&2
  fi

  echo -e "\n\n ${GREEN}[+]${RESET} Cloning a bunch of ${GREEN}wordlists${RESET}"
  #clone seclists
  if [ -d /usr/share/wordlists/SecLists ]; then
    echo -e " ${YELLOW}[i]${RESET} Already cloned seclists"
  else
    wget -cq https://github.com/danielmiessler/SecLists/archive/master.zip -O /usr/share/wordlists/SecList.zip
    cd /usr/share/wordlists/ 
    unzip -o /usr/share/wordlists/SecList.zip
    mv SecLists-master SecLists
    rm -f /usr/share/wordlists/SecList.zip
    cd ~
  fi
  ##### Update wordlists
  echo -e "\n\n ${GREEN}[+]${RESET} Cloning a bunch of ${GREEN}wordlists${RESET} ~ seclists, dirbuster ..."
  # wordlists from dirbuster
  if [ -d /usr/share/wordlists/dirbuster ]; then
    echo -e " ${YELLOW}[i]${RESET} Already cloned dirbuster wordlists"
  else
    mkdir -p /usr/share/wordlists/dirbuster
    git clone -q https://github.com/daviddias/node-dirbuster /usr/share/wordlists/dirbuster-git || echo -e ' '${RED}'[!] Issue when git cloning'${RESET} 1>&2
    mv /usr/share/wordlists/dirbuster-git/lists/* /usr/share/wordlists/dirbuster
    rm -rf /usr/share/wordlists/dirbuster-git
  fi

  # usernames.txt
  if [ -f /usr/share/wordlists/usernames.txt ]; then
    echo -e " ${YELLOW}[i]${RESET} Already downloaded usernames.txt"
  else
    cd /usr/share/wordlists/
    wget -c "https://raw.githubusercontent.com/jeanphorn/wordlist/master/usernames.txt" || echo -e ' '${RED}'[!] Issue when downloading'{RESET} 1>&2
    sed -ie "s/\r//g" usernames.txt

  fi 
  # more from dirbuster
  if [ -f /usr/share/wordlists/dirbuster/big.txt ]; then
    echo -e " ${YELLOW}[i]${RESET} Already cloned more dirbuster wordlists"
  else
    git clone -q https://github.com/digination/dirbuster-ng /usr/share/wordlists/dirbuster-git || echo -e ' '${RED}'[!] Issue when git cloning'${RESET} 1>&2
    mkdir -p /usr/share/wordlists/dirbuster
    mv /usr/share/wordlists/dirbuster-git/wordlists/* /usr/share/wordlists/dirbuster/
    rm -rf /usr/share/wordlists/dirbuster-git
  fi

  #--- Extract rockyou wordlist
  if [ -f /usr/share/wordlists/rockyou.txt ];then
    echo -e "${YELLOW} [i]${RESET} Already installed"
  else
    wget -qc https://github.com/praetorian-code/Hob0Rules/raw/master/wordlists/rockyou.txt.gz -O /usr/share/wordlists/rockyou.txt.gz || echo -e ' '${RED}'[!] Issue when donwloading'${RESET} 1>&2
    gzip -dc < /usr/share/wordlists/rockyou.txt.gz > /usr/share/wordlists/rockyou.txt
    rm -rf /usr/share/wordlists/rockyou.txt.gz
  fi

  ##### pwn tools and upgrade pip
  apt-get update
  sudo -u ${user} python3 -m pip install -q --upgrade pip
  sudo -u ${user} python3 -m pip install -q --upgrade git+https://github.com/Gallopsled/pwntools.git@dev

  # Install impacket
  echo -e "\n\n ${GREEN}[+]${RESET} Installing ${GREEN}impacket${RESET} ~ tools"
  if [ -d ${optdir}/impacket ];then
    echo -e "${YELLOW} [i]${RESET} Already installed"
  else
    #dependency for ldap3
    sudo -u ${user} pip3 install pyasn1==0.4.6
    git clone -q https://github.com/SecureAuthCorp/impacket ${optdir}/impacket || echo -e ' '${RED}'[!] Issue when git cloning'${RESET} 1>&2
    sudo -u ${user}  pip3 install -q ${optdir}/impacket
  fi

  ##### Install peda
  if [ -d ${outdir}/peda ];then
    echo -e "${YELLOW} [i]${RESET} Already installed"
  else
    git clone https://github.com/longld/peda.git ${outdir}/peda
    if [ -d ~/.gdbinit ];then
      echo 'source '${outdir}'/peda/peda.py' >> ~/.gdbinit
    fi
    if [ -d ~${user}/.gdbinit ];then
      echo 'source '${outdir}'/peda/peda.py' >> ~${user}/.gdbinit
    fi
  fi

  ##### Clone p0wny-shell
  echo -e "\n\n ${GREEN}[+]${RESET} Cloning ${GREEN}p0wny-shell${RESET} ~ cool php shell"
  if [ -d /usr/share/webshells/p0wny-shell ];then
    echo -e "${YELLOW} [i]${RESET} Already installed"
  else
    git clone -q https://github.com/flozz/p0wny-shell /usr/share/webshells/p0wny-shell || echo -e ' '${RED}'[!] Issue when git cloning'${RESET} 1>&2
  fi
 
  ##### clone pspy
  echo -e "\n\n ${GREEN}[+]${RESET} Cloning ${GREEN}pspy${RESET} ~ Monitor linux processes without root permissions "
  if [ -d ${optdir}/pspy ];then
    echo -e "${YELLOW} [i]${RESET} Already installed"
  else
    mkdir -p ${optdir}/pspy
    wget -qc https://github.com/DominicBreuker/pspy/releases/download/v1.2.0/pspy32 -O ${optdir}/pspy/pspy32 || echo -e ' '${RED}'[!] Issue with download'${RESET} 1>&2
    wget -qc https://github.com/DominicBreuker/pspy/releases/download/v1.2.0/pspy64 -O ${optdir}/pspy/pspy64 || echo -e ' '${RED}'[!] Issue with download'${RESET} 1>&2
  fi
  
  ##### Clone theHarvester
  echo -e "\n\n ${GREEN}[+]${RESET} Cloning ${GREEN}theHarvester${RESET} ~ E-mails, subdomains and names Harvester - OSINT "
  if [ -d /etc/theHarvester ];then
    echo -e "${YELLOW} [i]${RESET} Already installed"
  else
    git clone -q https://github.com/laramies/theHarvester || echo -e ' '${RED}'[!] Issue when git cloning'${RESET} 1>&2
   
    cd theHarvester
    python3 -m pip install -r requirements/base.txt
    cd ..
    mv theHarvester /etc/theHarvester
    echo "export PATH=$PATH:/etc/theHarvester" >> ~/.bashrc
  fi
  
  ##### Metasploit-framework
  #echo -e "\n${YELLOW} [i]${RESET} Installing ${GREEN}postgresql${RESET}"
  #sudo apt update && sudo apt-get install -y postgresql postgresql-client || echo -e ' '${RED}'[!] Issue with apt-get'${RESET} 1>&2
  #sudo service postgresql start && sudo update-rc.d postgresql enable
  echo -e "\n${YELLOW} [i]${RESET} Installing ${GREEN}Metasploit-framework${RESET}"
  # Note: metasploit package from parrot OS repo is broken so the installation is via the suggested from rapid7
  # apt-get -y -qq install metasploit-framework || echo -e ' '${RED}'[!] Issue with apt-get'${RESET} 1>&2
  # Instaliing recomendend from metasploit github
  # https://github.com/rapid7/metasploit-framework/wiki/Nightly-Installers
  curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall
  chmod 755 msfinstall
  ./msfinstall
  rm msfinstall
 
  echo -e "\n${YELLOW} [i]${RESET} Configuring ${GREEN}Metasploit-framework${RESET}..."
  msfdb init
  
  
  ##### burpsuite how to install
  echo -e "\n\n${YELLOW} [i]${RESET} How to install ${GREEN}burpsuite${RESET}"
  echo -e "${YELLOW} [i]${RESET} Download from ${GREEN}https://portswigger.net/burp/releases${RESET}"
  echo -e "${YELLOW} [i]${RESET} cd Downloads"
  echo -e "${YELLOW} [i]${RESET} chmod +x the executable"
  echo -e "${YELLOW} [i]${RESET} ./ it\n\n"

}

function setPermissions() {
    find /usr/share/wordlists/ -exec chown -v -R ${user}:${user} {} +
    
    find ${optdir}/impacket -exec chown -v -R ${user}:${user} {} \;
    find ${optdir}/pspy -exec chown -v -R ${user}:${user} {} \;
}

function helpMessagePPA () {
    clear
    echo -e '\n '${YELLOW}'[i] Steps to set PPA permission.'${RESET}
    echo -e '\n '${BOLD}${RED}'[!] Not doing this'${BOLD}' will'${RESET}${RED}' break you linux'${RESET}
    
    echo -e " ${GREEN}[*]${RESET} cd /etc/apt/preferences.d/"   
    echo -e " ${GREEN}[*]${RESET} gedit parrot-pinning "   
    echo -e " ${GREEN}[*]${RESET} set Pin-Priority of kali and Parrot to a number inferior of ubuntu and all others"
    echo -e " ${GREEN}[*]${RESET} example: parrot and kali to 500 and ubuntu and others to 700\n\n"
}

##### Initial menu
function menu () {
    #install
    echo -e '\n '${YELLOW}'[i] Some downloads will fail, repeat step 4 until all are installed'${RESET}
    echo -e '\n '${YELLOW}'[i]'${RESET}' '${BOLD}'Install - Choose one by one in order'${RESET}
    echo -e ' '${BLUE}'[1]'${RESET}" Update and upgrade"
    echo -e ' '${BLUE}'[2]'${RESET}" Add parrot-tools to apt"
    echo -e ' '${BLUE}'[3]'${RESET}" Change PPA permissions manually"
    echo -e ' '${BLUE}'[4]'${RESET}" Update and upgrade"
    echo -e ' '${BLUE}'[5]'${RESET}" Install tools"
    echo -e ' '${BLUE}'[6]'${RESET}" Clean system"
    echo -e ' '${BLUE}'[7]'${RESET}" Set folders permissions"
    
    echo -e '\n '${BLUE}'[q]'${RESET}" exit\n"
    read -e -p  "$(echo -e ' '${BOLD}'[>]'${RESET}' ')" opt

    case $opt in
      "1" | "4")
          update
          upgrade
          echo -e "\n ${BLUE}[*]${RESET} Done\n"
          menu
        ;;
      "2")
          addTools
          echo -e "\n ${BLUE}[*]${RESET} Added tools\n"
          menu
        ;;
      "3")
          helpMessagePPA
          menu
        ;;
      "5")
          clear
          install-tools
          menu
        ;;
      "6")
          echo
          cleanSystem
          menu
        ;;
      "7")
          echo -e "\n ${BLUE}[*]${RESET} Setting permissions... This might take a while\n"
          setPermissions
          menu
        ;;
      "exit" | "q")
          exit 0
          echo
        ;;
      *)
          clear
          echo -e '\n '${RED}'[!]'${RESET}" invalid opperation or invalid here\n"
          menu
        ;;
    esac
}

function main () {
    clear
    checkroot
    checkInternet
    menu
}

clear
main
