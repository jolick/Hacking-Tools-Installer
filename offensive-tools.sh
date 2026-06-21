#!/bin/bash

# Author: Joel Russo - jolick

##### settings
#--- Note: Tools come from Ubuntu (apt) or via uv (python). Kali repo is added but pinned low,
#--- only as fallback for tools Ubuntu doesn't have. Core libs are blocked from Kali to not break the host.

#--- for a more pratical use
outdir="/usr/share"    # where to save files of tools
optdir="/opt/tools"    # commonly used tools, user-writable

#--- your user
user="${SUDO_USER:-$(logname)}"   # user that called sudo
userhome=$(getent passwd "${user}" | cut -d: -f6)
#--- or if you want to set another user
#user="joel"


####################################################
##### What to install ~ edit these lists, comment a line to skip a tool

#--- dependencies and languages (apt)
deps=( curl git wget gpg ca-certificates build-essential gdb binutils \
       p7zip-full unzip zip gzip \
       ruby ruby-dev \
       python3 python3-dev libssl-dev libffi-dev \
       plocate openssl xsel )

#--- tools (apt; some come from the Kali repo)
tools=( vim tmux nmap masscan onesixtyone htop network-manager-openvpn \
        network-manager-vpnc network-manager-openconnect gobuster network-manager-iodine hashid cewl proxychains4 \
        sshuttle sqlmap sqlite3 fcrackzip john hydra crunch \
        nasm nfs-common hping3 ncat dnsenum binwalk smbmap ffuf feroxbuster \
        enum4linux wireshark joomscan nikto exploitdb hashcat responder \
        smtp-user-enum whois socat traceroute dnsutils dnsrecon )

#--- ruby gems
gems=( evil-winrm wpscan )

#--- python tools (uv)
uvtools=(
  impacket
  pwntools
  bloodhound-ce                                 # BloodHound.py CE collector
  bloodyAD
  coercer                                       # superset of PetitPotam
  certipy-ad                                    # ADCS attacks
  mitm6
  ldapdomaindump
  droopescan
  git+https://github.com/laramies/theHarvester  # not on pypi
  git+https://github.com/Pennyw0rth/NetExec     # netexec
  git+https://github.com/cddmp/enum4linux-ng    # not on pypi
)

#--- go tools (prebuilt release):  repo | asset-grep | type (raw/gz/tar/zip) | outname
gotools=(
  "ropnop/kerbrute|kerbrute_linux_amd64|raw|kerbrute"
)

#--- extra components (true/false)
install_bloodhound=true
install_ghidra=true
install_burp=true


####################################################

##### Colours
RED="\033[01;31m"      # Issues/Errors
GREEN="\033[01;32m"    # Success
YELLOW="\033[01;33m"   # Warnings/Information
BLUE="\033[01;34m"     # Heading
BOLD="\033[01;01m"     # Highlight
RESET="\033[00m"       # Normal

##### Message helpers
err  () { echo -e ' '${RED}'[!] '"${*}"${RESET} 1>&2; }   # [!] problem (stderr)
info () { echo -e " ${YELLOW}[i]${RESET} ${*}"; }          # [i] note
ok   () { echo -e "\n ${GREEN}[+]${RESET} ${*}"; }         # [+] doing something
hdr  () { echo -e "\n ${BLUE}[*]${RESET} ${*}"; }          # [*] heading / done

##### Auto-completion in read

# only in an interactive shell (bind errors under sudo)
if [[ $- == *i* ]]; then
    #bind TAB:menu-complete
    set -o emacs
    bind 'set show-all-if-ambiguous on'
    bind 'set completion-ignore-case on'
    bind 'TAB:dynamic-complete-history'

    # Available comands to autocomplete
    cmds="exit q U A 1 2 3 4 5 "
    for i in $cmds ; do
        history -s $i
    done
fi


#--Start--------------------------------------------------------------#

##### running as root
function checkroot () {
    if [[ ${EUID} -ne 0 ]]; then
        err "This script must be ${RED}run as root${RESET}. Quitting..."
        exit 1
    else
        hdr "${BOLD}Hacking tools post fresh install ${RESET}"
    fi
}


##### update and upgrade sistem
function update () {
    ok "${GREEN}Updating system...${RESET}"
    apt -y -qq update || err 'Issue with apt'
}

function upgrade () {
    # apt-get upgrade never downgrades/removes, just holds back
    ok "${GREEN}Upgrading system...${RESET}"
    apt-get -y -qq upgrade || err 'Issue with apt'
}

function checkInternet () {
    ok "Checking ${GREEN}Internet access${RESET}"
    for i in {1..10}; do ping -c 1 -W ${i} www.google.com &>/dev/null && break; done
    if [[ "$?" -ne 0 ]]; then
      err "${RED}No Internet access${RESET}. Manually fix the issue & re-run the script"
      if [[ $(systemd-detect-virt) != "none" ]]; then
        info "VM Detected. ${YELLOW}Try switching network adapter mode${RESET} (NAT/Bridged)"
        err "Quitting..."
        exit 1
      fi
    else
      info "${YELLOW}Detected Internet access${RESET}"
    fi
    echo
}

##### Add Kali repository
function addKaliRepo () {
    #--- prereqs (runs before the deps step)
    apt -y -qq install curl gpg ca-certificates || err 'Issue with apt'

    ok "Installing ${GREEN}Kali keyring${RESET}"
    install -d -m 0755 /etc/apt/keyrings
    curl -fsSL https://archive.kali.org/archive-keyring.gpg \
      | gpg --dearmor \
      | tee /etc/apt/keyrings/kali-archive-keyring.gpg > /dev/null \
      || err 'Issue downloading Kali keyring'

    file="/etc/apt/sources.list.d/kali.sources"
    echo "Types: deb" > ${file}
    echo "URIs: http://http.kali.org/kali" >> ${file}
    echo "Suites: kali-rolling" >> ${file}
    echo "Components: main contrib non-free non-free-firmware" >> ${file}
    echo "Signed-By: /etc/apt/keyrings/kali-archive-keyring.gpg" >> ${file}

    setPinning
    apt -y -qq update
}

##### Pin the Kali repo
# Kali below Ubuntu, and core libs pinned negative so they never come from Kali
function setPinning () {
    file="/etc/apt/preferences.d/kali-pinning"
    echo "Package: *" > ${file}
    echo "Pin: release o=Kali" >> ${file}
    echo "Pin-Priority: 100" >> ${file}
    echo "" >> ${file}
    echo "Package: libc6 libc-bin libc6-dev libstdc++6 libssl* libgcc-s1 libgmp* zlib1g systemd* udev" >> ${file}
    echo "Pin: release o=Kali" >> ${file}
    echo "Pin-Priority: -1" >> ${file}
}

##### Clean the system
function cleanSystem () {
  ok "${GREEN}Cleaning${RESET} the system"
  for FILE in clean autoremove autoclean; do apt -y -qq "${FILE}"; done
  updatedb
  cd ~ || return
}

##### uv - python tool manager
function installUv () {
  if sudo -u ${user} bash -lc 'export PATH="$HOME/.local/bin:$PATH"; command -v uv' &>/dev/null; then
    info "uv already installed"
  else
    ok "Installing ${GREEN}uv${RESET}"
    sudo -u ${user} bash -lc 'curl -LsSf https://astral.sh/uv/install.sh | sh'
  fi
}

#--- install a python tool with uv, as the user
function uvInstall () {
  ok "Installing ${GREEN}${1}${RESET} ~ uv"
  # pin python 3.12, 3.14 breaks some builds
  sudo -u ${user} bash -lc "export PATH=\"\$HOME/.local/bin:\$HOME/.cargo/bin:\$PATH\"; uv tool install --python 3.12 ${1}" || err "Issue with uv ${1}"
}

##### BloodHound CE via docker (bloodhound-cli)
function installBloodHound () {
  ok "Installing ${GREEN}BloodHound CE${RESET} ~ docker + bloodhound-cli"
  #--- docker + compose v2
  apt -y -qq install docker.io docker-compose-v2 || err 'Issue with apt'
  systemctl enable --now docker
  usermod -aG docker ${user}
  #--- bloodhound-cli wraps docker compose
  if [ -f ${optdir}/bloodhound/bloodhound-cli ];then
    info "Already installed"
  else
    mkdir -p ${optdir}/bloodhound
    cd ${optdir}/bloodhound || return
    wget -qc https://github.com/SpecterOps/bloodhound-cli/releases/latest/download/bloodhound-cli-linux-amd64.tar.gz -O bloodhound-cli.tar.gz || err 'Issue with download'
    tar -xzf bloodhound-cli.tar.gz
    rm -f bloodhound-cli.tar.gz
    ./bloodhound-cli install
  fi
}

##### Ghidra 
function installGhidra () {
  ok "Installing ${GREEN}Ghidra${RESET} ~ reverse engineering suite"
  apt -y -qq install openjdk-21-jdk || err 'Issue with apt'
  if [ -d ${optdir}/ghidra ];then
    info "Already installed"
  else
    #--- grab the latest PUBLIC zip from the api
    url=$(curl -s https://api.github.com/repos/NationalSecurityAgency/ghidra/releases/latest | grep browser_download_url | grep PUBLIC | cut -d '"' -f4)
    wget -qc "${url}" -O /tmp/ghidra.zip || err 'Issue with download'
    unzip -q /tmp/ghidra.zip -d ${optdir}/
    mv ${optdir}/ghidra_*_PUBLIC ${optdir}/ghidra
    rm -f /tmp/ghidra.zip
    info "run it with ${GREEN}${optdir}/ghidra/ghidraRun${RESET}"
    makeDesktop Ghidra "${optdir}/ghidra/ghidraRun" "${optdir}/ghidra/support/ghidra.ico" "Development;Security;"
  fi
}

##### Burp Suite Community 
function installBurp () {
  ok "Installing ${GREEN}Burp Suite Community${RESET}"
  if [ -d ${optdir}/burpsuite ];then
    info "Already installed"
  else
    #--- always the latest community linux installer
    curl -fsSL "https://portswigger.net/burp/releases/download?product=community&type=Linux" -o /tmp/burp.sh || err 'Issue with download'
    chmod +x /tmp/burp.sh
    #--- install4j unattended install into /opt/tools
    /tmp/burp.sh -q -dir ${optdir}/burpsuite -overwrite
    rm -f /tmp/burp.sh
    info "run it with ${GREEN}${optdir}/burpsuite/BurpSuiteCommunity${RESET}"
    info "For Pro grab it from ${GREEN}https://portswigger.net/burp/releases${RESET}"
  fi
}

#--- desktop launcher ($1 name, $2 exec, $3 icon, $4 categories)
function makeDesktop () {
  f="/usr/share/applications/${1}.desktop"
  echo "[Desktop Entry]" > "$f"
  echo "Type=Application" >> "$f"
  echo "Name=${1}" >> "$f"
  echo "Exec=${2}" >> "$f"
  echo "Icon=${3}" >> "$f"
  echo "Categories=${4}" >> "$f"
  echo "Terminal=false" >> "$f"
  update-desktop-database 2>/dev/null
}

#--- latest github release asset url matching a pattern
function GHTool () {
  curl -s "https://api.github.com/repos/${1}/releases/latest" | grep browser_download_url | grep -i "${2}" | head -1 | cut -d '"' -f4
}


#--Install steps (called by install-tools)------------------------------#

##### dirs, PATH, debconf, and make sure the Kali repo + pinning are there
function setupHost () {
  #create dirs
  mkdir -p ${outdir}
  mkdir -p /usr/share/wordlists/
  mkdir -p ${optdir}
  chown ${user}:${user} ${optdir}
  #--- put /opt/tools and ~/.local/bin (uv tools) on the user's PATH (idempotent)
  grep -q "${optdir}" ${userhome}/.bashrc 2>/dev/null || echo "export PATH=\$PATH:${optdir}" >> ${userhome}/.bashrc
  grep -q '.local/bin' ${userhome}/.bashrc 2>/dev/null || echo 'export PATH=$PATH:$HOME/.local/bin' >> ${userhome}/.bashrc
  chown ${user}:${user} ${userhome}/.bashrc 2>/dev/null

  #--- remove interactive yes/no prompts during instalation
  export DEBIAN_FRONTEND=noninteractive
  echo "wireshark-common wireshark-common/install-setuid boolean true" | debconf-set-selections

  #--- make sure the Kali repo + pinning are there
  if [ -f /etc/apt/sources.list.d/kali.sources ]; then
    apt -y -qq update
  else
    addKaliRepo
  fi
}

##### apt deps, apt tools and ruby gems
function installApt () {
  ok "Installing dependencies"
  for x in "${deps[@]}"; do dpkg -s "$x" &>/dev/null && continue; ok "Installing ${GREEN}${x}${RESET}"; apt -y -qq install "${x}" || err 'Issue with apt'; done
  for x in "${tools[@]}"; do dpkg -s "$x" &>/dev/null && continue; ok "Installing ${GREEN}${x}${RESET}"; apt -y -qq install "${x}" || err 'Issue with apt'; done
  #--- let your user run wireshark without root
  usermod -aG wireshark ${user} 2>/dev/null
  for x in "${gems[@]}"; do gem list -i "$x" &>/dev/null && continue; ok "Installing ${GREEN}${x}${RESET}"; gem install "$x" || err 'Issue with gem install'; done
  #--- drop duplicate gem versions
  gem cleanup 2>/dev/null
}

##### python tools via uv
function installPython () {
  installUv
  # netexec builds a rust dep, so make sure cargo is there
  sudo -u ${user} bash -lc '[ -x "$HOME/.cargo/bin/cargo" ] || curl --proto "=https" --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y'
  for x in "${uvtools[@]}"; do uvInstall "$x"; done
}

##### webshells, p0wny-shell and the nmap vulscan script
function installWebshells () {
  ok "Installing ${GREEN}vulscan script for nmap${RESET} ~ vulnerability scanner add-On"
  if [ -d /usr/share/nmap/scripts/vulscan ]; then
    info "Already installed"
  else
    git clone -q https://github.com/scipag/vulscan /usr/share/nmap/scripts/vulscan
  fi

  ok "cloning ${GREEN}webshells${RESET}"
  if [ -d /usr/share/webshells ]; then
    info "Already installed"
  else
    git clone -q https://github.com/BlackArch/webshells /usr/share/webshells || err 'Issue when git cloning'
  fi

  ok "Cloning ${GREEN}p0wny-shell${RESET} ~ cool php shell"
  if [ -d /usr/share/webshells/p0wny-shell ];then
    info "Already installed"
  else
    git clone -q https://github.com/flozz/p0wny-shell /usr/share/webshells/p0wny-shell || err 'Issue when git cloning'
  fi
}

##### wordlists ~ seclists, dirbuster, usernames, rockyou
function installWordlists () {
  ok "Cloning a bunch of ${GREEN}wordlists${RESET} ~ seclists, dirbuster ..."
  #clone seclists
  if [ -d /usr/share/wordlists/SecLists ]; then
    info "Already cloned seclists"
  else
    git clone -q --depth 1 https://github.com/danielmiessler/SecLists.git /usr/share/wordlists/SecLists || err 'Issue when git cloning'
  fi
  # wordlists from dirbuster
  if [ -d /usr/share/wordlists/dirbuster ]; then
    info "Already cloned dirbuster wordlists"
  else
    mkdir -p /usr/share/wordlists/dirbuster
    git clone -q https://github.com/daviddias/node-dirbuster /usr/share/wordlists/dirbuster-git || err 'Issue when git cloning'
    mv /usr/share/wordlists/dirbuster-git/lists/* /usr/share/wordlists/dirbuster
    rm -rf /usr/share/wordlists/dirbuster-git
  fi
  # usernames.txt
  if [ -f /usr/share/wordlists/usernames.txt ]; then
    info "Already downloaded usernames.txt"
  else
    cd /usr/share/wordlists/ || return
    wget -c "https://raw.githubusercontent.com/jeanphorn/wordlist/master/usernames.txt" || err 'Issue when downloading'
    sed -ie "s/\r//g" usernames.txt
    cd ${outdir} || return
  fi
  #--- Extract rockyou wordlist
  if [ -f /usr/share/wordlists/rockyou.txt ];then
    info "Already installed"
  else
    wget -qc https://github.com/praetorian-code/Hob0Rules/raw/master/wordlists/rockyou.txt.gz -O /usr/share/wordlists/rockyou.txt.gz || err 'Issue when donwloading'
    gzip -dc < /usr/share/wordlists/rockyou.txt.gz > /usr/share/wordlists/rockyou.txt
    rm -rf /usr/share/wordlists/rockyou.txt.gz
  fi
}

##### pspy ~ monitor linux processes without root
function installPspy () {
  ok "Cloning ${GREEN}pspy${RESET} ~ Monitor linux processes without root permissions "
  if [ -d ${optdir}/pspy ];then
    info "Already installed"
  else
    mkdir -p ${optdir}/pspy
    wget -qc https://github.com/DominicBreuker/pspy/releases/latest/download/pspy32 -O ${optdir}/pspy/pspy32 || err 'Issue with download'
    wget -qc https://github.com/DominicBreuker/pspy/releases/latest/download/pspy64 -O ${optdir}/pspy/pspy64 || err 'Issue with download'
  fi
}

##### Go binaries (prebuilt releases) into /opt/tools ~ list is up top (gotools)
function installGoTools () {
  ok "Installing ${GREEN}Go tools${RESET}"
  cd ${optdir} || return
  for entry in "${gotools[@]}"; do
    IFS='|' read -r repo pat type out <<< "$entry"
    [ -f "$out" ] && continue
    ok "Installing ${GREEN}${out}${RESET}"
    url=$(GHTool "$repo" "$pat")
    case $type in
      raw) wget -qc "$url" -O "$out" && chmod +x "$out" ;;
      gz)  wget -qc "$url" -O "$out.gz" && gzip -df "$out.gz" && chmod +x "$out" ;;
      tar) wget -qc "$url" -O "$out.tgz" && tar -xzf "$out.tgz" "$out" && rm -f "$out.tgz" ;;
      zip) wget -qc "$url" -O "$out.zip" && unzip -oq "$out.zip" "$out" && rm -f "$out.zip" ;;
    esac
  done
}

##### Metasploit-framework
function installMetasploit () {
  info "Installing ${GREEN}Metasploit-framework${RESET}"
  # https://github.com/rapid7/metasploit-framework/wiki/Nightly-Installers
  curl -fsSL https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > /tmp/msfinstall
  chmod 755 /tmp/msfinstall
  /tmp/msfinstall
  rm -f /tmp/msfinstall
  # the omnibus sets up the db on first run
}

##### show BloodHound creds last
function showCreds () {
  [ -f ${optdir}/bloodhound/bloodhound-cli ] || return
  bhpass=$( cd ${optdir}/bloodhound && ./bloodhound-cli config get default_password 2>/dev/null )
  ok "${BOLD}BloodHound CE${RESET} ~ ${GREEN}http://127.0.0.1:8080/ui/login${RESET}"
  ok "login ${GREEN}admin${RESET} / password ${GREEN}${bhpass}${RESET}"
}

##### Install tools (just runs the steps above in order)
function install-tools () {
  setupHost
  installApt
  installPython
  installWebshells
  installWordlists
  installPspy
  installGoTools
  installMetasploit
  [ "$install_bloodhound" = true ] && installBloodHound
  [ "$install_ghidra" = true ] && installGhidra
  [ "$install_burp" = true ] && installBurp
  showCreds
}

##### Update everything ~ apt + uv + gems
function updateEverything () {
    update
    upgrade
    ok "Upgrading ${GREEN}uv tools${RESET}"
    sudo -u ${user} bash -lc 'export PATH="$HOME/.local/bin:$PATH"; uv tool upgrade --all' || err 'Issue with uv'
    ok "Updating ${GREEN}gems${RESET}"
    gem update || err 'Issue with gem update'
}

function setPermissions() {
    chown -R ${user}:${user} /usr/share/wordlists/
    chown -R ${user}:${user} ${optdir}
}

##### Initial menu
function menu () {
    #install
    echo -e '\n '${YELLOW}'[i] Some downloads might fail, repeat Install tools until all are installed'${RESET}
    echo -e ' '${YELLOW}'[i]'${RESET}' '${BOLD}'Run [A] for everything, or the steps one by one'${RESET}
    echo -e '\n '${BLUE}'[A]'${RESET}" Auto - do everything"
    echo -e '\n '${BLUE}'[1]'${RESET}" Update and upgrade"
    echo -e ' '${BLUE}'[2]'${RESET}" Add Kali repo to apt (auto keyring + pinning)"
    echo -e ' '${BLUE}'[3]'${RESET}" Install tools"
    echo -e ' '${BLUE}'[4]'${RESET}" Clean system"
    echo -e ' '${BLUE}'[5]'${RESET}" Set folders permissions"

    echo -e '\n '${BLUE}'[U]'${RESET}" Update everything (apt + uv + gems)"
    echo -e ' '${BLUE}'[q]'${RESET}" exit\n"
    read -e -p  "$(echo -e ' '${BOLD}'[>]'${RESET}' ')" opt

    case $opt in
      "A" | "a")
          clear
          update
          upgrade
          install-tools
          setPermissions
          hdr "Done"
          menu
        ;;
      "1")
          update
          upgrade
          hdr "Done"
          menu
        ;;
      "2")
          addKaliRepo
          hdr "Added Kali repo"
          menu
        ;;
      "3")
          clear
          install-tools
          menu
        ;;
      "4")
          echo
          cleanSystem
          menu
        ;;
      "5")
          hdr "Setting permissions... This might take a while"
          setPermissions
          menu
        ;;
      "U" | "u")
          updateEverything
          hdr "Done"
          menu
        ;;
      "exit" | "q")
          exit 0
        ;;
      *)
          clear
          err "invalid opperation or invalid here"
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
