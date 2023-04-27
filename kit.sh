#!/bin/bash

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

source bash_funcs.sh


show_help=false
debug=false   # true or false please

while [[ $# -gt 0 ]]; do
    case $1 in
        -all)
            system_update
            msfdb_init
            neo4j_init
            c2_sliver_install
            ;;
        -scrub)
            scrub
            ;;
        -shells)
            shell_creation
            ;;
        -tools)
            tool_install
            tool_update
            msfdb_init
            neo4j_init
            nginx_config
            c2_sliver_install
            ;;
        -jon)
            jon
            ;;
        -c2)
            c2_sliver_install
            ;;
        -secret)
            shh
            ;;
        -test)
            test
            ;;
        -h|--help)
            show_help=true
            ;;
        *)
            echo "Invalid option: $1"
            show_help=true
            exit 1
            ;;
    esac
    shift
done

if [[ $# -eq 0 && $show_help = true ]] || [[ $1 == "-h" || $1 == "--help" ]]; then
    echo -e "Pentest environment kit script. use -h or --help for help\n "
    echo -e "-all: Updates & Upgrades the OS, then installs tools and software once completed.\n"
    echo -e "-scrub: Scrub the /etc/hosts file to the default configuration.\n"
    echo -e "-shells: BROKEN, CURRENTLY DOES NOTHING.\n"
    echo -e "-tools: Installs only the tools & software.\n"
    echo -e "-jon: Prints a compliment to Jon.\n"
    echo -e "-c2: Installs malware C2 frameworks (currently sliver only).\n"
    echo -e "-test: Testing for test purposes, obviously.\n"
fi

# This is leftover code from some of the previous main pushes, its here for
## reference purposes, until we square everything up from the previous pushes

#if [ "$all" = true ]; then
#    echo "You chose all"
#    nginx_config
#    system_update
#    msfdb_init
#    neo4j_init
#    c2_sliver_install
#elif [ "$shells" = true ]; then
#    echo "You chose shells"
    # shell_creation()
#elif [ "$tools" = true ]; then
#    echo "You chose tools"
#    tool_install
#    tool_update
#    msfdb_init
#    neo4j_init
#    nginx_config
#    c2_sliver_install
#elif [ "$scrub" = true ]; then
    # This isn't doing anything just yet.
#    echo "Scrubbing /etc/hosts"
#elif [ "$jon" = true ]; then
#    jon
#elif [ "$c2" = true ]; then
#    c2_sliver_install
#elif [ "$test" = true ]; then
#    test
#else
#    echo "Pentest environment kit script. use -h or --help for help"
#fi

#function main() {
#    cd "$dldir"
#}
#
#main