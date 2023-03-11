# Kit
Automated Kit Framework for setting up a Kali testing environment


#TODO

- [ ] Add a CLI parameter to import a .zsh_history file
- [ ] Add a cheat sheet into the individual (future) folders with generic command syntax, etc
- [ ] Grab all of the services & ports we started, dump to the user (neo4j, smb, web, etc) (netstat -tano | grep -i "<port>"), etc.
- [X] Ensure that the Metasploit database service is up & running, provide info to the user
- [ ] Maybe do a search to check if any errors or packages werent able to be added during the script
- [ ] Do some housekeeping on function names
- [ ] Condense functions
- [X] Scrub the /etc/hosts file if argument is specified
- [ ] Check to make sure this was created from a .vmdk, not an .iso, since the .iso install is more prone to ... breaking
- [ ] Include malicious ansible playbook(s)
- [ ] Fix and improve the dynamic shell portion of the script
- [ ] Move DarkOp plugins to msf
- [ ] Make an Active Directory dir in kit - move AD tools to that directory
- [X] Make it user dynamic, not hardcoded to the kali user
- [X] Adjust the dir/file checks to local, rather than abs path
- [X] Include personal custom scripts and snippets (x11, etc)
