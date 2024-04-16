#!/bin/bash

#if ! ["root" = "$(id -u - n)" ]; then
#	echo "ERROR: ${0} must be run as root!"; exit 1
#fi
 
#Paths to the database and log folder
DB_PATH=/usr/local/bin/dbip-city-lite-2024-04.mmdb
LOG_DIR_PATH=../logs/
#Cron job time in minutes
CRON_TIME=5

create_directory() {
	if [ ! -d "$1" ]; 
	then 
		echo "Directory doesn't exist, creating now"
		mkdir -p "$1"
		echo "Directory $1 created."
	else
		echo "Directory $1 already exists." 
	fi
}
#Create log directory
create_directory "$LOG_DIR_PATH"

#Capture time variable for unique file names
TIME_NOW=$(date +"%d-%m-%y_%H:%M")

#Capture journal logs
journalctl --no-pager -t vpn-user-portal -t connect_script --since "30 minutes ago" -o json > "$LOG_DIR_PATH"journal-logs.json

#Capture active WireGuard peers
sudo wg show all > "$LOG_DIR_PATH"wireguard-peers.txt

#Run python script 
mapfile -t OUTPUT < <(python3 impossible_travel.py "$LOG_DIR_PATH"journal-logs.json $DB_PATH "$LOG_DIR_PATH"wireguard-peers.txt "$LOG_DIR_PATH"outfile_"$TIME_NOW".json)

#Notify host if an impossible travel occurred
if echo "${OUTPUT[@]}" | grep -q "True"; then
	mailx -s "WARNING: Impossible Travel Detected" "$LOGNAME"@"$HOSTNAME" <<< "Impossible travel has occured on your server, please check the log files for additional information"
fi

#Remove logged wireguard data
rm "$LOG_DIR_PATH"wireguard-peers.txt

#Check if cronjob already exists for current user before adding it
CRONJOB_EXISTS=$(crontab -u "$LOGNAME" -l 2>/dev/null | grep -c "run_impossible_travel.sh")
if [ "$CRONJOB_EXISTS" -eq 0 ]; 
then
	echo "Trying to add cronjob"
	(crontab -l 2>/dev/null; echo "*/$CRON_TIME * * * * cd $HOME/eduvpn-log-analysis/scripts && ./run_impossible_travel.sh > $HOME/eduvpn-log-analysis/logs/cronjob.log 2>&1") | crontab -u "$LOGNAME" -
	echo "Cronjob added."
else
	echo "Cronjob already exists."
fi
