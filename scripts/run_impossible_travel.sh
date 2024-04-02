#!/bin/bash

#if ! ["root" = "$(id -u - n)" ]; then
#	echo "ERROR: ${0} must be run as root!"; exit 1
#fi
 
#Paths to the database and log folder
DB_PATH=../scripts/geoip2fast-asn-ipv6.dat.gz
LOG_DIR_PATH=../logs/
#Cron job time 
CRON_TIME=5

create_directory() {
	if [ ! -d $1 ]; 
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

#Capture time variables for unique file names
TIME_NOW=$(date +"%d-%m-%y_%H:%M")
TIME_EARLY=$(date -d "-$CRON_TIME min" "+%d-%m-%y_%H:%M")

#Capture journal logs
journalctl --no-pager -t vpn-user-portal -t www-data --since "1 hour ago" -o json > "$LOG_DIR_PATH"journal-logs.json

#Capture active WireGuard peers
sudo wg show all > "$LOG_DIR_PATH"wireguard-peers.txt

#Run python script
#./env/bin/python3 impossible_travel.py "$LOG_DIR_PATH"journal-logs.json $DB_PATH "$LOG_DIR_PATH"wireguard-peers.txt "$LOG_DIR_PATH"outfile_"$TIME_NOW".json 
OUTPUT=($( ./env/bin/python3 impossible_travel.py "$LOG_DIR_PATH"journal-logs.json $DB_PATH "$LOG_DIR_PATH"wireguard-peers.txt "$LOG_DIR_PATH"outfile_"$TIME_NOW".json ))

#Notify host if an impossible travel occurred
if echo "${OUTPUT[@]}" | grep -q "True"; then
	mailx -s "WARNING: Impossible Travel Detected" $LOGNAME@$HOSTNAME <<< "Impossible travel has occured on your server, please check the log files for additional information"
fi

#Remove logged wireguard data
rm "$LOG_DIR_PATH"wireguard-peers.txt

#Check if cronjob already exists for current user before adding it


CRONJOB_EXISTS=$(crontab -u $LOGNAME -l 2>/dev/null | grep -c "run_impossible_travel.sh")
if [ $CRONJOB_EXISTS -eq 0 ]; 
then
	echo "Trying to add cronjob"
	(crontab -l 2>/dev/null; echo "*/$CRON_TIME * * * * cd $HOME/debian-eduvpn-server/scripts && ./run_impossible_travel.sh > $HOME/debian-eduvpn-server/logs/cronjob.log 2>&1") | crontab -u $LOGNAME -
	echo "Cronjob added."
else
	echo "Cronjob already exists."
fi
: '
#Compare the current and previous output files and print the differences
PREVIOUS_OUTPUT="$LOG_DIR_PATH"outfile_"$TIME_EARLY".json

if [ -f "$PREVIOUS_OUTPUT" ];
then
	echo "Comparing previous and current outputs:"
	diff $PREVIOUS_OUTPUT "$LOG_DIR_PATH"outfile_"$TIME_NOW".json
else
	echo "No previous output file found for comparison."
fi
'
#cp "$LOG_DIR_PATH"outfile_"$TIME_NOW".json "$PREVIOUS_OUTPUT"
 
