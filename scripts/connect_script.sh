#!/bin/bash

if [ "C" = "${VPN_EVENT}" ]; then
	if [ -z "${VPN_ORIGINATING_IP}" ] || [ -z "${VPN_USER_ID}" ] || [ -z "${VPN_PROTO}" ]; then
		logger -t "$(basename "${0}" .sh)" "ERROR no VPN_ORIGINATING_IP, VPN_USER_ID or VPN_PROTO environment variables set" 
	else
		lookup=(mmdblookup -f /usr/local/bin/dbip-city-lite-2024-04.mmdb -i "${VPN_ORIGINATING_IP}") 
		mapfile -t COUNTRY < <("${lookup[@]}" country iso_code | cut -d '"' -f 2)
		mapfile -t CITY < <("${lookup[@]}" city names en | cut -d '"' -f 2)
		mapfile -t LATITUDE < <("${lookup[@]}" location latitude | cut -d '<' -f 1)
		mapfile -t LONGITUDE < <("${lookup[@]}" location longitude | cut -d '<' -f 1)
		if [ ! ${#CITY[@]} -eq 0 ] && [ ! ${#COUNTRY[@]} -eq 0 ] && [ ! ${#LATITUDE[@]} -eq 0 ]  && [ ! ${#LONGITUDE[@]} -eq 0 ]; then
			logger -t "$(basename "${0}" .sh)" "LOCATION ${VPN_USER_ID} ${VPN_PROTO}" "${CITY[@]}" "${LATITUDE[@]}" "${LONGITUDE[@]}" "${COUNTRY[@]}" 
		else
			logger -t "$(basename "${0}" .sh)" "ERROR no city or country found for given IP" 
		fi
	fi
else
	logger -t "$(basename "${0}" .sh)" "User ${VPN_USER_ID} disconnected"
fi

