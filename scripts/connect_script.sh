#!/bin/bash

if [ "C" = "${VPN_EVENT}" ]; then	
	OUTPUT=( $(convert_ip_to_geo "${VPN_ORIGINATING_IP}") )
	if [ ! ${#OUTPUT[@]} -eq 0 ]; then
		logger "LOCATION ${VPN_USER_ID} ${VPN_PROTO} ${OUTPUT[@]}"
	fi
else
	logger "User ${VPN_USER_ID} disconnected"
fi

