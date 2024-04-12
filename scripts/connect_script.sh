#!/bin/bash

if [ "C" = "${VPN_EVENT}" ]; then
	if [ -z "${VPN_ORIGINATING_IP}" ] || [ -z "${VPN_USER_ID}" ] || [ -z "${VPN_PROTO}" ]; then
		logger -t "$(basename "${0}" .sh)" "ERROR no VPN_ORIGINATING_IP, VPN_USER_ID or VPN_PROTO environment variables set" 
	else
		mapfile -t ASN < <(mmdblookup -f /usr/local/bin/dbip-asn-lite-2024-04.mmdb -i "${VPN_ORIGINATING_IP}" autonomous_system_organization | cut -d '"' -f 2) 
		mapfile -t COUNTRY < <(mmdblookup -f /usr/local/bin/dbip-country-lite-2024-04.mmdb -i "${VPN_ORIGINATING_IP}" country iso_code | cut -d '"' -f 2)
		if [ ! ${#ASN[@]} -eq 0 ] && [ ! ${#COUNTRY[@]} -eq 0 ]; then
			logger -t "$(basename "${0}" .sh)" "LOCATION ${VPN_USER_ID} ${VPN_PROTO}" "${COUNTRY[@]}" "${ASN[@]}"
		else
			logger -t "$(basename "${0}" .sh)" "ERROR no asn or country found for given IP" 
		fi
	fi
else
	logger -t "$(basename "${0}" .sh)" "User ${VPN_USER_ID} disconnected"
fi

