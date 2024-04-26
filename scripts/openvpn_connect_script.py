#!/usr/bin/env python3
"""Module providing a function for logging geolocation for users connected via openvpn."""

import os
import syslog


def main():
    """Main function for retrieving environment variables and logging user activity."""
    ev = os.getenv("VPN_EVENT")
    user_id = os.getenv("VPN_USER_ID")
    if ev != "C":
        syslog.syslog(syslog.LOG_INFO, f"User {user_id} disconnected")
        return
    orig_ip = os.getenv("VPN_ORIGINATING_IP")
    if not orig_ip:
        return

    try:
        country = os.getenv("VPN_GEO_IP_CC")
        geo = os.getenv("VPN_GEO_IP_URI").split(":")[1]
        lat = geo.split(",")[0]
        lon = geo.split(",")[1]
        proto = os.getenv("VPN_PROTO")
        syslog.syslog(
            syslog.LOG_INFO, f"LOCATION {user_id} {proto} {lat} {lon} {country}"
        )
    except ValueError as e:
        syslog.syslog(syslog.LOG_ERR, f"Failed retrieving info: {str(e)}")


if __name__ == "__main__":
    main()
