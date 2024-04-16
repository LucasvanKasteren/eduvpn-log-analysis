#!/usr/bin/env python3

import os
import maxminddb
import syslog


def main():
    ev = os.getenv("VPN_EVENT")
    user_id = os.getenv("VPN_USER_ID")
    if ev != "C":
        syslog.syslog(syslog.LOG_INFO, f"User {user_id} disconnected")
        return
    orig_ip = os.getenv("VPN_ORIGINATING_IP")
    db = None
    with maxminddb.open_database(
        "/usr/local/bin/dbip-city-lite-2024-04.mmdb"
    ) as reader:
        db = reader.get(orig_ip)
    if not db:
        syslog.syslog(syslog.LOG_ERR, "db could not be opened")
        return
    try:
        country = db["country"]["iso_code"]
        city = db["city"]["names"]["en"]
        loc = db["location"]
        lat = loc["latitude"]
        lon = loc["longitude"]
        proto = os.getenv("VPN_PROTO")
        syslog.syslog(
            syslog.LOG_INFO, f"LOCATION {user_id} {proto} {city} {lat} {lon} {country}"
        )
    except Exception as e:
        syslog.syslog(syslog.LOG_ERR, f"failed retrieving info: {str(e)}")


if __name__ == "__main__":
    main()
