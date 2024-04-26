"""Module providing functions to detect the impossible travel principle in python."""

import json
from os.path import exists
from datetime import datetime
import sys
import re
from collections import defaultdict

# import maxminddb
from geopy.distance import geodesic as GD


def load_data(db_file_path):
    """Load MaxMind database from the given file path."""
    if not exists(db_file_path):
        print(
            f"Cannot find dataset(s) at {db_file_path}\n",
            file=sys.stderr,
        )
        sys.exit(1)

    return maxminddb.open_database(db_file_path)


def wireguard_data_to_dict(wireguard_peers):
    """Convert WireGuard peers data from a text file to a dictionary format."""
    wireguard_data = defaultdict(list)
    current_interface = {}
    current_peer = {}
    with open(wireguard_peers, "r", encoding="utf-8") as f:
        content = f.read()
        splitcontent = content.splitlines()
        for line in splitcontent:
            if line != "":
                key, value = map(str.strip, line.split(":", maxsplit=1))
                if key == "interface":
                    wireguard_data[key] = value
                elif key in ["public key", "private key", "listening port"]:
                    current_interface[key] = value
                else:
                    current_peer[key] = value
            else:
                if current_interface:
                    wireguard_data["details"].append(current_interface)
                    current_interface = {}
                elif current_peer:
                    wireguard_data["peers"].append(current_peer)
                    current_peer = {}
                else:
                    print("Empty line found in text file\n", file=sys.stderr)

    # Add the last peer to the json as well
    if current_peer:
        wireguard_data["peers"].append(current_peer)

    return wireguard_data


def detect_impossible_travel(
    user_id,
    coordinates,
    country_code,
    unique_data,
    last_login_info,
    timestamp_seconds,
    datetime_object,
    protocol,
    travel_flag=False,
):
    """Detect impossible travel based on user's login information."""
    if (user_id, coordinates, country_code) not in unique_data:
        unique_data.add((user_id, coordinates, country_code))

        if not last_login_info[
            user_id
        ]:  # If the user has not been seen before log the data
            last_login_info[user_id].append(
                {
                    "timestamp": str(datetime_object),
                    "protocol": protocol,
                    "coordinates": coordinates,
                    "country_code": country_code,
                    "impossible_travel_flag": travel_flag,
                }
            )

            return user_id, last_login_info[user_id][-1]

        if (  # Check if a user who previously logged in, has different coordinates
            last_login_info[user_id][-1]["coordinates"] != coordinates
        ):
            last_timestamp_string = last_login_info[user_id][-1]["timestamp"]
            last_timestamp = datetime.timestamp(
                datetime.strptime(last_timestamp_string, "%Y-%m-%d %H:%M:%S.%f")
            )
            time_difference = timestamp_seconds - last_timestamp
            old_coordinates = last_login_info[user_id][-1]["coordinates"]
            # Calculate the distance between the old login and new login using the geodesic distance
            distance = GD(coordinates, old_coordinates).km
            # Convert time difference from seconds to hours
            speed = distance / (time_difference / 3600)
            max_speed = 3600

            if speed > max_speed:  # Travelled faster than 1000km/h
                travel_flag = True
                print(
                    f"Impossible travel flag set to {travel_flag} for user {user_id} who traveled {distance} km at speed {speed} km/h for {time_difference/3600} hrs.\n Last login from {coordinates} in {country_code} at {datetime_object}.\n"
                )
            else:
                print(
                    f"Impossible travel flag set to {travel_flag} for user {user_id} who traveled {distance} km at speed {speed} km/h for {time_difference/3600} hrs.\n User hopped location within a valid timespan with last login from {coordinates} in {country_code} at {datetime_object}.\n"
                )

        last_login_info[user_id].append(
            {
                "timestamp": str(datetime_object),
                "protocol": protocol,
                "coordinates": coordinates,
                "country_code": country_code,
                "impossible_travel_flag": travel_flag,
            }
        )

        return user_id, last_login_info[user_id][-1]

    return None


def parse_wireguard_protocol(
    message,
    wireguard_dict,
    user_id,
    datetime_object,
    timestamp_seconds,
    unique_data,
    db_reader,
    last_login_info,
):
    """Parse WireGuard protocol log messages and call impossible travel on it."""
    user_info = re.split(r"\(|:|\)", message.split()[2])
    public_key_peer_logs = user_info[2]
    for peer in wireguard_dict["peers"]:
        public_key_connected = peer["peer"]
        source_ip = re.findall(r"[0-9]+(?:\.[0-9]+){3}", peer["endpoint"])[0]
        db_dict = db_reader.get(source_ip)
        country_code = db_dict["country"]["iso_code"]
        coordinates = (
            db_dict["location"]["latitude"],
            db_dict["location"]["longitude"],
        )
        # Map the public key of connected user to the one in the logs to check if the user is still connected
        if public_key_peer_logs == public_key_connected:
            result = detect_impossible_travel(
                user_id,
                coordinates,
                country_code,
                unique_data,
                last_login_info,
                timestamp_seconds,
                datetime_object,
                "WireGuard",
            )
            return result
        print(
            f"User {user_id} with public key {public_key_peer_logs} used WireGuard and is no longer connected.\n"
        )

    return None


def parse_log_entry(
    log_entry,
    db_reader,
    unique_data,
    last_login_info,
    wireguard_dict,
):
    """Parse log entries for both openvpn and wireguard connections"""
    message = log_entry["MESSAGE"]
    user_id = message.split()[1]
    timestamp_microseconds = int(log_entry["__REALTIME_TIMESTAMP"])
    timestamp_seconds = timestamp_microseconds / 1000000
    datetime_object = datetime.fromtimestamp(timestamp_seconds)
    try:
        # protocol = message.find("*")
        # if protocol != -1:  # Do Wireguard parsing
        # if wireguard_dict["peers"]:
        #    result = parse_wireguard_protocol(
        #           message,
        #          wireguard_dict,
        #         user_id,
        #        datetime_object,
        #       timestamp_seconds,
        #      unique_data,
        #     db_reader,
        #    last_login_info,
        # )
        # return result
        # else:
        #   print("No WireGuard peers currently connected.\n")

        # Do openVPN parsing
        if message.split()[0] == "LOCATION":
            country_code = message.split()[-1]
            coordinates = (message.split()[-3], message.split()[-2])
            result = detect_impossible_travel(
                user_id,
                coordinates,
                country_code,
                unique_data,
                last_login_info,
                timestamp_seconds,
                datetime_object,
                "openVPN",
            )
            return result
            # else:
            #   print("No unique source IP for protocol openVPN in next logs\n")

    except ValueError as e:
        print(f"An error occurred while parsing: {e}\n", file=sys.stderr)

    return None


def get_log_details(json_path, db_reader_object, wireguard_peers_file):
    """Get connection details from JSON journal log file and write results to dictionary."""
    if not exists(json_path):
        print("Cannot find given json\n", file=sys.stderr)
        sys.exit(1)

    unique_data = set()
    results_dict = defaultdict(list)
    last_login_info = defaultdict(list)
    wireguard_dict = wireguard_data_to_dict(wireguard_peers_file)

    with open(json_path, "r", encoding="utf-8") as json_file:
        for line in json_file:
            log_dict = json.loads(line)
            result = parse_log_entry(
                log_dict,
                db_reader_object,
                unique_data,
                last_login_info,
                wireguard_dict,
            )
            if result:
                user_id, log_details = result
                results_dict[user_id].append(log_details)

    return results_dict


def main():
    """Main entry point of the script."""
    if len(sys.argv) != 5:
        print(
            "Usage: python impossible_travel.py <journal_json_log_file> <db_file> <wireguard_peers> <output_file>\n",
            file=sys.stderr,
        )
        sys.exit(1)

    (
        journal_json_log_file,
        db_file,
        wireguard_peers,
        output_file,
    ) = sys.argv[1:5]

    # db_reader = load_data(db_file)
    db_reader = ""
    results = get_log_details(journal_json_log_file, db_reader, wireguard_peers)

    if results:
        with open(output_file, "w", encoding="utf-8") as fp:
            json.dump(results, fp, indent=2)

        print("Written results to file\n")
    else:
        print("No login attempts happened in the last hour\n")


if __name__ == "__main__":
    main()
