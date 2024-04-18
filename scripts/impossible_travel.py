import json
from os.path import exists
import ipaddress
from datetime import datetime
import sys
import re
from collections import defaultdict
import maxminddb
from geopy.distance import geodesic as GD


def load_data(db_file_path):
    if not exists(db_file_path):  # or not exists(db_asn_path):
        print(
            f"Cannot find dataset(s) at {db_file_path}\n",  # or {db_asn_path}\n",
            file=sys.stderr,
        )
        sys.exit(1)

    return maxminddb.open_database(db_file_path)  # , maxminddb.open_database(
    #  db_city_path
    # )


def wireguard_data_to_dict(wireguard_peers):
    wireguard_data = defaultdict(list)
    current_interface = {}
    current_peer = {}
    with open(wireguard_peers, "r") as f:
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
    userID,
   # city,
    coordinates,
    country_code,
    unique_data,
    last_login_info,
    timestamp_seconds,
    datetime_object,
    protocol,
    travel_flag=False,
):
    if (userID, coordinates, country_code) not in unique_data:
        unique_data.add((userID, coordinates, country_code))

        if not last_login_info[
            userID
        ]:  # If the user has not been seen before log the data
            last_login_info[userID].append(
                {
                    "timestamp": str(datetime_object),
                    "protocol": protocol,
#                    "city": city,
                    "coordinates": coordinates,
                    "country_code": country_code,
                    "impossible_travel_flag": travel_flag,
                }
            )

            return userID, last_login_info[userID][-1]

        elif (  # Check if a user who previously logged in, has different coordinates
            last_login_info[userID][-1]["coordinates"] != coordinates
        ):
            last_timestamp_string = last_login_info[userID][-1]["timestamp"]
            last_timestamp = datetime.timestamp(
                datetime.strptime(last_timestamp_string, "%Y-%m-%d %H:%M:%S.%f")
            )
            time_difference = timestamp_seconds - last_timestamp
            old_coordinates = last_login_info[userID][-1]["coordinates"]
            # Calculate the distance between the old login and new login using the geodesic distance
            distance = GD(coordinates, old_coordinates).km
            # Convert time difference from seconds to hours
            speed = distance / (time_difference / 3600)
            max_speed = 3600

            if speed > max_speed:  # Travelled faster than 1000km/h
                travel_flag = True
                print(
                    f'Impossible travel flag set to {travel_flag} for user {userID} who traveled {distance} km at speed {speed} km/h for {time_difference/3600} hrs.\n Last login from {coordinates} in {country_code} at {datetime_object}.\n'
                )
            else:
                print(
                    f'Impossible travel flag set to {travel_flag} for user {userID} who traveled {distance} km at speed {speed} km/h for {time_difference/3600} hrs.\n User hopped location within a valid timespan with last login from {coordinates} in {country_code} at {datetime_object}.\n'
                )

        last_login_info[userID].append(
            {
                "timestamp": str(datetime_object),
                "protocol": protocol,
 #               "city": city,
                "coordinates": coordinates,
                "country_code": country_code,
                "impossible_travel_flag": travel_flag,
            }
        )

        return userID, last_login_info[userID][-1]

    return None


def parse_wireguard_protocol(
    message,
    wireguard_dict,
    userID,
    datetime_object,
    timestamp_seconds,
    unique_data,
    db_reader,
    last_login_info,
):
    userInfo = re.split(r"\(|:|\)", message.split()[2])
    profile_id = userInfo[1]
    public_key_peer_logs = userInfo[2]
    for peer in wireguard_dict["peers"]:
        public_key_connected = peer["peer"]
        source_ip = re.findall(r"[0-9]+(?:\.[0-9]+){3}", peer["endpoint"])[0]
        db_dict = db_reader.get(source_ip)
        country_code = db_dict["country"]["iso_code"]
 #       city = db_dict["city"]["names"]["en"]
        coordinates = (
            db_dict["location"]["latitude"],
            db_dict["location"]["longitude"],
        )
        # Map the public key of connected user to the one in the logs to check if the user is still connected
        if public_key_peer_logs == public_key_connected:
            result = detect_impossible_travel(
                userID,
  #              city,
                coordinates,
                country_code,
                unique_data,
                last_login_info,
                timestamp_seconds,
                datetime_object,
                "WireGuard",
            )
            return result
        else:
            print(
                f"User {userID} with public key {public_key_peer_logs} used WireGuard and is no longer connected.\n"
            )

    return None


def parse_log_entry(
    log_entry,
    db_reader,
    unique_data,
    last_login_info,
    wireguard_dict,
):
    message = log_entry["MESSAGE"]
    userID = message.split()[1]
    timestamp_microseconds = int(log_entry["__REALTIME_TIMESTAMP"])
    timestamp_seconds = timestamp_microseconds / 1000000
    datetime_object = datetime.fromtimestamp(timestamp_seconds)
    try:
        #protocol = message.find("*")
        #if protocol != -1:  # Do Wireguard parsing
       # if wireguard_dict["peers"]:
        #    result = parse_wireguard_protocol(
         #           message,
          #          wireguard_dict,
           #         userID,
            #        datetime_object,
             #       timestamp_seconds,
              #      unique_data,
               #     db_reader,
                #    last_login_info,
                #)
           # return result
        #else:
         #   print("No WireGuard peers currently connected.\n")

          # Do openVPN parsing
        if message.split()[0] == "LOCATION":
#            city_name_list = message.split()[3:-3]
 #           city_name = " ".join(city_name_list)
            country_code = message.split()[-1]
            coordinates = (message.split()[-3], message.split()[-2])
            result = detect_impossible_travel(
                    userID,
#                    city_name,
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

    except Exception as e:
        print(f"An error occurred while parsing: {e}\n", file=sys.stderr)

    return None


def get_log_details(json_path, db_reader, wireguard_peers):
    if not exists(json_path):
        print("Cannot find given json\n", file=sys.stderr)
        sys.exit(1)

    unique_data = set()
    results_dict = defaultdict(list)
    last_login_info = defaultdict(list)
    wireguard_dict = wireguard_data_to_dict(wireguard_peers)

    with open(json_path, "r") as json_file:
        for line in json_file:
            log_dict = json.loads(line)
            result = parse_log_entry(
                log_dict,
                db_reader,
                unique_data,
                last_login_info,
                wireguard_dict,
            )
            if result:
                userID, log_details = result
                results_dict[userID].append(log_details)

    return results_dict


if __name__ == "__main__":
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
    ) = sys.argv[1:6]

    db_reader = load_data(db_file)

    results = get_log_details(journal_json_log_file, db_reader, wireguard_peers)

    if results:
        with open(output_file, "w") as fp:
            json.dump(results, fp, indent=2)

        print("Written results to file\n")
    else:
        print("No login attempts happened in the last hour\n")
