import json
from os.path import exists
import ipaddress
from datetime import datetime
from geoip2fast import GeoIP2Fast
import sys
import re
from collections import defaultdict


def load_data(geo_data_path):
    if not exists(geo_data_path):
        print(f"Cannot find the dataset at {geo_data_path}\n", file=sys.stderr)
        sys.exit(1)
    
    return GeoIP2Fast(geoip2fast_data_file=geo_data_path, verbose=False)        


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

    #Add the last peer to the json as well 
    if current_peer:
        wireguard_data["peers"].append(current_peer)

    return wireguard_data

def detect_impossible_travel(userID, asn_name, country_code, unique_data, last_login_info, timestamp_seconds, datetime_object, protocol, travel_flag=False):
    if (userID, asn_name, country_code) not in unique_data:
        unique_data.add((userID, asn_name, country_code))

        if not last_login_info[userID]: #If the user has not been seen before log the data
            last_login_info[userID].append({"timestamp" : str(datetime_object),
                                        "protocol" : protocol,
                                        "asn_name" : asn_name,
                                        "country_code" : country_code,
                                        "impossible_travel_flag" : travel_flag})

            return userID, last_login_info[userID][-1]

        elif last_login_info[userID][-1]["asn_name"] != asn_name: #and last_login_info[userID][-1]["country_code"] != country_code:
            #Detect if a user who previously connected has committed impossible travel
            last_timestamp_string = last_login_info[userID][-1]["timestamp"]
            last_timestamp = datetime.timestamp(datetime.strptime(last_timestamp_string, '%Y-%m-%d %H:%M:%S.%f'))
            time_difference = timestamp_seconds - last_timestamp
            if time_difference < 1800:
                travel_flag = True
                print(f"Impossible travel flag set to {travel_flag} for user {userID}. Last login from geo location {asn_name} in country {country_code} at {datetime_object}.\n")
            else:
                print(f"Impossible travel flag set to {travel_flag} for user {userID}. User hopped location within a valid timespan.\n")
        

        last_login_info[userID].append({"timestamp" : str(datetime_object),
                                    "protocol" : protocol,
                                    "asn_name" : asn_name,
                                    "country_code" : country_code,
                                    "impossible_travel_flag" : travel_flag})

        return userID, last_login_info[userID][-1]
    
   # else:
    #    print(f"User {userID} connected with {protocol} has already been seen at {asn_name} in country {country_code}.\n", file=sys.stderr)
    
    return None

def parse_wireguard_protocol(message, wireguard_dict, userID, datetime_object, timestamp_seconds, unique_data, geoIP, last_login_info):
    userInfo = re.split(r"\(|:|\)", message.split()[2])
    profile_id = userInfo[1]
    public_key_peer_logs = userInfo[2]
    for peer in wireguard_dict["peers"]:
        public_key_connected = peer["peer"]
        source_ip = re.findall(r'[0-9]+(?:\.[0-9]+){3}', peer["endpoint"])[0]
        geo_data = geoIP.lookup(source_ip)
        asn_name = geo_data.asn_name
        country_code = geo_data.country_code
        #Map the public key of connected user to the one in the logs to check if the user is still connected
        if public_key_peer_logs == public_key_connected:
            result = detect_impossible_travel(userID, asn_name, country_code, unique_data, last_login_info, timestamp_seconds, datetime_object, "WireGuard")
            return result
        else:
            print(f"User {userID} with public key {public_key_peer_logs} used WireGuard and is no longer connected.\n")

    return None


def parse_log_entry(log_entry, geoIP, unique_data, last_login_info, wireguard_dict):
    message = log_entry["MESSAGE"]
    userID = message.split()[1]
    timestamp_microseconds = int(log_entry["__REALTIME_TIMESTAMP"])  
    timestamp_seconds = timestamp_microseconds / 1000000
    datetime_object = datetime.fromtimestamp(timestamp_seconds)
    try:
        protocol = message.find("*")
        if protocol != -1: #Do Wireguard parsing
            if wireguard_dict["peers"]:
                result = parse_wireguard_protocol(message, wireguard_dict, userID, datetime_object, timestamp_seconds, unique_data, geoIP, last_login_info) 
                return result
            else:
                print("No WireGuard peers currently connected.\n")

        else: #Do openVPN parsing
            if message.split()[0] == "LOCATION":
                asn_name_list = message.split()[3:-1]
                asn_name = " ".join(asn_name_list)
                country_code = message.split()[-1]
                result = detect_impossible_travel(userID, asn_name, country_code, unique_data, last_login_info, timestamp_seconds, datetime_object, "openVPN")
                return result
            #else:
             #   print("No unique source IP for protocol openVPN in next logs\n")
        
    except Exception as e:
        print(f"An error occurred while parsing: {e}\n", file=sys.stderr)
    
    return None


def get_log_details(json_path, geoIP, wireguard_peers):
    if not exists(json_path):
        print("Cannot find given json\n", file=sys.stderr)
        sys.exit(1)

    unique_data = set()
    results_dict = defaultdict(list)
    last_login_info = defaultdict(list)
    wireguard_dict = wireguard_data_to_dict(wireguard_peers)

    with open(json_path, 'r') as json_file:
        for line in json_file:
            log_dict = json.loads(line)
            result = parse_log_entry(log_dict, geoIP, unique_data, last_login_info, wireguard_dict)
            if result:
                userID, log_details = result
                results_dict[userID].append(log_details)

    return results_dict


if __name__ == '__main__':
    if len(sys.argv) != 5:
        print("Usage: python impossible_travel.py <journal_json_log_file> <geo_data_file> <wireguard_peers> <output_file>\n", file=sys.stderr)
        sys.exit(1)

    journal_json_log_file, geo_data_file, wireguard_peers, output_file = sys.argv[1:5]

    geoIP = load_data(geo_data_file)

    results = get_log_details(journal_json_log_file, geoIP, wireguard_peers)

    if results:
        with open(output_file, "w") as fp:
            json.dump(results, fp, indent=2)

        print("Written results to file\n")
    else:
        print("No login attempts happened in the last hour\n")
