﻿# Log Analysis - README  

## Introduction 
VPNs, such as eduVPN, play a crucial role in ensuring secure connections, allowing users to access resources remotely. However, the security of VPNs is not without threats. This README documents a tool to detect the impossible travel principle for VPN service eduVPN. In the following sections the problem will be explained together with how the tool tries to mitigate the potential security risk eduVPN faces. 

### Problem Statement
The "impossible travel" principle poses a potential security risk for the security eduVPN. This principle refers to a scenario where a user establishes a VPN connection from two geographically distant locations within an improbably short timeframe. This situation could indicate unauthorized access or a compromised device being used to connect to the eduVPN service.

### Detection Approach
To address the security risk as described above, a log analysis tool in Python 3 has been developed. This tool is designed to analyze eduVPN log files and detect potential security incidents related to the "impossible travel" principle. The tool utilizes the eduVPN logs to identify geolocation information of a connected user. To achieve this it leverages the [MaxMind-DB-Reader](https://github.com/maxmind/MaxMind-DB-Reader-python) Python library together with the "IP to City Lite" database from [DB IP](https://db-ip.com/db/download/ip-to-city-lite) databases, to map the source IP address to geolocation information. As soon as we obtain the geolocation information when a user connects, we try to detect the impossible travel scenario. The chosen approach calculates the distance between two latitude and longitude coordinates from different login attempts of the same user. To do this we use [python3-geopy library](https://packages.debian.org/bookworm/python3-geopy) which uses the geodesic distance. In short, this metric calculates the shortest path between two points along the earth's surface. By using the time difference between two login attempts we can calculate the pace at which a user has travelled between different locations. A pace threshold of 1000km/h is set to check if the travelled distance between two login attempts has happened within a reasonable pace. If this threshold gets exceeded a flag is raised and an email notification is sent to the server.

A schematic overview can be found at the bottom of this document (04-2024: outdated).

**Note:** As of vpn-user-portal >= 3.6.1, Geo IP has officially been taken into production for OpenVPN connection. The MaxMind-DB-Reader library is only used for WireGuard connections, however at this point, the detection approach for WireGuard is disabled. This for the reason that it does not work and it is not the preferred way of finding `ORIGINATING_IP` for WireGuard connections.

#### OpenVPN vs. WireGuard
Since eduVPN is based on both OpenVPN and WireGuard the tool distinguishes between the two. 
For openVPN the tool utilizes the [eduVPN script connection hook](https://docs.eduvpn.org/server/v3/script-connection-hook.html) to map the source IP of a connected user directly to geolocation information. This is done instead of explicit OpenVPN logging to preserve user privacy. As of vpn-user-portal >= 3.6.1 the mapping of geolocation information happens server side and exposes the `VPN_GEO_IP_CC` and `VPN_GEO_URI` variables to the connection hook script. 

WireGuard does not have the functionality of logging/exposing the `ORIGINATING_IP` to the connection hooks. The reason for this is that with WireGuard there is no "VPN connect" as such. The server sets up the WireGuard config for the client and tears it down when it is removed or no longer needed/valid. For future work, to avoid polling, perhaps a "good enough" scenario is to determine the `ORIGINATING_IP` the moment the VPN configuration is added, i.e. through the VPN client API or portal download and use that (see [here](https://codeberg.org/eduVPN/vpn-user-portal/issues/7)).

In this tool we have found a workaround (which currently is not enabled, see previous section) for above demanding the use of the `wg show all` command to identify all active peers and their source IPs. The output of the command is written to a text file and converted to a dictionary. The journal logs are only used to map the public key of a connected user to the source IP in the dictionary created with `wg show all`. Afterwards, the text file is removed and hence no explicit logging is kept. Moreover, for WireGuard we use the MaxMind-DB-Reader python library to map the source IP of an activate WireGuard connection to geolocation information. 

The limitation of WireGuard here is that it is only possible to capture the source IPs of active connections. Hence, a WireGuard connection can still evade detection if it connects and disconnects before the script runs again. To minimize this risk, a cronjob for repeated execution of the script is setup to run every 5 minutes.


## Deployment steps 
1. Setup your eduVPN server, check out the [docs](https://docs.eduvpn.org/server/v3/).
2. Enable the [eduVPN script connection hook](https://docs.eduvpn.org/server/v3/script-connection-hook.html) for the `openvpn_connect_script.py` as explained in the docs.
3. Setup Geo IP following the guide [here](https://docs.eduvpn.org/server/v3/geo-ip.html).
4. Install the python3-geopy library. Debian and Ubuntu: `sudo apt-get install python3-geopy`. For Fedora: `sudo dnf install python3-geopy`. 
5. Fork this repository on to your eduVPN server.
6. Go inside the scripts folder and run the tool with `./run_impossible_travel.sh`

**Note:** As of vpn-user-portal >= 3.6.1 (2024-04-24) Geo IP has been taken into production and WireGuard connections cannot be captured (yet) and hence one does not have to install MaxMind-DB-Reader as mentioned in the detection approach.

## Implementation
The log analysis tool consists of two main components located in a folder together:
1. **Python script** (`impossible_travel.py`) - This script is responsible for processing log entries, extracting relevant information, and detecting potential security incidents based on the impossible travel principle.

2. **Bash shell script** (`run_impossible_travel.sh`) - This script automates the log analysis process. It captures relevant logs, prepares the environment, and executes the Python script. Additionally, it sets up a cronjob to run the analysis periodically.

The tool also uses one smaller component:

3. **Script Connection Hook** (`openvpn_connect_script.py`) - This script uses Python3 with to make use of the exposed environment variables to the script. It writes geolocation data to syslog to let the analysis tool process the data further. 

**Note:** Since vpn-user-portal >= 3.6.1 (2024-04-24), `openvpn_connect_script.py` should be used which makes use of the new Geo IP feature and before that the `connect_script.py` was used which converted IP to geolocation information client side. 

### Script Connection Hook: `openvpn_connect_script.py`

### Purpose
The purpose of this script is to not use explicit source IP address logging for OpenVPN to preserve user privacy. It makes use of the script connection hook of eduVPN which exposes environment variables to the script and logs geolocation information of a user connected via OpenVPN. Afterwards the masked output is written to syslog.

#### Tasks
1. **Check user connection**
    - If a user connects and the environment variables are set, we use the exposed environment variables to process geolocation information for the user. 
2. **Write masked output**
    - Afterwards the 'masked' output is written to syslog, from where it can be further processed by the rest of the tool. 

To make this work a few requirements are necessary which can be found in the requirements section. 

### Python script: `impossible_travel.py` 

#### Purpose
The `impossible_travel.py` script is designed to process journalctl JSON log entries, detect suspicious login activities, and report potential security incidents. It uses python3-geopy library to calculate the distance between two latitude and longitude coordinates as written by the script connection hook.
 
It used to leverage the MaxMind-DB-Reader to map IP addresses to geolocation for WireGuard configuration data, but now this part is disabled. 

#### Functions
1. `load_data(db_file_path)`
   - Loads the IP to City Lite databases from the specified file path using the MaxMind-DB-Reader library. This is still necessary to do source IP to geolocation conversion for WireGuard connections. 
2. `wireguard_data_to_dict(wireguard_peers)`
   - Parses the WireGuard configuration data from `wg show` to a text file and organises it into a dictionary for easy accessing. 
3. `parse_wireguard_protocol(...)`
   - Parses the journalctl log from WireGuard connections and maps the public key to a public key from an active connection to find the source IP of that connection
4. `detect_impossible_travel(...)`
   - Tries to detect the impossible travel principle by calculating the distance between two GPS coordinates of two different login attempts from two different locations. The time difference and this distance are used to calculate whether the user travelled between the different locations with a reasonable speed. We have put the threshold at a 1000km/h.  
5. `parse_log_entry(...)`
   - Extracts relevant information from a log entry and delegates parsing to specific protocols (WireGuard or OpenVPN).
6. `get_log_details(...)`
   - Processes a JSON log file, detects and reports potential security incidents, and returns the results as a dictionary.

**Note:** Functions 1-2-3 are currently not used since WireGuard functionality is not available.

#### Execution
    python3 impossible_travel.py <journal_json_log_file> <db_file> <wireguard_peers> <output_file>

- ```json_log_file```: Path to the journal JSON log file.
- ```db_file```: Path to the DB-IP IP to City Lite data file.
- ```wireguard_peers```: Path to the WireGuard peers configuration file.
- ```output_file```: Path to the output file for storing results in JSON format.

##### Example
    python3 impossible_travel.py journal-logs.json dbip-city-lite.mmdb wireguard_peers.txt output.json

### Bash shell script: `run_impossible_travel.sh`

#### Purpose
The `run_impossible_travel.sh` shell script manages the execution of the Python log analysis script. It prepares the environment, captures journalctl logs, and runs the analysis, ensuring a seamless flow of log processing. It also sets up a cronjob for repeated execution. 

#### Tasks
1. **Create log directory**
   - Ensures the existence of the log directory and creates it if necessary. This is directory is created in the parent folder of the scripts folder. 
2. **Capture journal logs**
   - Uses `journalctl` to capture logs related to the "vpn-user-portal" tag from the last hour, saving them to a JSON file.
3. **Capture WireGuard peers information**
   - Retrieves WireGuard peers information using `wg show all` and saves it to a text file. 
4. **Run Python script**
   - Executes the Python log analysis script with appropriate command-line arguments.
5. **Setup Cronjob**
   - Setup a cronjob for repeated execution to check for the impossible travel principle. 
6. **Create output files**
   - Create unique log output files which captures the connections.

#### Execution
    ./run_impossible_travel.sh

### Requirements
- The provided examples assume that the scripts and log files have the same parent directory. The file structure can be found in the images folder.

- To run the python script we use python. Specifically it was tested using python3.11.2.

- Currently only one python package need to be installed to run the tool. For Debian and Ubuntu: `sudo apt-get install python3-maxminddb python3-geopy`. For Fedora: `sudo dnf install python3-maxminddb python3-geopy`. Since WireGuard is currently disabled, one does not need to install `python3-maxminddb`. 

- According to the eduVPN documentation, to enable the script connection hook feature, a good location to put the `openvpn_connect_script.py` is in the `/usr/local/bin` folder. For now it only works if you put the database in the `/usr/local/share/DB-IP/` folder as specified in the [docs](https://docs.eduvpn.org/server/v3/geo-ip.html).

#### Schematic Overview
A high-level overview of the program structure can also be found in the images folder.
