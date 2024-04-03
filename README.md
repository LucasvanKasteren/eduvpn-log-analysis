# Log Analysis - README  

## Introduction 
VPNs, such as eduVPN, play a crucial role in ensuring secure connections, allowing users to access resources remotely. However, the security of VPNs is not without threats. This README documents a tool to detect the impossible travel principle for VPN service eduVPN. In the following sections the problem will be explained together with how the tool tries to mitigate the potential security risk eduVPN faces. 

### Problem Statement
The "impossible travel" principle poses a potential security risk for the security eduVPN. This principle refers to a scenario where a user establishes a VPN connection from two geographically distant locations within an improbably short timeframe. This situation could indicate unauthorized access or a compromised device being used to connect to the eduVPN service. 

### Detection Approach
To address the security risk as described above, a log analysis tool in Python 3 has been developed. This tool is designed to analyze eduVPN log files and detect potential security incidents related to the "impossible travel" principle. The tool utilizes the eduVPN logs to identify geolocation information of a connected user. To achieve this, it leverages the GeoIP2Fast library to map the source IP address to geolocation information and enhance analysis capabilities. A schematic overview can be found at the bottom of this document.

#### OpenVPN vs. WireGuard
Since eduVPN is based on both OpenVPN and WireGuard the tool distinguishes between the two. 
For openVPN the tool utilizes the [eduVPN script connection hook](https://docs.eduvpn.org/server/v3/script-connection-hook.html) to map the source IP of a connected user directly to geolocation information. This is done instead of explicit OpenVPN logging to preserve user privacy. 

WireGuard does not have the functionality of using the script connection hook, demanding the use of the `wg show all` command to identify all active peers and their source IPs. The output of the command is written to a text file and converted to a dictionary. The journal logs are only used to map the public key of a connected user to the source IP in the dictionary created with `wg show all`. Afterwards, the text file is removed and hence no explicit logging is kept. 

The limitation of WireGuard here is that it is only possible to capture the source IPs of active connections. Hence, a WireGuard connection can still evade detection if it connects and disconnects before the script runs again. To minimize this risk, a cronjob for repeated execution of the script is setup to run every 5 minutes. 

## Implementation
The log analysis tool consists of two main components located in a folder together:
1. **Python script** (`impossible_travel.py`) - This script is responsible for processing log entries, extracting relevant information, and detecting potential security incidents based on the impossible travel principle.

2. **Bash shell script** (`run_impossible_travel.sh`) - This script automates the log analysis process. It captures relevant logs, prepares the environment, and executes the Python script. Additionally, it sets up a cronjob to run the analysis periodically.

The tool also uses one smaller component:

3. **Script Connection Hook** (`connect_script.sh`) - This small script executes a python executable, which converts the source IP address for OpenVPN and returns the user, its asn name and country code to syslog. 

### Script Connection Hook: `connect_script.sh`

### Purpose
The purpose of this script is to not use explicit source IP address logging for OpenVPN to preserve user privacy. It makes use of the script connection hook of eduVPN which executes and converts the source IP address to geolocation information of a user connected via OpenVPN. Afterwards the masked output is written to syslog.

#### Tasks
1. **Check user connection**
    - If a user connects, the python script `convert_ip_to_geo.py` Python script is executed to transform the user's source IP address to geolocation information. To perfom this 'masking' it makes use of the GeoIP2Fast library. 
2. **Write masked output**
    - Afterwards the 'masked' output is written to syslog, from where it can be further processed by the rest of the tool. 

To make this work a few requirements are necessary which can be found in the requirements section. 

### Python script: `impossible_travel.py` 

#### Purpose
The `impossible_travel.py` script is designed to process journalctl JSON log entries, detect suspicious login activities, and report potential security incidents. It leverages the GeoIP2Fast library to map IP addresses to geolocation and parses OpenVPN and WireGuard configuration data for enhanced analysis.

#### Functions
1. `load_data(geo_data_path)`
   - Loads GeoIP data from the specified file path using the GeoIP2Fast library. This is still necessary to do source IP to geolocation conversion for WireGuard connections. 
2. `wireguard_data_to_dict(wireguard_peers)`
   - Parses the WireGuard configuration data from `wg show` to a text file and organises it into a dictionary for easy accessing. 
3. `parse_wireguard_protocol(...)`
   - Parses the journalctl log from WireGuard connections and maps the public key to a public key from an active connection to find the source IP of that connection
4. `detect_impossible_travel(...)`
   - Tries to detect the impossible travel principle by comparing timestamps if a user's asn and country changed within a certain timeframe. 
5. `parse_log_entry(...)`
   - Extracts relevant information from a log entry and delegates parsing to specific protocols (WireGuard or OpenVPN).
6. `get_log_details(...)`
   - Processes a JSON log file, detects and reports potential security incidents, and returns the results as a dictionary.

#### Execution
    python3 impossible_travel.py <journal_json_log_file> <geo_data_file> <wireguard_peers> <output_file>

- ```json_log_file```: Path to the journal JSON log file.
- ```geo_data_file```: Path to the GeoIP data file.
- ```wireguard_peers```: Path to the WireGuard peers configuration file.
- ```output_file```: Path to the output file for storing results in JSON format.

##### Example
    python3 impossible_travel.py journal-logs.json geoip2fast-asn-ipv6.dat.gz wireguard_peers.txt output.json

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
   - Create unique log output files which captures the connections

#### Execution
    ./run_impossible_travel.sh

### Requirements
- The provided examples assume that the scripts and log files have the same parent directory. The file structure can be found in the images folder.

- To run the python script we use a virtual environment. This can be created with `python3 -m venv /path/to/new/virtual/environment`. The shell script then takes care of activating this virtual environment. The only non-standard library in the virtual environment is the GeoIP2Fast library which can be added with `pip install geoip2fast`. 

- According to the eduVPN documentation, to enable the script connection hook feature, a good location to put the `connect_script.sh` is in the `/usr/local/bin` folder. Additionally, the GeoIP2Fast database must also be present in this folder. Finally, the `convert_ip_to_geo.py` file needs to be converted to an executable which can accomplished by using [Python's pyinstaller library](https://pyinstaller.org/en/v4.8/usage.html). Convert this file inside the virtual environment to incorporate all necessary imports.  When converted, relocated it to the /usr/local/bin folder alongside the other files. You can also move the .exe file which can be found in the data folder to your /usr/local/bin folder.

#### Schematic Overview
A high-level overview of the program structure can also be found in the images folder.
