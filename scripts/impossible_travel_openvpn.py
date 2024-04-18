import sys




def parse_log_entry(
    log_entry,
    unique_data,
    last_login_info,
):
    message = log_entry["MESSAGE"]
    userID = message.split()[1]
    timestamp_microseconds = int(log_entry["__REALTIME_TIMESTAMP"])
    timestamp_seconds = timestamp_microseconds / 1000000
    datetime_object = datetime.fromtimestamp(timestamp_seconds)
    try:
        split_message = message.split()

        


            if message.split()[0] == "LOCATION":
                city_name_list = message.split()[3:-3]
                city_name = " ".join(city_name_list)
                country_code = message.split()[-1]
                coordinates = (message.split()[-3], message.split()[-2])
                result = detect_impossible_travel(
                    userID,
                    city_name,
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




def get_log_details(json_path):
    if not exists(json_path):
        print("Cannot find given json\n", file=sys.stderr)
        sys.exit(1)

    unique_data = set()
    results_dict = defaultdict(list)
    last_login_info = defaultdict(list)

    with open(json_path, "r") as json_file:
        for line in json_file:
            log_dict = json.loads(line)
            result = parse_log_entry(
                log_dict,
                unique_data,
                last_login_info,
            )
            if result:
                userID, log_details = result
                results_dict[userID].append(log_details)

    return results_dict




if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(
            "Usage: python impossible_travel.py <journal_json_log_file> <output_file>\n",
            file=sys.stderr,
        )
        sys.exit(1)

    (
        journal_json_log_file,
        output_file,
    ) = sys.argv[1:6]

    results = get_log_details(journal_json_log_file)

    if results:
        with open(output_file, "w") as fp:
            json.dump(results, fp, indent=2)

        print("Written results to file\n")
    else:
        print("No login attempts happened in the last hour\n")

