import maxminddb
from os.path import exists
import sys
import os


def load_data(db_country_path, db_asn_path):
    if not exists(db_country_path) or not exists(db_asn_path):
        with open("/tmp/error.txt", "w") as fp:
            fp.write(f"Cannot find dataset(s) at {db_country_path} or {db_asn_path}\n")

    return maxminddb.open_database(db_country_path), maxminddb.open_database(
        db_asn_path
    )


def mask_ip(db_reader_country, db_reader_asn, source_ip):
    # Lookup geo location details given a source ip
    country_dict = db_reader_country.get(source_ip)
    country = country_dict["country"]["iso_code"]
    asn_dict = db_reader_asn.get(source_ip)
    asn = asn_dict["autonomous_system_organization"]
    return asn, country


if __name__ == "__main__":
    source_ip = sys.argv[1]
    geo_data_file_country = "/usr/local/bin/dbip-country-lite-2024-04.mmdb"
    geo_data_file_asn = "/usr/local/bin/dbip-asn-lite-2024-04.mmdb"
    # Load the geoip2fast dataset
    db_reader_country, db_reader_asn = load_data(
        geo_data_file_country, geo_data_file_asn
    )

    # Extract country and IP address from source ip
    asn, country = mask_ip(db_reader_country, db_reader_asn, source_ip)
    print(asn, country)
