from geoip2fast import GeoIP2Fast
from os.path import exists
import sys
import os


def load_data(geo_data_path):
    if not exists(geo_data_path):
        with open("/tmp/error.txt", "w") as fp:
            fp.write(f"Cannot find the dataset at {geo_data_path}\n")

    return GeoIP2Fast(geoip2fast_data_file=geo_data_path, verbose=False)


def mask_ip(geoIP, source_ip):
    # Lookup geo location details given a source ip
    result = geoIP.lookup(source_ip)
    asn = result.asn_name
    country = result.country_code
    return asn, country


if __name__ == "__main__":
    source_ip = sys.argv[1]
    geo_data_path = "/usr/local/bin/geoip2fast-asn-ipv6.dat.gz"
    # Load the geoip2fast dataset
    geoIP = load_data(geo_data_path)

    # Extract country and IP address from source ip
    asn, country = mask_ip(geoIP, source_ip)
    print(asn, country)
