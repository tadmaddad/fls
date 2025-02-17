import re
import sys
import geoip2.database
from datetime import datetime, timedelta, timezone

def display_menu(first_time=True):
    if first_time:
        print("""
###############################################
#           Fortigate Log Sentinel            #
#                 Version: 0.0.1              #
###############################################
        """)
    print("Select the function:\n0. Exit\n1. Unusual Login\n")

# Extract the srcip from a log line using regex
def extract_srcip(log_line):
    match = re.search(r'srcip=([\d\.]+)', log_line)
    return match.group(1) if match else None

# Adjust the timestamp from the log based on the user’s local timezone.
# The log is assumed to have an ISO format timestamp as the first token.
def adjust_timestamp(log_line, local_tz):
    tokens = log_line.split()
    if not tokens:
        return "Unknown"
    timestamp_str = tokens[0]
    try:
        dt = datetime.fromisoformat(timestamp_str)
        dt_local = dt.astimezone(local_tz)
        return dt_local.strftime("%Y-%m-%d %H:%M:%S")
    except Exception as e:
        return "Unknown"

# Retrieve location information (country, subdivision, city) for an IP using GeoLite2
def get_location(ip, reader):
    try:
        response = reader.city(ip)
        country = response.country.name or "Unknown"
        subdivision = response.subdivisions.most_specific.name or "Unknown"
        city = response.city.name or "Unknown"
        return (country, subdivision, city)
    except Exception as e:
        print(f"GeoIP lookup error for IP {ip}: {e}", file=sys.stderr)
        return None

# Gather candidate normal IPs from the logs and store the first seen location for each.
def gather_normal_candidates(log_lines, reader):
    candidate_ips = {}  # {srcip: location}
    logs = []           # List of tuples: (line, srcip, location)
    for line in log_lines:
        src_ip = extract_srcip(line)
        if not src_ip:
            continue
        location = get_location(src_ip, reader)
        if not location:
            continue
        logs.append((line, src_ip, location))
        # Record the first occurrence as the candidate normal location
        if src_ip not in candidate_ips:
            candidate_ips[src_ip] = location
    return candidate_ips, logs

# Prompt the user to select the normal IP candidate using a numbered list.
def confirm_normal_ip(candidate_ips):
    if not candidate_ips:
        print("No candidate normal IPs detected.")
        sys.exit(1)
    candidate_list = list(candidate_ips.items())
    print("Detected candidate normal IPs:")
    for idx, (ip, loc) in enumerate(candidate_list, start=1):
        print(f"{idx}. IP: {ip} with location: {loc}")
    while True:
        try:
            selection = int(input("Please select the number corresponding to the IP to be treated as normal: ").strip())
            if 1 <= selection <= len(candidate_list):
                chosen_ip, chosen_loc = candidate_list[selection - 1]
                return chosen_ip, chosen_loc
            else:
                print(f"Invalid selection. Please enter a number between 1 and {len(candidate_list)}.")
        except ValueError:
            print("Invalid input. Please enter a valid number.")

# Perform unusual login check by comparing all log entries against the confirmed normal IP and location,
# then print anomalous entries in a table format (Date, IP, Location).
def unusual_login_check(log_file_path, db_path, local_tz):
    try:
        with open(log_file_path, 'r', encoding='utf-8') as f:
            log_lines = [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"Error reading log file: {e}", file=sys.stderr)
        sys.exit(1)

    reader = geoip2.database.Reader(db_path)
    candidate_ips, logs = gather_normal_candidates(log_lines, reader)
    normal_ip, normal_location = confirm_normal_ip(candidate_ips)
    if normal_location is None:
        normal_location = get_location(normal_ip, reader)
        if not normal_location:
            print(f"Failed to retrieve location for the provided IP {normal_ip}. Exiting.")
            reader.close()
            sys.exit(1)
    print(f"\nProceeding with normal IP: {normal_ip} (Location: {normal_location})\n")

    anomalies = []
    # Flag a log as anomalous if:
    # - The srcip is not the confirmed normal IP, OR
    # - The srcip is the same but the location differs.
    for line, src_ip, location in logs:
        if src_ip != normal_ip or (src_ip == normal_ip and location != normal_location):
            anomalies.append((line, src_ip, location))
    reader.close()

    if anomalies:
        print("Unusual Login check detected anomalous login events:\n")
        header = "{:<30} {:<15} {:<40}".format("Date", "IP", "Location")
        print(header)
        print("-" * len(header))
        for line, ip, current_loc in anomalies:
            adj_timestamp = adjust_timestamp(line, local_tz)
            loc_str = ", ".join(current_loc)
            print("{:<30} {:<15} {:<40}".format(adj_timestamp, ip, loc_str))
    else:
        print("No anomalous login events detected.")

def main():
    first_time = True
    while True:
        display_menu(first_time)
        first_time = False
        choice = input("Enter your choice: ").strip()
        if choice == "0":
            print("Exiting.")
            sys.exit(0)
        elif choice == "1":
            log_file_path = input("Enter the log file path: ").strip()
            db_path = input("Enter the GeoLite2-City database path [default: GeoLite2-City.mmdb]: ").strip()
            if not db_path:
                db_path = "GeoLite2-City.mmdb"
            # Prompt for UTC offset and create a timezone object
            offset_input = input("Enter your local UTC offset in hours (e.g. +9 or -8): ").strip()
            try:
                offset_hours = float(offset_input)
            except ValueError:
                print("Invalid UTC offset. Defaulting to 0.")
                offset_hours = 0
            local_tz = timezone(timedelta(hours=offset_hours))
            unusual_login_check(log_file_path, db_path, local_tz)
        else:
            print("Invalid option. Please try again.")

if __name__ == '__main__':
    main()
