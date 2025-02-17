# Fortigate Log Sentinel

Fortigate Log Sentinel is a Python-based log analysis tool designed for parsing and analyzing Fortigate firewall logs. It detects unusual login events by comparing source IP addresses and their geolocation information.

## Version

0.0.1

## Features

- **Unusual Login Check**: Identifies anomalous login events by comparing the source IP and its geolocation against a confirmed "normal" IP.
- **Geolocation Lookup**: Uses the GeoLite2-City database to retrieve detailed location information.
- **Interactive Interface**: Guides you through selecting the normal IP and displays anomalous events in a table format.

## Requirements

- Python 3.x
- [geoip2](https://pypi.org/project/geoip2/)
- [GeoLite2-City](https://dev.maxmind.com/geoip/geoip2/geolite2/) database file

## Usage

Clone this repository or download the `fls.py` file, then run the script from the command line:

python fls.py

Follow the interactive prompts to:

- Enter the path to your Fortigate log file.
- Specify the GeoLite2-City database file path (defaults to `GeoLite2-City.mmdb` if left blank).
- Provide your local UTC offset (e.g., `+9` or `-8`) for timestamp adjustment.

## Contributing

Contributions are welcome! Feel free to fork the repository and submit a pull request with your suggestions or improvements.

## License

MIT License

## Disclaimer

Fortigate Log Sentinel is provided "as is" without any warranties. Use it at your own risk.
