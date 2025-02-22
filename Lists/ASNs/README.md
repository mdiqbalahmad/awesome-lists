## Description
This project contains scripts to fetch and process data related to bad Autonomous System Numbers (ASNs) most used in phishing attacks or abused by attackers. The data is fetched from multiple sources . This folders includes scripts to automatically update the list of bad ASNs and retrieve their corresponding IP ranges.

## Scripts and Files
1. `fetch_cybercrimeinfocenter_phishing_asn_stats.py`
This script automatically fetches the latest list of bad ASNs most used in phishing attacks from www.cybercrimeinfocenter.org and saves the output in a file named `latest_bad_asn_phishing_list.csv`

- This script performs the following steps:
  - Fetches the main page that lists all the quarterly reports.
  - Parses the HTML to find the latest URL for the "bad ASN" report.
  - Fetches the data from the latest URL.
  - Extracts the table and saves it to a CSV file named latest_bad_asn_phishing_list.csv.

2. `latest_bad_asn_phishing_list.csv`
This file contains the latest top bad ASNs most used in phishing attacks, fetched from www.cybercrimeinfocenter.org. The file is updated by the `fetch_cybercrimeinfocenter_phishing_asn_stats.py` script.

3. `fetch_IP_ranges_of_bad_ASN.py`
This script fetches the updated IP ranges of each bad ASN listed in the consolidated list of ASNs and saves the IP ranges of each ASN in the current folder.
Reads the list of ASNs from:
- latest_bad_asn_phishing_list.csv (Cybercrime Info Center).
- bad_asn_static_list.csv (my static List of ASNs).
- evild3ad-ASN-BlackList.csv (VPN ASNs from https://github.com/evild3ad/Microsoft-Analyzer-Suite/blob/main/Blacklists/ASN-Blacklist.csv)
- spamhaus_asn_list.csv (Spamhaus ASN Drop List).

- This script performs the following steps:
  - Fetches the ASN lists from the sources above.
  - Combines all ASNs into a single deduplicated list.
  - Constructs a command to execute the [get_ip_range.py](https://github.com/mthcht/awesome-lists/blob/main/Lists/Ranges_IP_Address_Company_List/bgp.he.net/get_ip_range.py) script with the AS numbers as arguments.
  - Executes the command to fetch the IP ranges of the listed ASNs and saves the results in the current folder.
