# Google Safe Browsing DNSBL (Domain Name System-based blackhole list) Generator

## Overview

Python script to periodically update a local SQLite database with URLs sourced from various public lists (e.g. Tranco TOP1M), and use the Google Safe Browsing API to generate a malicious URL blocklist for [DNSBL](https://en.wikipedia.org/wiki/Domain_Name_System-based_blackhole_list) applications like [pfBlockerNG](https://linuxincluded.com/block-ads-malvertising-on-pfsense-using-pfblockerng-dnsbl) or [Pi-hole](https://pi-hole.net).

Uses [Ray](http://www.ray.io) to make parallel requests with pipelining to the Google Safe Browsing API.

## URL sources

- DomCop TOP10M : https://www.domcop.com/top-10-million-domains
- Tranco TOP1M : https://tranco-list.eu

## Requirements

- Tested on Python 3.8.6
- x86-64 CPU; for Python Ray support
- You will need to [obtain a Google Developer API key and set it up for the Safe Browsing API](https://developers.google.com/safe-browsing/v4/get-started)

## Setup instructions

`git clone` and `cd` into the project directory, then run the following

```bash
echo "API_KEY=<your-google-api-key-here>" >> .env
pip3 install requirements.txt
```

## How to use

```bash
# TESTING mode: Generate URLs_marked_malicious_by_Google.txt based on last 4000 URLs from Tranco TOP1M list
python3 main.py --mode testing
# FULL mode: Update local database with latest TOP1M+TOP10M URLs and generate URLs_marked_malicious_by_Google.txt from local database
python3 main.py --mode full
```

## User Protection Notice

Google works to provide the most accurate and up-to-date information about unsafe web resources. However, Google cannot guarantee that its information is comprehensive and error-free: some risky sites may not be identified, and some safe sites may be identified in error.

## References

- https://developers.google.com/safe-browsing
- https://developers.google.com/safe-browsing/v4/usage-limits
- https://tranco-list.eu
- https://www.domcop.com/top-10-million-domains
