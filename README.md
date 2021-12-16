# Safe Browsing DNSBL (Domain Name System-based blackhole list) Generator

## Overview

Create and/or update a local [SQLite](https://www.sqlite.org) database with URLs sourced from various public lists (e.g. Tranco TOP1M), and use the Google Safe Browsing API and Yandex Safe Browsing API to generate a malicious URL blocklist for [DNSBL](https://en.wikipedia.org/wiki/Domain_Name_System-based_blackhole_list) applications like [pfBlockerNG](https://linuxincluded.com/block-ads-malvertising-on-pfsense-using-pfblockerng-dnsbl) or [Pi-hole](https://pi-hole.net).

Uses [Ray](http://www.ray.io) to make parallel requests with pipelining to the Safe Browsing APIs.

## URL sources

- DomCop TOP10M : https://www.domcop.com/top-10-million-domains
- Tranco TOP1M : https://tranco-list.eu

## Requirements

- Linux or macOS
- Tested on Python 3.8.12
- x86-64 CPU; for Python Ray support
- Recommended: At least 8GB RAM
- Recommended: At least 5GB storage space
- [Obtain a Google Developer API key and set it up for the Safe Browsing API](https://developers.google.com/safe-browsing/v4/get-started)
- [Obtain a Yandex Developer API key](https://yandex.com/dev/safebrowsing)

## Setup instructions

`git clone` and `cd` into the project directory, then run the following

```bash
echo "GOOGLE_API_KEY=<your-google-api-key-here>" >> .env
echo "YANDEX_API_KEY=<your-yandex-api-key-here>" >> .env
pip3 install -r requirements.txt
```

### Install [fping](https://fping.org)

```bash
# Debian/Ubuntu
sudo apt install fping
```

```bash
# CentOS/RHEL
sudo yum install fping
```

```bash
# Fedora/Rocky Linux/AlmaLinux
sudo dnf install fping
```

```bash
# Arch Linux/Manjaro/EndeavourOS
sudo pacman -S fping
```

```bash
# macOS
brew install fping
```

## How to use

```bash
# TESTING mode: Generate URLs_marked_malicious_by_Safe_Browsing.txt based on last 1500 URLs from Tranco TOP1M list
python3 main.py --mode testing
# FULL mode: Update local database with latest TOP1M+TOP10M URLs and generate URLs_marked_malicious_by_Safe_Browsing.txt from local database
python3 main.py --mode full
```

## Known Issues

- Yandex Safe Browsing API calls often fail with either ConnectionResetError or HTTP Status Code 204. Yandex Technical support has been notified. _Temporary workaround: Keep retrying API call until it succeeds_

## User Protection Notice

### Google

Google works to provide the most accurate and up-to-date information about unsafe web resources. However, Google cannot guarantee that its information is comprehensive and error-free: some risky sites may not be identified, and some safe sites may be identified in error.

## References

- https://developers.google.com/safe-browsing
- https://developers.google.com/safe-browsing/v4/usage-limits
- https://yandex.com/dev/safebrowsing/
- https://tranco-list.eu
- https://www.domcop.com/top-10-million-domains
