# Safe Browsing DNSBL (Domain Name System-based blackhole list) Generator

## Overview

Create and/or update local [SQLite](https://www.sqlite.org) databases with URLs sourced from 
various public lists (e.g. Tranco TOP1M), and use the Google Safe Browsing API and Yandex Safe Browsing API 
to generate a malicious URL blocklist for [DNSBL](https://en.wikipedia.org/wiki/Domain_Name_System-based_blackhole_list) 
applications like [pfBlockerNG](https://linuxincluded.com/block-ads-malvertising-on-pfsense-using-pfblockerng-dnsbl) 
or [Pi-hole](https://pi-hole.net).

## URL sources

- Domains Project: https://domainsproject.org
- DomCop TOP10M : https://www.domcop.com/top-10-million-domains
- Tranco TOP1M : https://tranco-list.eu

## Requirements

- Linux or macOS
- Tested on Python 3.8.12
- x86-64 CPU; for Python Ray support
- Recommended: At least 8GB RAM
- Recommended: At least 5GB SSD free storage space; **at least 500GB SSD free storage space needed for downloading Domains Project URLs**
- [Obtain a Google Developer API key and set it up for the Safe Browsing API](https://developers.google.com/safe-browsing/v4/get-started)
- [Obtain a Yandex Developer API key](https://yandex.com/dev/safebrowsing)

## Setup instructions

`git clone` and `cd` into the project directory, then run the following

```bash
echo "GOOGLE_API_KEY=<your-google-api-key-here>" >> .env
echo "YANDEX_API_KEY=<your-yandex-api-key-here>" >> .env
pip3 install -r requirements.txt
```

## How to use

### Quick start (try this first)
```bash
# Download URLs from Tranco TOP1M and DomCop TOP10M, generate malicious URL blocklist using Google Safe Browsing API, and update local database
python3 main.py --fetch-urls --identify-malicious-urls --sources top1m top10m --providers google
```

### Some examples

```bash
# Download URLs from Tranco TOP1M and update local database
python3 main.py --fetch-urls --sources top1m
```

```bash
# Download URLs from Tranco TOP1M, generate malicious URL blocklist using Google Safe Browsing API, and update local database
python3 main.py --fetch-urls --identify-malicious-urls --sources top1m --providers google
```

```bash
# Download URLs from DomCop TOP10M, then generate malicious URL blocklist using both Google Safe Browsing API and Yandex Safe Browsing API, 
# and update local database
python3 main.py --fetch-urls --identify-malicious-urls --sources top10m --providers google
# or alternatively
python3 main.py --fetch-urls --identify-malicious-urls --sources top10m
```

```bash
# (Warning: need at least 500GB free space) Download URLs from Domains Project (domainsproject.org), 
# generate malicious URL blocklist using Google Safe Browsing API,
# and update local database
python3 main.py --fetch-urls --identify-malicious-urls --sources domainsproject --providers google
```

```bash
# (Warning: need at least 500GB free space) Download URLs from all sources, 
# generate malicious URL blocklist using Google Safe Browsing API and Yandex Safe Browsing API,
# and update local database
python3 main.py --fetch-urls --identify-malicious-urls --sources top1m top10m domainsproject --providers google yandex
# or alternatively
python3 main.py --fetch-urls --identify-malicious-urls
```

```bash
# From all existing URLs in local database, generate malicious URL blocklist using Yandex Safe Browsing API
python3 main.py --identify-malicious-urls --providers Yandex
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
- https://remusao.github.io/posts/few-tips-sqlite-perf.html
- https://domainsproject.org