<div align="center">
    <h1>Safe Browsing DNSBL (Domain Name System-based blackhole list) Generator</h1>
</div>

Create and/or update local [SQLite](https://www.sqlite.org) databases with URLs sourced from 
various public lists (i.e. Tranco TOP1M, DomCop TOP10M, and Domains Project), and use the Safe Browsing API from Google and/or Yandex 
to generate a malicious URL blocklist for [DNSBL](https://en.wikipedia.org/wiki/Domain_Name_System-based_blackhole_list) 
applications like [pfBlockerNG](https://linuxincluded.com/block-ads-malvertising-on-pfsense-using-pfblockerng-dnsbl) 
or [Pi-hole](https://pi-hole.net).

## URL sources

- Tranco TOP1M (~1 million URLs): https://tranco-list.eu
- DomCop TOP10M (~10 million URLs): https://www.domcop.com/top-10-million-domains
- Domains Project (~1.7 billion URLs): https://domainsproject.org

## Requirements

- Linux or macOS
- Tested on Python 3.8.12
- Multi-core x86-64 CPU; for Python Ray support
- Recommended: At least 8GB RAM
- Recommended: At least 5GB SSD free storage space; **at least 500GB SSD free storage space needed for processing Domains Project URLs**
- [Obtain a Google Developer API key and set it up for the Safe Browsing API](https://developers.google.com/safe-browsing/v4/get-started)
- [Obtain a Yandex Developer API key](https://yandex.com/dev/safebrowsing)

## Setup instructions

`git clone` and `cd` into the project directory, then run the following

```bash
echo "GOOGLE_API_KEY=<your-google-api-key-here>" >> .env
echo "YANDEX_API_KEY=<your-yandex-api-key-here>" >> .env
pip3 install -r requirements.txt

# Optional (dataset size ~49Gb): Download Domains Project URLs (https://domainsproject.org)
cd ../
git clone https://github.com/tb0hdan/domains.git
cd domains
git lfs install # you will need to install Git LFS first (https://git-lfs.github.com)
./unpack.sh
```

## Usage

### Quick start (try this first)
\
Download URLs from Tranco TOP1M and DomCop TOP10M, generate malicious URL blocklist using Google Safe Browsing API, and update local database
```bash
python3 main.py --fetch-urls --identify-malicious-urls --sources top1m top10m --vendors google
```
---
### Some other examples
\
Download URLs from Tranco TOP1M and update local database (no blocklist generated)
```bash
python3 main.py --fetch-urls --sources top1m
```
\
Download URLs from Tranco TOP1M, generate malicious URL blocklist using Google Safe Browsing API, and update local database
```bash
python3 main.py --fetch-urls --identify-malicious-urls --sources top1m --vendors google
```
\
Download URLs from DomCop TOP10M, then generate malicious URL blocklist using both Google Safe Browsing API and Yandex Safe Browsing API, and update local database
```bash
python3 main.py --fetch-urls --identify-malicious-urls --sources top10m --vendors google
# or alternatively
python3 main.py --fetch-urls --identify-malicious-urls --sources top10m
```
\
**(Warning: this needs at least 500GB free space)** Download URLs from Domains Project (domainsproject.org), generate malicious URL blocklist using Google Safe Browsing API, and update local database
```bash
python3 main.py --fetch-urls --identify-malicious-urls --sources domainsproject --vendors google
```
\
**(Warning: this needs at least 500GB free space)** Download URLs from all sources (Tranco TOP1M, DomCop TOP10M, and Domains Project), generate malicious URL blocklist using Google Safe Browsing API and Yandex Safe Browsing API, and update local database
```bash
python3 main.py --fetch-urls --identify-malicious-urls --sources top1m top10m domainsproject --vendors google yandex
# or alternatively
python3 main.py --fetch-urls --identify-malicious-urls
```
\
From all existing URLs in local database, generate malicious URL blocklist using Yandex Safe Browsing API
```bash
python3 main.py --identify-malicious-urls --vendors yandex
```
\
Show help message
```bash
python3 main.py --help
```

## Known Issues

- Yandex Safe Browsing API calls often fail with either ConnectionResetError or HTTP Status Code 204. Yandex Technical support has been notified. _Temporary workaround: Keep retrying API call until it succeeds_

## User Protection Notice

### Google

Google works to provide the most accurate and up-to-date information about unsafe web resources. However, Google cannot guarantee that its information is comprehensive and error-free: some risky sites may not be identified, and some safe sites may be identified in error.

## Libraries/Frameworks used
- [SQLite](https://www.sqlite.org)
- [APSW](https://rogerbinns.github.io/apsw)
- [Ray](https://www.ray.io)
- [TLDExtract](https://github.com/john-kurkowski/tldextract)

## References

- https://developers.google.com/safe-browsing
- https://yandex.com/dev/safebrowsing/
- https://tranco-list.eu
- https://www.domcop.com/top-10-million-domains
- https://domainsproject.org
- https://remusao.github.io/posts/few-tips-sqlite-perf.html