# Safe Browsing DNSBL (Domain Name System-based blackhole list) Generator

[![GitHub stars](https://img.shields.io/github/stars/elliotwutingfeng/Safe-Browsing-DNSBL-Generator?style=social)](https://github.com/elliotwutingfeng/Safe-Browsing-DNSBL-Generator/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/elliotwutingfeng/Safe-Browsing-DNSBL-Generator?style=social)](https://github.com/elliotwutingfeng/Safe-Browsing-DNSBL-Generator/network/members)
![GitHub code size in bytes](https://img.shields.io/github/languages/code-size/elliotwutingfeng/Safe-Browsing-DNSBL-Generator)
![GitHub repo size](https://img.shields.io/github/repo-size/elliotwutingfeng/Safe-Browsing-DNSBL-Generator)
[![GitHub issues](https://img.shields.io/github/issues/elliotwutingfeng/Safe-Browsing-DNSBL-Generator)](https://github.com/elliotwutingfeng/Safe-Browsing-DNSBL-Generator/issues)
[![GitHub license](https://img.shields.io/github/license/elliotwutingfeng/Safe-Browsing-DNSBL-Generator)](https://github.com/elliotwutingfeng/Safe-Browsing-DNSBL-Generator/blob/master/LICENSE)
[![GitHub commit activity](https://img.shields.io/github/commit-activity/w/elliotwutingfeng/Safe-Browsing-DNSBL-Generator)](https://github.com/elliotwutingfeng/Safe-Browsing-DNSBL-Generator/commits/master)

\
Generate malicious URL blocklists for [DNSBL](https://en.wikipedia.org/wiki/Domain_Name_System-based_blackhole_list) applications like [pfBlockerNG](https://linuxincluded.com/block-ads-malvertising-on-pfsense-using-pfblockerng-dnsbl) or [Pi-hole](https://pi-hole.net) using the Safe Browsing API from [Google](https://developers.google.com/safe-browsing) and/or [Yandex](https://yandex.com/dev/safebrowsing), with URLs sourced from various public lists like [Tranco TOP1M](https://tranco-list.eu), [DomCop TOP10M](https://www.domcop.com/top-10-million-domains), and [Domains Project](https://domainsproject.org).

---

## URL sources

-   Tranco TOP1M (~1 million URLs): <https://tranco-list.eu>
-   DomCop TOP10M (~10 million URLs): <https://www.domcop.com/top-10-million-domains>
-   Domains Project (~1.7 billion URLs): <https://domainsproject.org>
-   IPv4 Addresses (~4.2 billion IP Addresses): 0.0.0.0 - 255.255.255.255

## Safe Browsing API Vendors

<div style="display:flex;">
<a href="https://developers.google.com/safe-browsing">
<figure style="text-align:center;">
<img height="100px" src="images/google.svg" alt="Google Safe Browsing API" />
<figcaption>Google</figcaption>
</figure>
</a>
<a href="https://yandex.com/dev/safebrowsing">
<figure style="text-align:center;">
<img height="100px" src="images/yandex.png" alt="Yandex Safe Browsing API" />
<figcaption>Yandex</figcaption>
</figure>
</a>
</div>

## Requirements

-   Linux or macOS
-   Tested on Python 3.8.12
-   Multi-core x86-64 CPU; for Python Ray support
-   Recommended: At least 8GB RAM
-   At least 5GB SSD free storage space; **at least 600GB required to process Domains Project URLs and IPv4 Addresses**
-   [Obtain a Google Developer API key and set it up for the Safe Browsing API](https://developers.google.com/safe-browsing/v4/get-started)
-   [Obtain a Yandex Developer API key](https://yandex.com/dev/safebrowsing)

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
```

Edit `unpack.sh` and remove `combine` from the last line, then run:

```bash
./unpack.sh
```

## Usage Examples

**Try this first:** Fetch Tranco TOP1M and DomCop TOP10M, insert their contents to local database, and generate a blocklist using Google Safe Browsing API

-   :heavy_check_mark: Download/Extract URLs to local database
-   :heavy_check_mark: Identify malicious URLs from local database using Safe Browsing API, and generate a blocklist
-   :heavy_check_mark: Update local database with latest malicious URL statuses
-   :memo: Sources: **Tranco TOP1M**, **DomCop TOP10M**
-   :shield: Vendors: **Google**

```bash
python3 main.py --fetch-urls --identify-malicious-urls --sources top1m top10m --vendors google
```

---

Fetch Tranco TOP1M and insert its contents to local database (no blocklist will be generated)

-   :heavy_check_mark: Download/Extract URLs to local database
-   :memo: Sources: **Tranco TOP1M**
-   :shield: Vendors: **Not Applicable**

```bash
python3 main.py --fetch-urls --sources top1m
```

---

Fetch URLs from all sources, insert their contents to local database, and generate a blocklist using Google Safe Browsing API and Yandex Safe Browsing API **(:warning: requires at least 600GB free space)**

-   :heavy_check_mark: Download/Extract URLs to local database
-   :heavy_check_mark: Identify malicious URLs from local database using Safe Browsing API, and generate a blocklist
-   :heavy_check_mark: Update local database with latest malicious URL statuses
-   :memo: Sources: **Tranco TOP1M**, **DomCop TOP10M**, **Domains Project**, **IPv4 Addresses**
-   :shield: Vendors: **Google**, **Yandex**

```bash
python3 main.py --fetch-urls --identify-malicious-urls --sources top1m top10m domainsproject ipv4 \
--vendors google yandex
# or alternatively
python3 main.py --fetch-urls --identify-malicious-urls
```

---

Generate a (potentially outdated) blocklist from local database using malicious URL statuses attained from past scans

-   :heavy_check_mark: Retrieve URLs with malicious statuses (attained from past scans) from local database, and generate a blocklist
-   :memo: Sources: **DomCop TOP10M**, **Domains Project**
-   :shield: Vendors: **Google**

```bash
python3 main.py --retrieve-known-malicious-urls --sources top10m domainsproject --vendors google
```

---

Show help message

```bash
python3 main.py --help
```

## Known Issues

-   Yandex Safe Browsing API calls often fail with either ConnectionResetError or HTTP Status Code 204. Yandex Technical support has been notified. _Temporary workaround: Keep retrying API call until it succeeds_

## Disclaimer

This project is not sponsored, endorsed, or otherwise affiliated with Google and/or Yandex.

## ToS

-   [Google Safe Browsing API ToS](https://developers.google.com/safe-browsing/terms)
-   [Yandex Safe Browsing API ToS](https://yandex.ru/legal/yandex_sb_api/?lang=en)

## Libraries/Frameworks used

-   [SQLite](https://www.sqlite.org)
-   [APSW](https://rogerbinns.github.io/apsw)
-   [Ray](https://www.ray.io)
-   [TLDExtract](https://github.com/john-kurkowski/tldextract)

## References

-   <https://developers.google.com/safe-browsing>
-   <https://yandex.com/dev/safebrowsing>
-   <https://tranco-list.eu>
-   <https://www.domcop.com/top-10-million-domains>
-   <https://domainsproject.org>
-   <https://remusao.github.io/posts/few-tips-sqlite-perf.html>
