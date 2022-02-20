# Safe Browsing DNSBL (Domain Name System-based blackhole list) Generator

[![GitHub stars](https://img.shields.io/github/stars/elliotwutingfeng/Safe-Browsing-DNSBL-Generator?style=social)](https://github.com/elliotwutingfeng/Safe-Browsing-DNSBL-Generator/stargazers)
[![GitHub watchers](https://img.shields.io/github/watchers/elliotwutingfeng/Safe-Browsing-DNSBL-Generator?style=social)](https://github.com/elliotwutingfeng/Safe-Browsing-DNSBL-Generator/watchers)
[![GitHub forks](https://img.shields.io/github/forks/elliotwutingfeng/Safe-Browsing-DNSBL-Generator?style=social)](https://github.com/elliotwutingfeng/Safe-Browsing-DNSBL-Generator/network/members)
![GitHub code size in bytes](https://img.shields.io/github/languages/code-size/elliotwutingfeng/Safe-Browsing-DNSBL-Generator)
![GitHub repo size](https://img.shields.io/github/repo-size/elliotwutingfeng/Safe-Browsing-DNSBL-Generator)
[![GitHub issues](https://img.shields.io/github/issues/elliotwutingfeng/Safe-Browsing-DNSBL-Generator)](https://github.com/elliotwutingfeng/Safe-Browsing-DNSBL-Generator/issues)
[![GitHub license](https://img.shields.io/github/license/elliotwutingfeng/Safe-Browsing-DNSBL-Generator)](https://github.com/elliotwutingfeng/Safe-Browsing-DNSBL-Generator/blob/master/LICENSE)
[![GitHub commit activity](https://img.shields.io/github/commit-activity/w/elliotwutingfeng/Safe-Browsing-DNSBL-Generator)](https://github.com/elliotwutingfeng/Safe-Browsing-DNSBL-Generator/commits/master)

\
Generate malicious URL blocklists for [DNSBL](https://en.wikipedia.org/wiki/Domain_Name_System-based_blackhole_list) applications like [pfBlockerNG](https://linuxincluded.com/block-ads-malvertising-on-pfsense-using-pfblockerng-dnsbl) or [Pi-hole](https://pi-hole.net) by scanning various public URL sources using the Safe Browsing API from [Google](https://developers.google.com/safe-browsing) and/or [Yandex](https://yandex.com/dev/safebrowsing).

---

## URL sources

-   Tranco TOP1M (~1 million URLs): <https://tranco-list.eu>
-   DomCop TOP10M (~10 million URLs): <https://www.domcop.com/top-10-million-domains>
-   Registrar R01 (~5.8 million URLs): <https://r01.ru>
-   CubDomain.com (~200 million URLs): <https://cubdomain.com>
-   ICANN CZDS (Centralized Zone Data Service) (~220 million URLs): <https://czds.icann.org>
-   Domains Project (~1.7 billion URLs): <https://domainsproject.org>
-   Amazon Web Services EC2 (~56 million URLs): <https://docs.aws.amazon.com/vpc/latest/userguide/vpc-dns.html#vpc-dns-hostnames>
-   IPv4 Addresses (~4.2 billion IP Addresses): 0.0.0.0 - 255.255.255.255

## Safe Browsing API vendors

| <a href="https://developers.google.com/safe-browsing"><img height="100px" src="images/google.svg" alt="Google Safe Browsing API" /></a> | <a href="https://yandex.com/dev/safebrowsing"><img height="100px" src="images/yandex.png" alt="Yandex Safe Browsing API" /></a> |
| :-------------------------------------------------------------------------------------------------------------------------------------: | :-----------------------------------------------------------------------------------------------------------------------------: |
|                                          [Google](https://developers.google.com/safe-browsing)                                          |                                          [Yandex](https://yandex.com/dev/safebrowsing)                                          |
|                                        [Terms-of-Service](https://developers.google.com/safe-browsing/terms)                                         |                                      [Terms-of-Service](https://yandex.ru/legal/yandex_sb_api/?lang=en)                                      |

## Requirements

-   Linux or macOS
-   Python >= 3.9.10
-   Multi-core x86-64 CPU; for Python Ray support
-   RAM: At least 8GB
-   SSD Drive Space: At least 1TB required to process all URL sources
-   [Obtain a Google Developer API key and set it up for the Safe Browsing API](https://developers.google.com/safe-browsing/v4/get-started)
-   [Obtain a Yandex Developer API key](https://yandex.com/dev/safebrowsing)
-   [Sign up for a ICANN CZDS account](https://czds.icann.org)

## Additional instructions for ICANN CZDS

Once registered, turn off email notifications in the user settings,
then select `Create New Request` on the Dashboard to request for zone file access.

**ICANN Terms-of-Service download limit per zone file:** Once every 24 hours

## Setup instructions

`git clone` and `cd` into the project directory, then run the following

```bash
echo "GOOGLE_API_KEY=<your-google-api-key-here>" >> .env
echo "YANDEX_API_KEY=<your-yandex-api-key-here>" >> .env
echo "ICANN_ACCOUNT_USERNAME=<your-icann-account-username-here>" >> .env
echo "ICANN_ACCOUNT_PASSWORD=<your-icann-account-password-here>" >> .env
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
-   :heavy_check_mark: Download Safe Browsing API malicious URL hashes to local database
-   :heavy_check_mark: Identify malicious URLs from local database using Safe Browsing API hashes, and generate a blocklist
-   :heavy_check_mark: Update local database with latest malicious URL statuses
-   :memo: Sources: **Tranco TOP1M**, **DomCop TOP10M**
-   :shield: Vendors: **Google**

```bash
python3 main.py --fetch-urls --update-hashes --identify-malicious-urls --sources top1m top10m --vendors google
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

Fetch URLs from all sources, insert their contents to local database, and generate a blocklist using Google Safe Browsing API and Yandex Safe Browsing API **(:warning: requires at least 1TB free space)**

-   :heavy_check_mark: Download/Extract URLs to local database
-   :heavy_check_mark: Download Safe Browsing API malicious URL hashes to local database
-   :heavy_check_mark: Identify malicious URLs from local database using Safe Browsing API hashes, and generate a blocklist
-   :heavy_check_mark: Update local database with latest malicious URL statuses
-   :memo: Sources: **Tranco TOP1M**, **DomCop TOP10M**, **Registrar R01**, **CubDomain.com**, **ICANN**, **Domains Project**, **Amazon Web Services EC2**, **IPv4 Addresses**
-   :shield: Vendors: **Google**, **Yandex**

```bash
python3 main.py --fetch-urls --update-hashes --identify-malicious-urls
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

-   Yandex Safe Browsing Update API appears to be unserviceable. Yandex Technical support has been notified.

## Disclaimer

This project is not sponsored, endorsed, or otherwise affiliated with Google and/or Yandex.

## Libraries/Frameworks used

-   [SQLite](https://www.sqlite.org)
-   [APSW](https://rogerbinns.github.io/apsw)
-   [Ray](https://www.ray.io)
-   [TLDExtract](https://github.com/john-kurkowski/tldextract)
-   [BeautifulSoup4](https://beautiful-soup-4.readthedocs.io)
-   [AIOHTTP](https://docs.aiohttp.org/en/stable)

## References

-   <https://developers.google.com/safe-browsing>
-   <https://yandex.com/dev/safebrowsing>
-   <https://remusao.github.io/posts/few-tips-sqlite-perf.html>
-   <https://github.com/icann/czds-api-client-python>
