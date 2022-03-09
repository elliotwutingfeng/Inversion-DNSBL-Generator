<div align="center">
  <h3 align="center">Safe Browsing DNSBL (Domain Name System-based blackhole list) Generator</h3>

  <p align="center">
    Generate malicious URL blocklists for <a href="https://en.wikipedia.org/wiki/Domain_Name_System-based_blackhole_list">DNSBL</a> applications like <a href="https://linuxincluded.com/block-ads-malvertising-on-pfsense-using-pfblockerng-dnsbl">pfBlockerNG</a> or <a href="https://pi-hole.net">Pi-hole</a> by scanning various public URL sources using the Safe Browsing API from <a href="https://developers.google.com/safe-browsing">Google</a> and/or <a href="https://yandex.com/dev/safebrowsing">Yandex</a>.
    <br />
    <br />
    <a href="https://github.com/elliotwutingfeng/Safe-Browsing-DNSBL-Blocklists/issues">Report Bug</a>
    ·
    <a href="https://github.com/elliotwutingfeng/Safe-Browsing-DNSBL-Blocklists/issues">Request Feature</a>
  </p>

  <p align="center">
  <a href="https://python.org"><img src="https://img.shields.io/badge/Python-FFD43B?style=for-the-badge&logo=python&logoColor=blue" alt="Python"/></a>
  <a href="https://www.sqlite.org"><img src="https://img.shields.io/badge/SQLite-07405E?style=for-the-badge&logo=sqlite&logoColor=white" alt="SQLite"/></a>
  <a href="https://docs.aiohttp.org/en/stable"><img src="https://img.shields.io/badge/AIOHTTP-2C5BB4?style=for-the-badge&logo=aiohttp&logoColor=white" alt="AIOHTTP"/></a>
  <a href="https://www.ray.io"><img src="https://img.shields.io/badge/Ray-028CF0?style=for-the-badge&logo=ray&logoColor=white" alt="Ray"/></a>
  </p>

  <p align="center">
  <a href="https://github.com/elliotwutingfeng/Safe-Browsing-DNSBL-Generator/stargazers"><img src="https://img.shields.io/github/stars/elliotwutingfeng/Safe-Browsing-DNSBL-Generator?style=for-the-badge" alt="GitHub stars"/></a>
  <a href="https://github.com/elliotwutingfeng/Safe-Browsing-DNSBL-Generator/watchers"><img src="https://img.shields.io/github/watchers/elliotwutingfeng/Safe-Browsing-DNSBL-Generator?style=for-the-badge" alt="GitHub watchers"/></a>
  <a href="https://github.com/elliotwutingfeng/Safe-Browsing-DNSBL-Generator/network/members"><img src="https://img.shields.io/github/forks/elliotwutingfeng/Safe-Browsing-DNSBL-Generator?style=for-the-badge" alt="GitHub forks"/></a>
  <a href="https://github.com/elliotwutingfeng/Safe-Browsing-DNSBL-Generator/issues"><img src="https://img.shields.io/github/issues/elliotwutingfeng/Safe-Browsing-DNSBL-Generator?style=for-the-badge" alt="GitHub issues"/></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/LICENSE-BSD--3--CLAUSE-GREEN?style=for-the-badge" alt="GitHub license"/></a>
  <a href="https://github.com/elliotwutingfeng/Safe-Browsing-DNSBL-Generator/commits/master)"><img src="https://img.shields.io/github/commit-activity/w/elliotwutingfeng/Safe-Browsing-DNSBL-Generator?style=for-the-badge" alt="GitHub commit activity"/></a>
  </p>

</div>

---

## Blocklists available for download

![Total Blocklist URLs](https://img.shields.io/tokei/lines/github/elliotwutingfeng/Safe-Browsing-DNSBL-Blocklists?label=Total%20Blocklist%20URLS&style=for-the-badge)

You may download the blocklists [here](https://github.com/elliotwutingfeng/Safe-Browsing-DNSBL-Blocklists#safe-browsing-dnsbl-domain-name-system-based-blackhole-list-blocklists)

## URL sources

| Name | URL Count (millions) | Source |
|-|-|-|
| Tranco TOP1M | 1 | https://tranco-list.eu |
| DomCop TOP10M | 10 | https://www.domcop.com/top-10-million-domains |
| Registrar R01 | 5.9 | https://r01.ru |
| CubDomain.com | 184 | https://cubdomain.com |
| ICANN CZDS (Centralized Zone Data Service) | 227 | https://czds.icann.org |
| Domains Project    | 2100 | https://domainsproject.org |
| Amazon Web Services EC2 | 56 | https://docs.aws.amazon.com/vpc/latest/userguide/vpc-dns.html#vpc-dns-hostnames |
| OpenINTEL.nl | 6 | https://openintel.nl |
| Switch.ch | 3.3 | https://switch.ch/open-data |
| IPv4 Addresses | 4200 | 0.0.0.0 - 255.255.255.255 |

## Safe Browsing API vendors

| <a href="https://developers.google.com/safe-browsing"><img height="100px" src="images/google.svg" alt="Google Safe Browsing API" /></a> | <a href="https://yandex.com/dev/safebrowsing"><img height="100px" src="images/yandex.png" alt="Yandex Safe Browsing API" /></a> |
|:-:|:-:|
|[Google](https://developers.google.com/safe-browsing)|[Yandex](https://yandex.com/dev/safebrowsing)|
|[Terms-of-Service](https://developers.google.com/safe-browsing/terms)|[Terms-of-Service](https://yandex.ru/legal/yandex_sb_api/?lang=en)|

## Requirements

### System (mandatory)

-   Linux or macOS
-   Python >= 3.9.10
-   Multi-core x86-64 CPU; for Python Ray support
-   RAM: At least 8GB
-   SSD Drive Space: At least 600GB required to process all URL sources

### Safe Browsing API Access (mandatory)

Choose at least one
-   Google: [Obtain a Google Developer API key and set it up for the Safe Browsing API](https://developers.google.com/safe-browsing/v4/get-started)
-   Yandex: [Obtain a Yandex Developer API key](https://yandex.com/dev/safebrowsing)

### URL feed access (optional)

-   ICANN Zone Files: [Sign up for a ICANN CZDS account](https://czds.icann.org)
    - Once registered, turn off email notifications in the user settings,
then select `Create New Request` on the Dashboard to request for zone file access.

    - **ICANN Terms-of-Service download limit per zone file:** Once every 24 hours

### Others (optional)

-   GitHub API (for uploading blocklists to GitHub): [Create a Personal Access Token](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/creating-a-personal-access-token)

## Setup instructions

`git clone` and `cd` into the project directory, then run the following

```bash
# You will need at least one of the following environment variables
echo "GOOGLE_API_KEY=<your-google-api-key-here>" >> .env
echo "YANDEX_API_KEY=<your-yandex-api-key-here>" >> .env

# These environment variables are optional
echo "ICANN_ACCOUNT_USERNAME=<your-icann-account-username-here>" >> .env
echo "ICANN_ACCOUNT_PASSWORD=<your-icann-account-password-here>" >> .env
echo "GITHUB_ACCESS_TOKEN=<your-github-personal-access-token-here>" >> .env
echo "BLOCKLIST_REPOSITORY_NAME=<your-blocklist-repository-name-here>" >> .env

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

**Try this first:** Fetch Tranco TOP1M and DomCop TOP10M, insert their contents to local database, download Safe Browsing API malicious URL hashes, and generate a blocklist using Google Safe Browsing API

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

Fetch URLs from all sources, insert their contents to local database, download Safe Browsing API malicious URL hashes, and generate a blocklist using Google Safe Browsing API and Yandex Safe Browsing API **(:warning: requires at least 600GB free space)**

-   :heavy_check_mark: Download/Extract URLs to local database
-   :heavy_check_mark: Download Safe Browsing API malicious URL hashes to local database
-   :heavy_check_mark: Identify malicious URLs from local database using Safe Browsing API hashes, and generate a blocklist
-   :heavy_check_mark: Update local database with latest malicious URL statuses
-   :memo: Sources: Everything
-   :shield: Vendors: **Google**, **Yandex**

```bash
python3 main.py --fetch-urls --update-hashes --identify-malicious-urls
```

---

Generate a blocklist from local database using malicious URL statuses attained from past scans

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

- This project is not sponsored, endorsed, or otherwise affiliated with Google and/or Yandex.

- Google works to provide the most accurate and up-to-date information about unsafe web resources. However, Google cannot guarantee that its information is comprehensive and error-free: some risky sites may not be identified, and some safe sites may be identified in error.

- URLs detected with the Safe Browsing API usually have a malicious validity period of about 5 minutes. As the blocklists are updated only once every 24 hours, the blocklists must not be used to display user warnings.

**More information on Google Safe Browsing API usage limits:** https://developers.google.com/safe-browsing/v4/usage-limits

## References

-   <https://developers.google.com/safe-browsing>
-   <https://yandex.com/dev/safebrowsing>
-   <https://remusao.github.io/posts/few-tips-sqlite-perf.html>
-   <https://github.com/icann/czds-api-client-python>
