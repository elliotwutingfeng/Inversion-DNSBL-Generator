# Popular URLs marked as malicious by Google Safe Browsing API

## Overview

Python script to periodically update a local SQLite database with popular URLs sourced from various public lists (e.g. Tranco TOP1M), and use the Google Safe Browsing API to generate a malicious URL blocklist for applications like pfBlockerNG/Pi-hole etc. Uses [Ray](http://www.ray.io/) to make parallel requests with pipelining to the Google Safe Browsing API.

## Popular URL sources

- Tranco TOP1M : https://tranco-list.eu
- DomCop TOP10M : https://www.domcop.com/top-10-million-domains

## Requirements

- Python 3.7.6
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
# TESTING mode: Generate blocklist.txt based on last 4000 URLs from Tranco TOP1M list
python3 main.py --mode testing
# FULL mode: Update local database with latest TOP1M+TOP10M URLs and generate blocklist.txt from local database
python3 main.py --mode full
```

## References

- https://tranco-list.eu
- https://www.domcop.com/top-10-million-domains
- https://developers.google.com/safe-browsing/v4/lookup-api
