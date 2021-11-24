# Tranco TOP1M URLs marked unsafe by Google Safe Browsing API

## Overview

Python script to find all URLs in [Tranco TOP1M](https://tranco-list.eu) deemed by Google Safe Browsing API to be unsafe. Results are saved to a text file which can be fed into blocklist applications like pfBlockerNG/Pi-hole etc.

## Setup instructions

1. You will need to [obtain a Google Developer API key and set it up for the Safe Browsing API](https://developers.google.com/safe-browsing/v4/get-started)
2. `git clone` and `cd` into the project directory, then run the following

```bash
echo "<your-google-api-key-here>" >> .env
pip3 install requirements.txt
```

## How to use

```bash
# TESTING mode: Lookup last 5000 URLs from Tranco TOP1M list on Google Safe Browsing API, save results to text file
python3 main.py --mode test
# FULL mode: Lookup all 1000,000 URLs on Google Safe Browsing API, save results to text file
python3 main.py --mode full
```

## References

- https://tranco-list.eu
- https://developers.google.com/safe-browsing/v4/lookup-api
