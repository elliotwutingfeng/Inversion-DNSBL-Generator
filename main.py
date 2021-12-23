import argparse
from update_database import update_database

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="""Python script to periodically update local SQLite databases with popular URLs 
    sourced from various public lists (e.g. Tranco TOP1M), and use the Google Safe Browsing API and Yandex Safe Browsing API to generate a 
    malicious URL blocklist for applications like pfBlockerNG/Pi-hole etc. Uses [Ray](http://www.ray.io/) to make 
    parallel requests with pipelining to the Google Safe Browsing API and Yandex Safe Browsing API."""
    )
    parser.add_argument(
        "-t",
        "--tasks",
        nargs="+",
        required=False,
        choices=[
            "fetch",  # Retrieve raw URL data, UPSERT to DB
            "generate",  # Download latest hashPrefixes, use them to identify URLs in DB that are malicious, then create a .txt blocklist.
        ],  # TODO add option to generate blocklist from DB using lastMalicious statuses in DB
        help=f"""""",
        default=["fetch", "generate"],
    )
    parser.add_argument(
        "-l",
        "--lists",
        nargs="+",
        required=False,
        choices=["top1m", "top10m", "domainsproject"],
        help=f"""""",
        default=["top1m", "top10m", "domainsproject"],
    )
    parser.add_argument(
        "-p",
        "--providers",
        nargs="+",
        required=False,
        choices=["Google", "Yandex"],
        help=f"""""",
        default=["Google", "Yandex"],
    )
    args = parser.parse_args()

    update_database(tasks=args.tasks, lists=args.lists, providers=args.providers)
