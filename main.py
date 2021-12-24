from argparse import (
    ArgumentParser,
    RawDescriptionHelpFormatter,
    RawTextHelpFormatter,
    ArgumentDefaultsHelpFormatter,
)
from update_database import update_database


class CustomFormatter(
    RawTextHelpFormatter, RawDescriptionHelpFormatter, ArgumentDefaultsHelpFormatter
):
    pass


if __name__ == "__main__":
    parser = ArgumentParser(
        description="""
    Create and/or update local [SQLite](https://www.sqlite.org) databases with URLs sourced from 
    various public lists (e.g. Tranco TOP1M), and use the Google Safe Browsing API and Yandex Safe Browsing API 
    to generate a malicious URL blocklist for [DNSBL](https://en.wikipedia.org/wiki/Domain_Name_System-based_blackhole_list) 
    applications like [pfBlockerNG](https://linuxincluded.com/block-ads-malvertising-on-pfsense-using-pfblockerng-dnsbl) 
    or [Pi-hole](https://pi-hole.net).

    For example, to generate a blocklist of malicious URLs from Tranco TOP1M using Google Safe Browsing API, 
    run `python3 main.py --fetch-urls --identify-malicious-urls --sources top1m --providers google`
    """,
        formatter_class=CustomFormatter,
    )
    parser.add_argument(
        "-f",
        "--fetch-urls",
        dest="fetch",
        action="store_true",
        help="""
        Fetch URL datasets from local and/or remote sources, 
        and update them to database
        """,
    )

    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "-i",
        "--identify-malicious-urls",
        dest="identify",
        action="store_true",
        help="""
        Use Safe Browsing API to identify malicious URLs in database, 
        write the URLs to a .txt file blocklist, 
        and update database with these malicious URLs
        """,
    )
    group.add_argument(
        "-r",
        "--retrieve-known-malicious-urls",
        dest="retrieve",
        action="store_true",
        help="""
        Retrieve URLs in database that have been flagged 
        as malicious, then create a .txt blocklist
        """,
    )

    parser.add_argument(
        "-s",
        "--sources",
        nargs="+",
        required=False,
        choices=["top1m", "top10m", "domainsproject"],
        help="""
        (OPTIONAL: Omit this flag to use all URL sources)
        Choose 1 or more URL sources
        ----------------------------
        top1m -> Tranco TOP1M
        top10m -> DomCop TOP10M
        domainsproject -> domainsproject.org
        """,
        default=["top1m", "top10m", "domainsproject"],
        type=str,
    )
    parser.add_argument(
        "-p",
        "--providers",
        nargs="+",
        required=False,
        choices=["google", "yandex"],
        help="""
        (OPTIONAL: Omit this flag to use all Safe Browsing API providers)
        Choose 1 or more URL sources
        ----------------------------
        google -> Google Safe Browsing API
        yandex -> Yandex Safe Browsing API  
        """,
        default=["google", "yandex"],
        type=str,
    )

    args = parser.parse_args()
    args.providers = sorted([x.capitalize() for x in args.providers])
    if not (args.fetch or args.identify or args.retrieve):
        parser.error("No action requested, add -h for help")

    update_database(
        fetch=args.fetch,
        identify=args.identify,
        retrieve=args.retrieve,
        sources=args.sources,
        providers=args.providers,
    )
