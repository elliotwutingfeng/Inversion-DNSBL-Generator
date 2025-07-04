"""
Main
"""

import os
from argparse import (
    Action,
    ArgumentDefaultsHelpFormatter,
    ArgumentParser,
    RawDescriptionHelpFormatter,
    RawTextHelpFormatter,
)

from modules.process_flags import process_flags


class CustomFormatter(
    RawTextHelpFormatter,
    RawDescriptionHelpFormatter,
    ArgumentDefaultsHelpFormatter,
):
    """Custom Help text formatter for argparse."""


class MinimumOneAction(Action):
    """Ensures minimum argument input value of 1"""

    def __call__(self, parser, namespace, values, option_string=None):
        if values < 1:
            parser.error("Minimum input value for {0} is 1".format(option_string))
        setattr(namespace, self.dest, values)


if __name__ == "__main__":
    parser = ArgumentParser(
        description="""
    Generate malicious URL blocklists for
    DNSBL applications like pfBlockerNG or Pi-hole using the
    Safe Browsing API from Google and/or Yandex, with URLs
    sourced from various public lists like
    Tranco TOP1M, DomCop TOP10M, and Domains Project.

    For example, to generate a blocklist of malicious URLs
    from Tranco TOP1M using Google Safe Browsing API,
    run `python3 main.py --fetch-urls --identify-malicious-urls
    --sources top1m --vendors google`
    """,
        formatter_class=CustomFormatter,
        # Disallows long options to be abbreviated
        # if the abbreviation is unambiguous
        allow_abbrev=False,
    )
    parser.color = True

    parser.add_argument(
        "-f",
        "--fetch-urls",
        dest="fetch",
        action="store_true",
        help="""
        Fetch URL datasets from local and/or remote sources,
        and update database with URL datasets
        """,
    )

    parser.add_argument(
        "-u",
        "--update-hashes",
        action="store_true",
        help="""
        Download the latest Safe Browsing API malicious
        URL full hashes and update database with full hashes.
        (WARNING: Enabling this flag will
        cost more than 5000 Safe Browsing API calls)
        """,
    )

    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "-i",
        "--identify-malicious-urls",
        dest="identify",
        action="store_true",
        help="""
        Use Safe Browsing API hashes to identify malicious URLs in database,
        write the URLs to a .txt file blocklist,
        and update database with these malicious URLs
        (this flag cannot be enabled together
        with '--retrieve-known-malicious-urls')
        """,
    )
    group.add_argument(
        "-r",
        "--retrieve-known-malicious-urls",
        dest="retrieve",
        action="store_true",
        help="""
        Retrieve URLs in database that have been flagged
        as malicious from past scans, then create a .txt file blocklist
        (this flag cannot be enabled together with '--identify-malicious-urls')
        """,
    )

    sources = {
        "top1m": "Tranco TOP1M",
        "top10m": "DomCop TOP10M",
        "r01": "Registrar R01 (.ru, .su, .rf)",
        "cubdomain": "CubDomain.com",
        "icann": "ICANN zone files (ICANN Terms-of-Service "
        "download limit per zone file: Once every 24 hours)",
        "domainsproject": "domainsproject.org",
        "ec2": "Amazon Web Services EC2 public hostnames",
        "gce": "Google Compute Engine public hostnames",
        "openintel": "OpenINTEL.nl (.nu .se .ee .gov .fed.us)",
        "switch_ch": "Switch.ch (.ch .li)",
        "afnic": "AFNIC.fr (.fr .re .pm .tf .wf .yt)",
        "internet_ee": "Internet.ee (.ee)",
        "internetstiftelsen": "Internetstiftelsen",
        "sknic": "SK-NIC.sk (.sk)",
        "googletag": "Google Threat Analysis Group Indicators of Compromise",
        "ipv4": "ipv4 addresses",
    }

    parser.add_argument(
        "-s",
        "--sources",
        nargs="+",
        required=False,
        choices=list(sources.keys()),
        help=f"""
        (OPTIONAL: Omit this flag to use all URL sources)
        Choose 1 or more URL sources
        ----------------------------
        {os.linesep.join(f"{name} -> {description}"
        for name,description in sources.items())}
        """,
        default=list(sources.keys()),
        type=str,
    )

    parser.add_argument(
        "--cubdomain-num-days",
        required=False,
        help="""
        (OPTIONAL: Omit this flag to fetch and/or
        analyse the entire CubDomain.com dataset)
        Counting back from current date, the number of days of CubDomain.com
        data to fetch and/or analyse. By default all available data
        dating back to 25 June 2017 will be considered.
        If 'cubdomain' is not enabled in `--sources`,
        this flag will be silently ignored.
        """,
        default=None,
        type=int,
        action=MinimumOneAction,
    )

    parser.add_argument(
        "--afnic-num-days",
        required=False,
        help="""
        (OPTIONAL: Omit this flag to fetch only
        monthly archives and not fetch AFNIC.fr daily updates)
        Counting back from current date, the number of days of AFNIC.fr
        daily updates to fetch and/or analyse.
        By default only monthly archives will be fetched,
        and no daily updates will be fetched,
        .
        If 'afnic' is not enabled in `--sources`,
        this flag will be silently ignored.
        """,
        default=None,
        type=int,
        action=MinimumOneAction,
    )

    choices = {
        "google": "Google Safe Browsing API",
        "yandex": "Yandex Safe Browsing API",
    }

    parser.add_argument(
        "-v",
        "--vendors",
        nargs="+",
        required=False,
        choices=list(choices.keys()),
        help=f"""
        (OPTIONAL: Omit this flag to use all Safe Browsing API vendors)
        Choose 1 or more URL sources
        ----------------------------
        {os.linesep.join(f"{name} -> {description}"
        for name,description in choices.items())}
        """,
        default=list(choices.keys()),
        type=str,
    )

    parser.add_argument(
        "-n",
        "--num-cpus",
        required=False,
        help="""
        (OPTIONAL: Omit this flag to use all available CPUs)
        Number of CPUs to use for parallel processes. By default
        all available CPUs will be used.
        """,
        default=None,
        type=int,
        action=MinimumOneAction,
    )

    parser.add_argument(
        "--include-dashboard",
        action="store_true",
        help="""
        Whether or not to start the Ray dashboard,
        which displays the status of the Ray cluster.
        """,
    )

    parser.add_argument(
        "--blocklist-suffix",
        required=False,
        type=str,
        help="Suffix to be added to blocklist filenames when uploading to GitHub",
        default=None,
    )

    args = parser.parse_args()
    args.vendors = sorted([vendor.capitalize() for vendor in args.vendors])
    if not (args.fetch or args.update_hashes or args.identify or args.retrieve):
        parser.error("No action requested, add -h for help")

    process_flags(parser_args=vars(args))
