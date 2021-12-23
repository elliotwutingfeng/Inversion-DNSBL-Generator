import ray
import subprocess
import logging
from logger_utils import init_logger

from ray_utils import execute_with_ray


def fping(url):
    # "fast pings" a given url, visit https://fping.org/ to learn more about the 'fping' command
    CMD = f"fping {url}"
    output = subprocess.run(CMD, shell=True, capture_output=True)
    return output


def check_activity_URLs(urls_to_be_checked):
    logging.info("Checking host statuses of URLs with fping")
    # Check URL host statuses with fping
    results = execute_with_ray(urls_to_be_checked, fping)
    alive_and_not_dns_blocked_urls = []
    alive_and_dns_blocked_urls = []
    unreachable_urls = []
    name_not_known_urls = []
    unknown_urls = []
    for result in results:
        url = result.args.split(" ")[1]
        # stdout = result.stdout.decode()
        stderr = result.stderr.decode()
        returncode = result.returncode

        if returncode == 0:
            if "[<- 127.0.0.1]" not in stderr:
                alive_and_not_dns_blocked_urls.append(url)  # Host reachable
            else:
                alive_and_dns_blocked_urls.append(
                    url
                )  # Host reachable but blocked by local DNSBL
        elif returncode == 1:
            unreachable_urls.append(url)  # Host unreachable
        elif returncode == 2:
            name_not_known_urls.append(url)  # IP address not found
        else:
            unknown_urls.append(url)

    logging.info(f"Alive and unblocked URLS: {len(alive_and_not_dns_blocked_urls)}")
    logging.info(f"Alive and blocked URLS: {len(alive_and_dns_blocked_urls)}")
    logging.info(f"Unreachable URLS: {len(unreachable_urls)}")
    logging.info(f"Name Not Known URLS: {len(name_not_known_urls)}")
    logging.info(f"Unknown URLS: {len(unknown_urls)}")

    return (
        alive_and_not_dns_blocked_urls,
        alive_and_dns_blocked_urls,
        unreachable_urls,
        name_not_known_urls,
        unknown_urls,
    )


if __name__ == "__main__":
    logger = init_logger()
    ray.shutdown()
    ray.init(include_dashboard=False)

    with open("URLs_marked_malicious_by_Safe_Browsing.txt", "r") as f:
        dangerous_urls = [x.strip() for x in f.readlines()]
    (
        alive_and_not_dns_blocked_urls,
        alive_and_dns_blocked_urls,
        unreachable_urls,
        name_not_known_urls,
        unknown_urls,
    ) = check_activity_URLs(dangerous_urls)

    ray.shutdown()