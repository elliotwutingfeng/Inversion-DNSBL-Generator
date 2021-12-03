import ray
import subprocess

from ray_utils import execute_tasks

@ray.remote
def fping(url,pba):
    # "fast pings" a given url, visit https://fping.org/ to learn more about the 'fping' command
    CMD = f"fping {url}"
    output = subprocess.run(CMD,shell=True,capture_output=True)
    pba.update.remote(1)
    return output

def check_activity_URLs(all_urls):
    # Identify alive and dead urls with fping
    results = execute_tasks(all_urls,fping)
    alive_urls = []
    dead_urls = []
    for result in results:
        url = result.args.split(" ")[1]
        #stdout = result.stdout.decode()
        #stderr = result.stderr.decode()
        returncode = result.returncode
        if returncode == 0:
            alive_urls.append(url)
        else:
            dead_urls.append(url)
    return alive_urls,dead_urls