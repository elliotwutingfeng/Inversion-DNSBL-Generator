## This script demonstrates the basic features of the database
import ray
import time

from db_utils import (
create_connection, 
create_table,database,
sql_create_urls_table,
sql_create_updatelog_table,
add_urls,get_all_urls,
update_malicious_URLs,
update_activity_URLs
)
from alivecheck import check_activity_URLs
from safebrowsing import get_unsafe_URLs
from top1m_utils import get_top1m_whitelist


ray.shutdown()
ray.init(include_dashboard=False,num_cpus=4)

# Create database with 2 tables
conn = create_connection(database)
# initialise tables
if conn is not None:
    # create urls table
    create_table(conn, sql_create_urls_table)

    # create updatelog table
    create_table(conn, sql_create_updatelog_table)
else:
    print("Error! cannot create the database connection.")

# Fetch today's TOP1M
print("Fetching TOP1M")
top1m_urls = get_top1m_whitelist()
#top1m_urls = ["google.com","yahoo.com","halo.com","daolulianghua.com"] # daolulianghua.com is unsafe

updateTime = time.time()

# UPSERT database with today's TOP1M
print("Adding URLs to DB")
project_id = add_urls(conn, top1m_urls, updateTime)
all_urls = get_all_urls(conn)

# Identify malicious URLs, UPDATE them in the DB
print("Updating malicious URLs")
unsafe_urls = get_unsafe_URLs(all_urls)
update_malicious_URLs(conn, unsafe_urls, updateTime)

# Fping all URLs, UPDATE them in the DB (lastReachAttempt,lastReachable)
alive_urls,_ = check_activity_URLs(all_urls)
update_activity_URLs(conn, alive_urls, updateTime)

# Generate TXT blocklist, push to GitHub
# TODO


ray.shutdown()