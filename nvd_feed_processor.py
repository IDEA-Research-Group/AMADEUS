'''
Run this to index CVE data in redis. 
You must have downloaded offline NVD data feeds, found in the following link
https://nvd.nist.gov/vuln/data-feeds
'''
import ujson

from redisearch import Client, TextField, IndexDefinition, Query
from concurrent.futures import ThreadPoolExecutor, as_completed

import redis

index_exists = True

# Create a normal redis connection
conn = redis.Redis('localhost')

# Creating a client with a given index name
client = Client("cveIndex")
try:
    client.info()
except Exception as e:
    if e.args[0] != "Unknown Index name":
        print("You must be running a redis server with the redisearch module installed")
        exit()

# IndexDefinition is avaliable for RediSearch 2.0+
definition = IndexDefinition(prefix=['cve:'])

# Creating the index definition and schema
try:
    client.create_index((TextField("id"), TextField("description"), TextField("configurations")), definition=definition)
except:
    # Index already exists. Delete and recreate
    client.drop_index()
    print("Index already exists. Dropping. Delete keys and try again.")
    exit()

def process_CVE_file(file):
    with open(file, 'r', encoding="utf8") as f:
        json = ujson.decode(f.read())
        cve_items = json['CVE_Items']
        for cve_item in cve_items:
            cve_id = cve_item['cve']['CVE_data_meta']['ID']
            cve_desc = cve_item['cve']['description']['description_data'][0]['value']
            cve_configurations = str(cve_item['configurations']['nodes'])
            # Sanitizing special characters to prevent them from being tokenized away
            cve_desc_sanitized = cve_desc.replace(':','cc11').replace('.','pp22').replace('*','ss33')
            cve_configurations_sanitized = cve_configurations.replace(':','cc11').replace('.','pp22').replace('*','ss33')
            # Indexing a document for RediSearch 2.0+
            client.redis.hset('cve:'+cve_id,
                            mapping={
                                'id': cve_id,
                                'description': cve_desc_sanitized,
                                'configurations': cve_configurations_sanitized
                            })
        print("Processed " + file)

with ThreadPoolExecutor(max_workers=20) as pool:
    futures = []
    for i in range(2002,2021):
        future = pool.submit(process_CVE_file, './nvd_data_feeds/nvdcve-1.1-{0}.json'.format(i))
        futures.append(future)
    json_list = [x.result() for x in as_completed(futures)]

print("Done processing CVE feeds. Processing NVD CPE match feed")

with open("./nvd_data_feeds/nvdcpematch-1.0.json", 'r', encoding="utf8") as f:
    json = ujson.decode(f.read())
    matches = json['matches']
    for match in matches:
        rootUri = match['cpe23Uri']
        keyName = rootUri
        if 'versionStartIncluding' in match:
            keyName += ';;versionStartIncluding=' + match['versionStartIncluding']
        if 'versionStartExcluding' in match:
            keyName += ';;versionStartExcluding=' + match['versionStartExcluding']
        if 'versionEndIncluding' in match:
            keyName += ';;versionEndIncluding=' + match['versionEndIncluding']
        if 'versionEndExcluding' in match:
            keyName += ';;versionEndExcluding=' + match['versionEndExcluding']
        if len(match['cpe_name']) > 0:
            # if CPE list is empty no need to include it in cache
            valueString = ";;".join(x['cpe23Uri'] for x in match['cpe_name'])
            conn.set(keyName, valueString)

print("done")