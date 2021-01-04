'''
Run this to index CVE data in redis. 
You must have downloaded offline NVD data feeds, found in the following link
https://nvd.nist.gov/vuln/data-feeds
'''
import ujson

from redisearch import Client, TextField, IndexDefinition, Query
from concurrent.futures import ThreadPoolExecutor, as_completed

index_exists = True

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
    client.create_index((TextField("id"), TextField("description")), definition=definition)
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
            # Indexing a document for RediSearch 2.0+
            client.redis.hset('cve:'+cve_id,
                            mapping={
                                'id': cve_id,
                                'description': cve_desc,
                                'configurations': cve_configurations
                            })
        print("Processed " + file)

with ThreadPoolExecutor(max_workers=20) as pool:
    futures = []
    for i in range(2002,2021):
        future = pool.submit(process_CVE_file, './nvd_data_feeds/nvdcve-1.1-{0}.json'.format(i))
        futures.append(future)
    json_list = [x.result() for x in as_completed(futures)]

print("done")

# Add to cache
# FT.CREATE myIdx ON HASH PREFIX 1 doc: SCHEMA fieldname TEXT
# hset doc:thisisatest fieldname "hey there"
# FT.SEARCH myIdx "keyword*" LIMIT 0 10
'''
from redisearch import Client, TextField, IndexDefinition, Query

# Creating a client with a given index name
client = Client("myIndex")

# IndexDefinition is avaliable for RediSearch 2.0+
definition = IndexDefinition(prefix=['doc:', 'article:'])

# Creating the index definition and schema
client.create_index((TextField("title", weight=5.0), TextField("body")), definition=definition)

# Indexing a document for RediSearch 2.0+
client.redis.hset('doc:1',
                mapping={
                    'title': 'RediSearch',
                    'body': 'Redisearch impements a search engine on top of redis'
                })

# Indexing a document for RediSearch 1.x
client.add_document(
    "doc:2",
    title="RediSearch",
    body="Redisearch implements a search engine on top of redis",
)

# Simple search
res = client.search("search engine")

# the result has the total number of results, and a list of documents
print(res.total) # "2"
print(res.docs[0].title) # "RediSearch"

# Searching with complex parameters:
q = Query("search engine").verbatim().no_content().with_scores().paging(0, 5)
res = client.search(q)
'''
