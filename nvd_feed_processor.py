import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from shutil import rmtree
from subprocess import PIPE, STDOUT, Popen
from sys import stdout
from time import sleep
from zipfile import ZipFile

import redis
import ujson
from redisearch import Client, IndexDefinition, TextField
from requests import get


def open_redis():
    if not os.path.isdir('./nvd_data_feeds/'):
        os.mkdir('./nvd_data_feeds/')

    print('Creating the docker container with redislabs/redisearch\n')
    Popen(['docker', 'run', '--rm', '--name', 'amadeus', '-p', '6379:6379', 'redislabs/redisearch:latest'])
    sleep(6)

    urls = [
        'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2021.json.zip',
        'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2020.json.zip',
        'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2019.json.zip',
        'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2018.json.zip',
        'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2017.json.zip',
        'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2016.json.zip',
        'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2015.json.zip',
        'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2014.json.zip',
        'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2013.json.zip',
        'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2012.json.zip',
        'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2011.json.zip',
        'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2010.json.zip',
        'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2009.json.zip',
        'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2008.json.zip',
        'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2007.json.zip',
        'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2006.json.zip',
        'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2005.json.zip',
        'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2004.json.zip',
        'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2003.json.zip',
        'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2002.json.zip',
        'https://nvd.nist.gov/feeds/json/cpematch/1.0/nvdcpematch-1.0.json.zip'
        ]

    print('\nDownloading and unziping json feeds')
    if not os.path.isdir('./downloads/'):
        os.mkdir('./downloads/')
    tam = len(urls)
    dl = 0
    for url in urls:
        name = url.split('/')[-1]
        response = get(url)
        open('./downloads/' + name, 'wb').write(response.content)
        with ZipFile('./downloads/' + name, 'r') as zip_ref:
            zip_ref.extractall('./nvd_data_feeds/')
        dl += 1
        prog = dl / tam
        done = int(50 * prog)
        stdout.write('\r[%s%s%s]%s' % ('Progres > ', '=' * (done-1) + '>', ' ' * (50-done), str(round(prog*100)) + '%'))
    rmtree('./downloads/')
    print('\n')

    print('Start processing CVE feeds')

    # Create a normal redis connection
    conn = redis.Redis('localhost')

    # Creating a client with a given index name
    client = Client('cveIndex')

    # IndexDefinition is avaliable for RediSearch 2.0+
    definition = IndexDefinition(prefix=['cve:'])

    # Creating the index definition and schema
    try:
        client.create_index((TextField('id'), TextField('description'), TextField('configurations')), definition=definition)
    except:
        # Index already exists. Delete and recreate
        client.drop_index()
        print('Index already exists\nDropping\nDelete keys and try again')
        exit()

    def process_CVE_file(file):
        with open(file, 'r', encoding='utf8') as f:
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
            print('Processed ' + file)

    with ThreadPoolExecutor(max_workers=20) as pool:
        futures = []
        for i in range(2002,2021):
            future = pool.submit(process_CVE_file, './nvd_data_feeds/nvdcve-1.1-{0}.json'.format(i))
            futures.append(future)
        json_list = [x.result() for x in as_completed(futures)]

    print('Done processing CVE feeds\nProcessing NVD CPE match feed')

    with open('./nvd_data_feeds/nvdcpematch-1.0.json', 'r', encoding='utf8') as f:
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
                valueString = ';;'.join(x['cpe23Uri'] for x in match['cpe_name'])
                conn.set(keyName, valueString)

    print('\nAMADEUS is already launched!')

def close_redis():
    Popen(['docker', 'stop', 'amadeus'])
    sleep(2)
    print('AMADEUS has been close succesfully!')
