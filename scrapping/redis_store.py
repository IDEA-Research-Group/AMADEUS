'''
Redis helper functions. Needs a Redis server running locally.
'''

import redis
import jsonpickle

conn = redis.Redis('localhost')

SEARCH_RESULTS_HASH_KEY = "vul_search_result_{}"
CVES_FROM_CPE_HASH_KEY = "cves_from_cpe_{}"
CPES_FROM_CVE_HASH_KEY = "cpes_from_cve_{}"
EXPLOITS_FROM_CVE_HASH_KEY = "exploits_from_cve_{}"

def store_search_results(keyword: str, results: list):
    '''
    Stores search results from vulnerability databases (not exploits)
    '''
    key = SEARCH_RESULTS_HASH_KEY.format(keyword)
    jsonDict = jsonpickle.encode(results)
    conn.set(key, jsonDict)
    print("Stored {} related search results in cache".format(keyword))

def get_search_results(keyword: str):
    '''
    Tries to retrieve search results from vulnerability databases, returns a list or None if record doesn't exist
    '''
    key = SEARCH_RESULTS_HASH_KEY.format(keyword)
    try:
        val = conn.get(key)
    except:
        raise Exception("You need to be running a Redis server at localhost:6379")
    if val:
        print("Loaded {} related search results in cache".format(keyword))
        return jsonpickle.decode(val.decode('utf-8'))
    else:
        return None

def store_cpes_from_cve(cveId: str, cpes: tuple):
    '''
    Stores a tuple of semimodel of CPEs affected by the given CVE and running configurations
    '''
    key = CPES_FROM_CVE_HASH_KEY.format(cveId)
    jsonDict = jsonpickle.encode(cpes)
    conn.set(key, jsonDict)
    print("Stored CPEs related to CVE {} in cache".format(cveId))

def get_cpes_from_cve(cveId: str):
    '''
    Tries to retrieve a tuple composed of semimodel dictionary of CPEs affected by a CVE and running configurations, returns a tuple or None if record doesn't exist
    '''
    key = CPES_FROM_CVE_HASH_KEY.format(cveId)
    val = conn.get(key)
    if val:
        print("Loaded CPEs related to CVE {} from cache".format(cveId))
        return jsonpickle.decode(val.decode('utf-8'))
    else:
        return None

def store_exploits_from_cve(cveId: str, exploits: list):
    '''
    Stores a list of exploits associated to the given CVE
    '''
    key = EXPLOITS_FROM_CVE_HASH_KEY.format(cveId)
    jsonDict = jsonpickle.encode(exploits)
    conn.set(key, jsonDict)
    print("Stored exploits related to {} in cache".format(cveId))

def get_exploits_from_cve(cveId: str):
    '''
    Tries to retrieve exploits associated to the given CVE, returns a list or None if record doesn't exist
    '''
    key = EXPLOITS_FROM_CVE_HASH_KEY.format(cveId)
    val = conn.get(key)
    if val:
        print("Loaded exploits related to {} from cache".format(cveId))
        return jsonpickle.decode(val.decode('utf-8'))
    else:
        return None

# TODO Add methods for deleting cache entries