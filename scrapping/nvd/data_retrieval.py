'''
    Implements communication with NVD and the extraction
    of CVEs and CPEs
'''

__author__ = "Jose Antonio Carmona (joscarfom@alum.us.es)"


# BeautifulSoup4 and HTTP connections
import ssl
from bs4 import BeautifulSoup
from urllib.request import Request, urlopen
import urllib.parse

# Common
import re
import json
import time
import math

# Concurrency
from concurrent.futures import ThreadPoolExecutor, as_completed

# Structures
from scrapping.structures import CVE

# Auxiliary JSON CPE Extractor
from .cpes_json import extract_semimodel

class NvdScraper:

    SCRAPER_NAME = "nvd"
    BASE_NVD_URI = "https://nvd.nist.gov/"
    VULN_QUERY_URI = BASE_NVD_URI + "vuln/search/results?form_type=Basic&results_type=overview&search_type=all&query={}&startIndex={}"
    CVE_CPES_URI = BASE_NVD_URI + "vuln/detail/{}/cpes?expandCpeRanges=true"

    CVE_PATTERN = "^CVE-"

    def get_CVEs(self, keyword:str, page_num:int = 0, exact_match:bool = False) -> list:

        '''
            Searches NVD in order to fetch vulnerabilities related with 
            the keyword.

            :param keyword: Query that will be performed against the NVD server

            :param page_num: Number of the page from where to extract CVEs. A 
            query may produce more than one page of results. By default, page 
            size is 20.

            :param exact_match: Whether the user wants to perform a search using 
            exact keyword match
        '''

        # First, we need to check the arguments

        if not keyword or type(keyword) is not str:
            raise ValueError("keyword must be a non-empty string")

        if type(page_num) is not int or page_num < 0:
            raise ValueError("page_num must be a non-negative integer")

        res = list()
        startIndex = page_num * 20
        query_url = NvdScraper.VULN_QUERY_URI

        # If the user wants to perform a search where the keyword exactly matches
        if exact_match:
            query_url += "&queryType=phrase"

        # In some Python ENVs it is mandatory to provide a SSL context when accessing HTTPS sites
        # TODO: Change this to use user's OS built-in cas (pip certifi)
        context = ssl._create_unverified_context()
        
        # Sends an HTTPS request to NVD and constructs a BS Object
        # to analyse the page
        while True:
            req = Request(query_url.format(urllib.parse.quote(keyword), startIndex))
            try:
                res_page = urlopen(req, context=context)
                break
            except:
                print("[WARN] NVD request failed for keyword {}. Possible rate limiting. Retrying".format(keyword))
                time.sleep(5)
        
        soup = BeautifulSoup(res_page, "html.parser")

        # All CVEs are wrapped in a table (in fact the only one in the html) with an attribute
        # data-testid="vuln-results-table". Inside this table, they are found in <tr> tags.
        vulns_table = soup.find("table", {"data-testid":"vuln-results-table"})

        # Had the table been found (= results were found), we would extract the CVEs
        if vulns_table:
            vulns = vulns_table.find_all("tr", {"data-testid" : re.compile("^vuln-row-")})
            res.append(map(lambda v: CVE(v.th.strong.a.text.strip(), sources=["nvd"], vul_description=v.td.p.text), vulns))
        else:
            print("No results were found in NVD database")

        matchingRecords = int(soup.find("strong", {"data-testid":"vuln-matching-records-count"}).text.replace(',',''))
        if matchingRecords > 20 and page_num == 0:
            print("Found " + str(matchingRecords) + " results on NVD. Paginating")
            with ThreadPoolExecutor(max_workers=50) as pool:
                futures = []
                for i in range(1, math.ceil(matchingRecords/20)):
                    futureNvd = pool.submit(self.get_CVEs, keyword, exact_match=exact_match, page_num=i)
                    futures.append(futureNvd)
                results = [x.result() for x in as_completed(futures)]
            totalList = []
            for page in results:
                for result in page:
                    totalList.append(result)
            return totalList
        else:
            return list(res[0])

    def get_CPEs(self, cve: CVE) -> (dict, dict):

        '''
            Retrieves the CPEs of a given CVE, generating a dictionary containing:
                \t "CPEs": A list of the different CPEs grouped by Configuration
                \t "RUNNING_ON": A list of the different Running Enviroments 
                grouped by Configuration
            
            :param cve_id: The ID of the CVE we want the CPEs to be extracted
        '''

        # First, we need to check the arguments

        if not cve or type(cve) is not CVE:
            raise ValueError("cve must be a valid CVE object")

        if not re.compile(NvdScraper.CVE_PATTERN).match(cve.cve_id):
            raise ValueError("cve_id must be a valid CVE identifier")

        res = ({}, [])

        # In some Python ENVs it is mandatory to provide a SSL context when accessing HTTPS sites
        # TODO: Change this to use user's OS built-in cas (pip certifi)
        context = ssl._create_unverified_context()

        # Sends an HTTPS request to NVD and constructs a BS Object
        # to analyse the page
        req = Request(NvdScraper.CVE_CPES_URI.format(cve.cve_id))
        res_page = urlopen(req, context=context)
        soup = BeautifulSoup(res_page, "html.parser")

        # This webpage is dynamically rendered. CPEs are generated from a serialized JSON
        # found in the DOM. We retrieve and parse that JSON in order to extract the different
        # CPEs
        serializedJSON = soup.find("input", id="cveTreeJsonDataHidden")
        serializedJSON = None if not serializedJSON else serializedJSON.attrs["value"]

        # Maybe the CVE does not have any associated CPEs, so we may return an empty dict
        if not serializedJSON or serializedJSON == "[]":
            print("[-] This CVE does not have any associated CPEs")
            return res

        # Else, we try to parse that JSON we have found
        try:
            parsedJSON = json.loads(serializedJSON.replace("&quot;", "\""))
        except json.decoder.JSONDecodeError as err:
            print("[-] There was an error trying to parse JSON data with CPEs related to CVE: {}".format(cve_id))
            print(err)
            return res

        semi_model, running_conf = extract_semimodel(parsedJSON)

        return semi_model, running_conf