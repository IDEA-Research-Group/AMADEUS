'''
    Implements communication with VULDB for CVE and CPE extraction
'''

__author__ = "Nicolás de Ory Carmona (deorynicolas@gmail.com)"


# BeautifulSoup4 and HTTP connections
import ssl
from bs4 import BeautifulSoup
from urllib.request import Request, urlopen, HTTPRedirectHandler
import urllib.parse
import requests

# Common
import re
import json
import os
from collections import defaultdict

from scrapping.structures import CVE


class VuldbScraper:

    VULDB_BASE_URI = "https://vuldb.com/"
    VULDB_LOGIN_URI = VULDB_BASE_URI + "?login"
    VULDB_SEARCH_URI = VULDB_BASE_URI + "?search"
    VULDB_ID_URI = VULDB_BASE_URI + "?id."

    def __init__(self):
        self.cookie, self.csrftoken = self.__getLoginCookieAndToken()

    def __getLoginCookieAndToken(self):
        loginInfo = { 'user': os.getenv('VULDB_USER'), 'password': os.getenv('VULDB_PASSWORD') }
        resp = requests.post(VuldbScraper.VULDB_LOGIN_URI, loginInfo)

        if "Login failed. Please try again." in resp.text:
            raise Exception("Error logging to VulDB. Check environment variables.")

        soup = BeautifulSoup(resp.text, "html.parser")
        csrftoken = soup.select_one('input[name="csrftoken"]').get('value')
        return (resp.cookies, csrftoken)

    def get_CVEs(self, keyword: str, exact_match: bool=False) -> list:

        '''
            Searches VulDB in order to fetch vulnerabilities related with 
            the keyword.

            :param keyword: Query that will be performed against the VulDB server
            :param exact_match: results must match keyword exactly
        '''

        # First, we need to check the arguments

        if not keyword or type(keyword) is not str:
            raise ValueError("keyword must be a non-empty string")
        
        searchPayload = {'search': keyword, 'csrftoken': self.csrftoken }
        searchResponse = requests.post(VuldbScraper.VULDB_SEARCH_URI, searchPayload, cookies= self.cookie)

        if 'You have been using too many search requests lately' in searchResponse.text:
            print("VulDB rate limited")
            return
        
        soup = BeautifulSoup(searchResponse.text, "html.parser")
        tableEntries = soup.select_one('table').findChildren("tr", recursive=False)

        vulnerabilities = []

        for entry in tableEntries:
            tableCell = entry.select_one('td:nth-child(4)')
            if tableCell: # Check if entry is not the table header
                titleConfiguration = tableCell.get('title')
                entryIdElem = tableCell.select_one('a')
                if entryIdElem: # Check if entry is not the table header
                    entryVulName = entryIdElem.text
                    if exact_match and keyword not in entryVulName: # If exact_match is true, skip item if not a exact keyword match
                        continue
                    entryId = entryIdElem.get('href')[4:]
                    entryCVE = entry.select_one('a[target="cve"]').text
                    vulnerabilities.append(CVE(entryCVE, source= "vuldb", vul_name= entryVulName, vuldb_id= entryId, configuration= titleConfiguration))

        return vulnerabilities

    def get_CPEs(self, cve: CVE) -> (dict, dict):

        '''
            Retrieves the CPEs of a given CVE, generating a dictionary containing:
                \t "CPEs": A list of the different CPEs grouped by Configuration
                \t "RUNNING_ON": A list of the different Running Enviroments 
                grouped by Configuration
            
            :param cve a CVE object with a valid vuldb id
        '''

        if not cve or type(cve) is not CVE:
            raise ValueError("cve must be a valid CVE object with a valid vuldb id")

        if not cve.vuldb_id:
            # No vuldb id, so we can't use this scraper for CPEs
            return

        resp = requests.get(VuldbScraper.VULDB_ID_URI + cve.vuldb_id, cookies= self.cookie)

        if "🔒" in resp.text:
            print("Invalid login cookie")
            return

        soup = BeautifulSoup(resp.text, "html.parser")
        
        cpeH1s = soup.select('h2#cpe')
        if len(cpeH1s) == 0:
            print("Unexpected error parsing CPE data")
            return
        
        cpev23H1 = list(cpeH1s)[0]
        cpeEntries = cpev23H1.findNext("ul").findChildren("a")

        cpeResults = []

        notifiedOmittedCPEs = False

        for entry in cpeEntries:
            cpeText = entry.text
            if cpeText == "cpe:x.x:x:xxxxxx:xxxx:x.xx.x:*:*:*:*:*:*:*":
                if not notifiedOmittedCPEs:
                    print("[WARN] Vuldb - Some CPEs were omitted - premium")
                    notifiedOmittedCPEs = True
                continue
            cpeResults.append(cpeText)

        semi_model = defaultdict(lambda: defaultdict(lambda: list()))
        for cpe in cpeResults:
            split = cpe.split(':')
            semi_model[split[3]][split[4]][cpe] = list()

        running_conf = list() # TODO

        return semi_model, running_conf

#cookie, csrftoken = getLoginCookieAndToken()

#l = get_CVEs("Mozilla", cookie, csrftoken)
#s, r = get_CPEs("162188", cookie)
#print(s)