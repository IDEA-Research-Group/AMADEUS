'''
    Implements communication with VULDB for CVE and CPE extraction
'''

__author__ = "Nicolás de Ory Carmona (deorynicolas@gmail.com)"


import json
import os
# Common
import re
# BeautifulSoup4 and HTTP connections
import ssl
import time
import urllib.parse
from collections import defaultdict
from urllib.request import HTTPRedirectHandler, Request, urlopen

import requests
from bs4 import BeautifulSoup
from scrapping.structures import CVE


class VuldbScraper:

    SCRAPER_NAME = "vuldb"
    VULDB_BASE_URI = "https://vuldb.com/"
    VULDB_LOGIN_URI = VULDB_BASE_URI + "?login"
    VULDB_SEARCH_URI = VULDB_BASE_URI + "?search"
    VULDB_ID_URI = VULDB_BASE_URI + "?id."

    def __init__(self):
        self.cookie, self.csrftoken = self.__getLoginCookieAndToken()

    def __getLoginCookieAndToken(self):
        loginInfo = { 'user': os.getenv('VULDB_USER'), 'password': os.getenv('VULDB_PASSWORD') }
        while True:
            resp = requests.post(VuldbScraper.VULDB_LOGIN_URI, loginInfo)
            if "Login failed. Please try again." in resp.text:
                raise Exception("Error logging to VulDB. Check environment variables.")
            elif "DDoS Protection Message" in resp.text:
                print("[WARN] Vuldb rate limit exceeded, for a few minutes. Retrying in 10 seconds")
                time.sleep(10)
            else:
                break

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

        while True:
            searchPayload = {'search': keyword, 'csrftoken': self.csrftoken }
            searchResponse = requests.post(VuldbScraper.VULDB_SEARCH_URI, searchPayload, cookies= self.cookie)
            if 'CSRF token invalid' in searchResponse.text:
                print("VulDB CSRF token invalid, regenerating")
                # regenerate tokens
                self.__init__()
                searchPayload = {'search': keyword, 'csrftoken': self.csrftoken }
            elif 'You have been using too many search requests lately' in searchResponse.text:
                print("[WARN] VulDB CVE search rate limited. Retrying. Try again later or disable Vuldb scraping")
                time.sleep(5)
            elif "DDoS Protection Message" in searchResponse.text:
                print("[WARN] Vuldb rate limit exceeded, for a few minutes. Retrying in 10 seconds")
                time.sleep(10)
            else:
                break

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
                    entryCVE = entry.select_one('a[target="cve"]').text.strip()
                    vulnerabilities.append(CVE(entryCVE, sources= ["vuldb"], vul_name= entryVulName, vuldb_id= entryId, configurations= [titleConfiguration]))

        return vulnerabilities

    def get_CPEs(self, cve: CVE) -> tuple(dict, dict):

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

        while True:
            resp = requests.get(VuldbScraper.VULDB_ID_URI + cve.vuldb_id, cookies= self.cookie)
            if "🔒" in resp.text:
                raise Exception("Invalid login cookie")
            elif "We have detected an extended amount of requests from your user account." in resp.text:
                print("[WARN] VulDB CPE rate limited. Retrying")
                time.sleep(5)
            else:
                break

        soup = BeautifulSoup(resp.text, "html.parser")
        
        cpeH1s = soup.select('h2#cpe')
        if len(cpeH1s) == 0:
            raise Exception("Unexpected error parsing CPE data.")
        
        cpev23H1 = list(cpeH1s)[0]
        cpeEntries = cpev23H1.findNext("ul").findChildren("a")

        cpeResults = []

        notifiedOmittedCPEs = False

        for entry in cpeEntries:
            cpeText = entry.text
            if "cpe:x.x" in cpeText:
                if not notifiedOmittedCPEs:
                    print("[WARN] Vuldb - Some CPEs were omitted - premium")
                    notifiedOmittedCPEs = True
                continue
            cpeResults.append(cpeText)

        semi_model = defaultdict(lambda: defaultdict(lambda: defaultdict()))
        for cpe in cpeResults:
            if cpe == '🔍':
                print("[WARN] Vuldb - CPEs for this CVE are not being shown - premium")
                break
            split = cpe.split(':')
            semi_model[split[3]][split[4]][cpe] = list()

        running_conf = list() # TODO

        return semi_model, running_conf

#cookie, csrftoken = getLoginCookieAndToken()

#l = get_CVEs("Mozilla", cookie, csrftoken)
#s, r = get_CPEs("162188", cookie)
#print(s)
