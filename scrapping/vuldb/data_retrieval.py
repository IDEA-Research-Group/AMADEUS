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



class VulDbScraper:

    VULDB_BASE_URI = "https://vuldb.com/"
    VULDB_LOGIN_URI = VULDB_BASE_URI + "?login"
    VULDB_SEARCH_URI = VULDB_BASE_URI + "?search"
    VULDB_ID_URI = VULDB_BASE_URI + "?id."

    def __init__(self):
        self.cookie, self.csrftoken = VulDbScraper.__getLoginCookieAndToken()

    @staticmethod
    def __getLoginCookieAndToken():
        loginInfo = { 'user': os.getenv('VULDB_USER'), 'password': os.getenv('VULDB_PASSWORD') }
        resp = requests.post(VulDbScraper.VULDB_LOGIN_URI, loginInfo)

        if "Login failed. Please try again." in resp.text:
            raise Exception("Error logging to VulDB. Check environment variables.")

        soup = BeautifulSoup(resp.text, "html.parser")
        csrftoken = soup.select_one('input[name="csrftoken"]').get('value')
        return (resp.cookies, csrftoken)

    def get_CVEs(self, keyword:str) -> list:

        '''
            Searches VulDB in order to fetch vulnerabilities related with 
            the keyword.

            :param keyword: Query that will be performed against the VulDB server
            :param cookies: Login cookie returned by getLoginCookieAndToken method
            :param csrftoken: CSRFToken returned by getLoginCookieAndToken method 
        '''

        # First, we need to check the arguments

        if not keyword or type(keyword) is not str:
            raise ValueError("keyword must be a non-empty string")
        
        searchPayload = {'search': keyword, 'csrftoken': self.csrftoken }
        searchResponse = requests.post(VulDbScraper.VULDB_SEARCH_URI, searchPayload, cookies= self.cookie)

        if 'You have been using too many search requests lately' in searchResponse.text:
            print("rate limited")
            return
        
        soup = BeautifulSoup(searchResponse.text, "html.parser")
        tableEntries = soup.select_one('table').findChildren("tr", recursive=False)

        vulnerabilities = []

        for entry in tableEntries:
            entryIdElem = entry.select_one('td[title="Web Browser"] a')
            if entryIdElem: # Check if entry is not the table header
                entryId = entryIdElem.get('href')[4:]
                entryCVE = entry.select_one('a[target="cve"]').text
                vulnerabilities.append((entryId, entryCVE))

        return vulnerabilities

    def get_CPEs(self, vuldb_id:str) -> dict:

        '''
            Retrieves the CPEs of a given CVE, generating a dictionary containing:
                \t "CPEs": A list of the different CPEs grouped by Configuration
                \t "RUNNING_ON": A list of the different Running Enviroments 
                grouped by Configuration
            
            :param vuldb_id: The VULDB ID of the vulnerability
            :param cookie: The login cookie
        '''

        if not vuldb_id or type(vuldb_id) is not str:
            raise ValueError("vuldb_id must be a non-empty string")

        resp = requests.get(VulDbScraper.VULDB_ID_URI + vuldb_id, cookies= self.cookie)

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
                    print("[WARN] Some CPEs were omitted")
                    notifiedOmittedCPEs = True
                continue
            cpeResults.append(cpeText)

        semi_model = defaultdict(lambda: defaultdict(lambda: list()))
        for cpe in cpeResults:
            split = cpe.split(':')
            semi_model[split[3]][split[4]].append(cpe)

        running_conf = list() # TODO

        return semi_model, running_conf

#cookie, csrftoken = getLoginCookieAndToken()

#l = get_CVEs("Mozilla", cookie, csrftoken)
#s, r = get_CPEs("162188", cookie)
#print(s)