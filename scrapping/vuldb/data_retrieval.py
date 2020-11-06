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

# Auxiliary JSON CPE Extractor
#from ..cpes_json import extract_semimodel

BASE_NVD_URI = "https://nvd.nist.gov/"
VULN_QUERY_URI = BASE_NVD_URI + "vuln/search/results?form_type=Basic&results_type=overview&search_type=all&query={}&startIndex={}"
CVE_CPES_URI = BASE_NVD_URI + "vuln/detail/{}/cpes?expandCpeRanges=true"

CVE_PATTERN = "^CVE-"

#loggedIn = False

def getLoginCookieAndToken():
    loginInfo = { 'user': os.getenv('VULDB_USER'), 'password': os.getenv('VULDB_PASSWORD') }

    resp = requests.post("https://vuldb.com/?login", loginInfo)

    if "Login failed. Please try again." in resp.text:
        print("Error logging to VulDB")
        return None
    
    soup = BeautifulSoup(resp.text, "html.parser")
    csrftoken = soup.select_one('input[name="csrftoken"]').get('value')

    return (resp.cookies, csrftoken)

def get_CVEs(keyword:str, cookies, csrftoken) -> list:

    '''
        Searches VulDB in order to fetch vulnerabilities related with 
        the keyword.

        :param keyword: Query that will be performed against the VulDB server
    '''

    # First, we need to check the arguments

    if not keyword or type(keyword) is not str:
        raise ValueError("keyword must be a non-empty string")
    
    if not cookies or not csrftoken:
        raise ValueError("Cookies and Csrf token must be provided")
    
    searchPayload = {'search': 'Mozilla Firefox', 'csrftoken': csrftoken }
    searchResponse = requests.post("https://vuldb.com/?search", searchPayload, cookies=cookies)

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
            print(entryId + " - " + entryCVE)

    return vulnerabilities

def get_CPEs(vuldb_id:str, cookie) -> dict:

    '''
        Retrieves the CPEs of a given CVE, generating a dictionary containing:
            \t "CPEs": A list of the different CPEs grouped by Configuration
            \t "RUNNING_ON": A list of the different Running Enviroments 
            grouped by Configuration
        
        :param vuldb_id: The ID of the vulnerability
        :param cookie: The login cookie
    '''

    if not vuldb_id or type(vuldb_id) is not str:
        raise ValueError("vuldb_id must be a non-empty string")

    if not cookie:
        raise ValueError("cookie must be a RequestCookieJar")

    resp = requests.get("https://vuldb.com/?id."+vuldb_id, cookies=cookie)

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

    for entry in cpeEntries:
        cpeText = entry.text
        cpeResults.append(cpeText)

    semi_model = defaultdict(lambda: defaultdict(lambda: list()))
    for cpe in cpeResults:
        split = cpe.split(':')
        semi_model[split[3]][split[4]].append(cpe)

    running_conf = list() # TODO

    return semi_model, running_conf

cookie, _ = getLoginCookieAndToken()

s, r = get_CPEs("164010", cookie)
print(s)

#get_CVEs("ma", 0)