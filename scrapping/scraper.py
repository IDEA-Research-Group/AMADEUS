'''
    Implements communication with vulnerability databases for extraction
    of CVEs and CPEs
'''

__author__ = "Nicolás de Ory (deorynicolas@gmail.com)"


# Concurrency
from concurrent.futures import ThreadPoolExecutor, as_completed

# Regex
import re

# Redis
from .redis_store import *

# Scrapers
from .nvd.data_retrieval import NvdScraper
from .vuldb.data_retrieval import VuldbScraper

from .structures import CVE
from .exploitdb_scraper import ExploitDbScraper


class VulnerabilityScraper():

    def __init__(self):
        self.nvdScraper = NvdScraper()
        self.vuldbScraper = VuldbScraper()
        self.scrapers = [self.nvdScraper, self.vuldbScraper]
        
        self.exploitScraper = ExploitDbScraper()
    
    
    def get_CVEs(self, keyword: str, exact_match: bool=False, exclude_scrapers: list=[], no_print=False):
        '''
            Returns a list of CVEs matching the given keyword, using available web scrapers

            :param keyword: keyword to look for

            :param exact_match: if results should be for the exact keyword
        '''
        if not no_print:
            print("Search for CVEs")
        
        cachedResult = get_search_results(keyword)
        if cachedResult != None:
            return cachedResult
        
        with ThreadPoolExecutor(max_workers=10) as pool:
            # TODO do NVD paging
            futures = []
            if "nvd" not in exclude_scrapers:
                futureNvd = pool.submit(self.nvdScraper.get_CVEs, keyword, exact_match=exact_match)
                futures.append(futureNvd)
            if "vuldb" not in exclude_scrapers:
                futureVuldb = pool.submit(self.vuldbScraper.get_CVEs, keyword, exact_match=exact_match)
                futures.append(futureVuldb)
            results = [x.result() for x in as_completed(futures)]

            cves = dict()

            for r in results:
                if not r:
                    continue
                for cve in r:
                    if cve.cve_id not in cves:
                        cves[cve.cve_id] = cve
                    else:
                        cves[cve.cve_id].joinData(cve)
            
            # Populate CVE info from as many sources as possible
            if not no_print:
                print("Populating CVEs")
            number_of_cves = len(cves.values())
            for i, cve in enumerate(cves.values()):
                for scraper in [s for s in self.scrapers if s.SCRAPER_NAME not in cve.sources and s.SCRAPER_NAME not in exclude_scrapers]:
                    newCves = scraper.get_CVEs(cve.cve_id, exact_match= True) # NOTE: Might consume a lot of search quota
                    if newCves:
                        cves[cve.cve_id].joinData(newCves)
                    progress = int((i/number_of_cves)*100)
                    if progress % 10 == 0 and not no_print:
                        print("Progress: {}%".format(progress))
                    
            store_search_results(keyword, list(cves.values()))
            return cves.values()
    
    def get_CVEs_from_CPE(self, cpe: str):
        '''
        Searches for vulnerabilities that affect the specified CPE 2.3 string. Currently searches on NVD only.
        
        :param cpe: cpe to look for
        '''
        return self.get_CVEs(cpe, exact_match=True, exclude_scrapers=["vuldb"], no_print=True)

    def get_CPEs(self, cve: CVE) -> (dict, dict): 
        '''
            Returns a list of CPEs matching the given CVE, using available web scrapers
            Note: Mutates given cve, appending found configurations in CPEs (Application, Hardware or Operating System)

            :param cve: cve to look for
        '''
        cachedResult = get_cpes_from_cve(cve.cve_id)
        if cachedResult != None:
            for k in cachedResult[0]:
                for m in cachedResult[0][k]:
                    for cpe in cachedResult[0][k][m]:
                        self.getConfigurationFromCPE(cpe, cve)
            return cachedResult
            
        semimodel1, runningConf1 = self.nvdScraper.get_CPEs(cve)
        vuldbResults = self.vuldbScraper.get_CPEs(cve)
        semimodel2, runningConf2 = vuldbResults if vuldbResults else (None, None)
        semimodels = [semimodel1, semimodel2]
        semimodels = [s for s in semimodels if s]
        finalSemimodel = dict()

        for semimodel in semimodels:
            topKeys = semimodel.keys()
            for k in topKeys:
                if k not in finalSemimodel:
                    finalSemimodel[k] = dict()
                middleKeys = semimodel[k].keys()
                for m in middleKeys:
                    if m not in finalSemimodel[k]:
                        finalSemimodel[k][m] = dict()
                    cpes = semimodel[k][m]
                    for cpe in cpes:
                        self.getConfigurationFromCPE(cpe, cve)
                        if cpe not in finalSemimodel[k][m]:
                            finalSemimodel[k][m][cpe] = list()
        
        store_cpes_from_cve(cve.cve_id, (finalSemimodel, runningConf1))
        return (finalSemimodel, runningConf1)

    def getConfigurationFromCPE(self, cpe: str, cve: CVE):
        '''
        Reads the given CPE type and assigns it to the given CPE if it doesn't already have that configuration
        '''
        partRegex = r'cpe:2.3:\/?([\w])+:'
        match = re.match(partRegex, cpe)
        if not match:
            print("Unrecognized CPE " + cpe)
        else:
            matches = match.groups()
            if len(matches) > 0:
                part = matches[0]
                if part == "a" and "Application" not in cve.configurations:
                    cve.configurations.append("Application")
                elif part == "h" and "Hardware" not in cve.configurations:
                    cve.configurations.append("Hardware")
                elif part == "o" and "Operating System" not in cve.configurations:
                    cve.configurations.append("Operating System")

    def get_exploits_for_CVE(self, cve: CVE):
        '''
        Returns a list of exploits for the given CVE
        '''
        if not cve or not isinstance(cve, CVE):
            raise TypeError("cve must be a valid CVE object")

        return self.exploitScraper.get_exploits_for_CVE(cve.cve_id)
    
    def get_exploits_for_CPE(self, cpe: str, excludeCVE: CVE = None):
        '''
        Returns a list of exploits that affect the given CPE configuration
        '''
        if not cpe or type(cpe) is not str:
            raise TypeError("cve must be a valid CVE object")

        return self.exploitScraper.get_exploits_for_CPE(cpe, self, excludeCVE=excludeCVE)