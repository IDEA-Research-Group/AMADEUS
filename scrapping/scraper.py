'''
    Implements communication with vulnerability databases for extraction
    of CVEs and CPEs
'''

__author__ = "Nicolás de Ory (deorynicolas@gmail.com)"


# Concurrency
from concurrent.futures import ThreadPoolExecutor, as_completed

# Scrapers
from .nvd.data_retrieval import NvdScraper
from .vuldb.data_retrieval import VuldbScraper

from .structures import CVE

class VulnerabilityScraper():

    def __init__(self):
        self.nvdScraper = NvdScraper()
        self.vuldbScraper = VuldbScraper()
    
    
    def get_CVEs(self, keyword: str, exact_match: bool=False):
        '''
            Returns a list of CVEs matching the given keyword, using available web scrapers

            :param keyword: keyword to look for

            :param exact_match: if results should be for the exact keyword
        '''
        with ThreadPoolExecutor(max_workers=10) as pool:
            # TODO do NVD paging
            futureNvd = pool.submit(self.nvdScraper.get_CVEs, keyword, exact_match=exact_match)
            futureVuldb = pool.submit(self.vuldbScraper.get_CVEs, keyword, exact_match=exact_match)
            futures = [futureNvd, futureVuldb]
            results = [x.result() for x in as_completed(futures)]

            cves = dict()

            for r in results:
                for cve in r:
                    if cve.cve_id not in cves:
                        cves[cve.cve_id] = cve
                    else:
                        cves[cve.cve_id].joinData(cve)

            return cves.values()
    
    def get_CPEs(self, cve: CVE) -> (dict, dict): 
        '''
            Returns a list of CPEs matching the given CVE, using available web scrapers

            :param cve: cve to look for
        '''
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
                        if cpe not in finalSemimodel[k][m]:
                            finalSemimodel[k][m][cpe] = list()
        
        return (finalSemimodel, runningConf1)