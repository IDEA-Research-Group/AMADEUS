'''
    Implements communication with vulnerability databases for extraction
    of CVEs and CPEs
'''

__author__ = "Nicolás de Ory (deorynicolas@gmail.com)"


import re
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from enum import Enum

from cpe import CPE

from .exploitdb_scraper import ExploitDbScraper
from .nvd.data_retrieval import NvdScraper
from .redis_store import *
from .structures import CVE
from .vuldb.data_retrieval import VuldbScraper


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
        
        with ThreadPoolExecutor(max_workers=50) as pool:
            futures = []
            if "nvd" not in exclude_scrapers:
                futureNvd = pool.submit(self.nvdScraper.get_CVEs, keyword, exact_match=exact_match)
                futures.append(futureNvd)
            if "vuldb" not in exclude_scrapers:
                #futureVuldb = pool.submit(self.vuldbScraper.get_CVEs, keyword, exact_match=exact_match)
                #futures.append(futureVuldb)
                pass
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
                for scraper in [s for s in self.scrapers if s.SCRAPER_NAME not in cve.sources and s.SCRAPER_NAME not in exclude_scrapers and s.SCRAPER_NAME != 'vuldb']:
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

    def get_CVEs_from_exploit(self, exploit: str):
        return self.exploitScraper.get_CVEs_from_exploit(exploit)

    def expand(self, complex_cpe):
        '''
        Expands and conditionally expands a complex CPE in order to obtain
        simple and up-to-date CPEs.
        
        :param container: A valid dictionary-like representation
        of a complex CPE
        '''
        res = list()
        versionStartIncluding=complex_cpe.get('versionStartIncluding', False)
        versionStartExcluding=complex_cpe.get('versionStartExcluding', False)
        versionEndIncluding=complex_cpe.get('versionEndIncluding', False)
        versionEndExcluding=complex_cpe.get('versionEndExcluding', False)
        if versionStartIncluding != False or versionStartExcluding != False or versionEndIncluding != False or versionEndExcluding != False:
            res = get_expanded_cpe(complex_cpe['cpe23Uri'], 
                                versionStartIncluding=versionStartIncluding,
                                versionStartExcluding=versionStartExcluding,
                                versionEndIncluding=versionEndIncluding,
                                versionEndExcluding=versionEndExcluding)
            res = [r.replace(':-', ':*') for r in res]
            return res
        else:
            return [complex_cpe['cpe23Uri'].replace(':-', ':*')]

    def process_basic_configuration(self, node):
        res = defaultdict(lambda: defaultdict(set))
        for complex_cpe in node['cpe_match']:
            aux = CPE(complex_cpe['cpe23Uri'])
            res[aux.get_vendor()[0]][aux.get_product()[0]].update(self.expand(complex_cpe))
        return res

    def process_running_on_configuration(self, node):
        simple_cpes = defaultdict(lambda: defaultdict(set))
        running_on = defaultdict(lambda: defaultdict(set))
        if 'children' not in node:
            # TODO if this happens, we would need to add a constraint in FMR saying that X cpe needs Y cpe and viceversa.
            for complex_cpe in node['cpe_match']:
                aux = CPE(complex_cpe['cpe23Uri'])
                simple_cpes[aux.get_vendor()[0]][aux.get_product()[0]].update(self.expand(complex_cpe))
        else:
            for subnode in node['children']:
                isVulnerable = subnode['cpe_match'][0]['vulnerable']
                if isVulnerable:
                    # simple cpe
                    for complex_cpe in subnode['cpe_match']:
                        aux = CPE(complex_cpe['cpe23Uri'])
                        simple_cpes[aux.get_vendor()[0]][aux.get_product()[0]].update(self.expand(complex_cpe))
                else:
                    # running on
                    for complex_cpe in subnode['cpe_match']:
                        aux = CPE(complex_cpe['cpe23Uri'])
                        running_on[aux.get_vendor()[0]][aux.get_product()[0]].update(self.expand(complex_cpe))
        return simple_cpes, running_on

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

        cveInfo = get_search_results(cve.cve_id)[0]
        configNodes = cveInfo.cpeConfigurations

        cpes = defaultdict(lambda: defaultdict(lambda: defaultdict(list)))
        running_configs = list()
        simple_cpes = list()
        rc_count = -1

        for node in configNodes:
            running_on = None

            if node['operator'] == "OR":
                # basic
                print("[-] Detected Configuration Type: BASIC")
                simple_cpes = self.process_basic_configuration(node)
            elif node['operator'] == "AND":
                # running on
                print("[-] Detected Configuration Type: RUNNING_ON")
                simple_cpes, running_on = self.process_running_on_configuration(node)
                # Would this be the correct way to go? When all configs are vulnerable, it's basically processed as a basic_configuration.
                # No running on configs would be included
                if len(running_on) > 0:
                    rc_count += 1
                    running_configs.append(running_on)
            else:
                raise ValueError("Unknown operator " + node['operator'])
        
            # Append results to dictionary
            if hasattr(simple_cpes, 'items'):
                for vendor, products in simple_cpes.items():
                    # Iterate over all products of a vendor
                    for product, s_cpes in products.items():

                        # Iterate over all new CPEs
                        for cpe in s_cpes:

                            # This line retrieves the specific CPE if exists
                            # and creates a new entry if it doesn't
                            res_cpe = cpes[vendor][product][cpe]
                            self.getConfigurationFromCPE(cpe, cve)

                            if node['operator'] == "AND" and len(running_on) > 0:
                                res_cpe.append(rc_count)
                                
        return cpes, running_configs

    def getConfigurationFromCPE(self, cpe: str, cve: CVE):
        '''
        Reads the given CPE type and assigns it to the given CPE if it doesn't already have that configuration
        '''
        partRegex = r'cpe:2.3:\/?([\w])+:'
        match = re.match(partRegex, cpe)
        cpe = CPE(cpe)
        if not match:
            print("Unrecognized CPE " + cpe)
        else:
            matches = match.groups()
            if len(matches) > 0:
                part = matches[0]
                if part == "a" and (cpe, "Application") not in cve.configurations:
                    cve.configurations.append((cpe, "Application"))
                elif part == "h" and (cpe, "Hardware") not in cve.configurations:
                    cve.configurations.append((cpe, "Hardware"))
                elif part == "o" and (cpe, "Operating System") not in cve.configurations:
                    cve.configurations.append((cpe, "Operating System"))

    def get_exploits_for_CVE(self, cve: CVE):
        '''
        Returns a list of exploits for the given CVE
        '''
        if not cve or not isinstance(cve, CVE):
            raise TypeError("cve must be a valid CVE object")

        return self.exploitScraper.get_exploits_for_CVE(cve.cve_id)
    
    def get_exploits_for_CPE(self, cpe: str, excludeCVE: CVE, cveExploitDict: dict):
        '''
        Returns a list of exploits that affect the given CPE configuration
        :param cveExploitDict A dict that stores CVE: list(exploits) to prevent unnecesary work
        '''
        if not cpe or type(cpe) is not str:
            raise TypeError("cve must be a valid CVE object")

        return self.exploitScraper.get_exploits_for_CPE(cpe, self, excludeCVE, cveExploitDict)
