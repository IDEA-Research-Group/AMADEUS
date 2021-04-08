import threading
import time
import subprocess
import argparse
import re
import csv
import os

from timer import ChronoTimer

from scrapping.scraper import VulnerabilityScraper
from scrapping.structures import CVE

from concurrent.futures import ThreadPoolExecutor, as_completed

from fm.fm import generate_tree

from dotenv import load_dotenv
load_dotenv()

def launch_nmap(target_ip):

    res = None
    command = "nmap -sV -A -oG - {}".format(target_ip)

    try:
        subprocesso = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE)

        while subprocesso.poll() is None:
            print('NMAP is executing. Please wait...')
            time.sleep(5)
        
        subprocess_return = str(subprocesso.stdout.read().decode("utf-8"))
        print('Network analysis finished. Vulnerability search may start now.')
        
        res = subprocess_return

        print("---- NMAP RESULTS ----")
        print(res)
        print("--------------------- \n")

    except Exception as e:
        print('There was an error when trying to launch nmap in your system')
        print(e)
    
    return res

def process_nmap_out(out):

    res = []

    for l in out.splitlines():
        for l2 in l.split('\t'):
            if 'open' in l2 or 'filtered' in l2:
                for l3 in l2.split('/,'):
                    lastSeen = None
                    j = 0
                    for i in reversed(range(0, len(l3))):
                        if lastSeen != '/' or l3[i] != '/':
                            lastSeen = l3[i]
                        else:
                            j = i + 2
                            break
                    if len(l3) != j:
                        res.append(l3[j:])
    
    return res

def get_cves_for_exploits(exploits: list):
    scraper = VulnerabilityScraper()
    for exploit in exploits:
        print("{}: {}".format(exploit, scraper.get_CVEs_from_exploit(exploit)))

def construct_cpe_model_for_cve(cve: CVE, cve_times: list):
    timer = ChronoTimer()
    cve.configurations = [] # Workaround for a bug
    semi_model, running_conf = scraper.get_CPEs(cve)
    print("Finding direct exploits for {}".format(cve.cve_id))
    timer.start_exploit_scraping()
    direct_exploits = scraper.get_exploits_for_CVE(cve)
    indirect_exploits = dict()
    cpesToCheck = []
    for v in semi_model:
        for p in semi_model[v]:
            for cpe in semi_model[v][p]:
                cpesToCheck.append(cpe)
    
    print("Finding indirect exploits for {}. Checking {} CPEs".format(cve.cve_id, len(cpesToCheck)))
    n = len(cpesToCheck)
    
    with ThreadPoolExecutor(max_workers=50) as pool:
        futures = {}
        cveExploitDict = dict()
        for cpe in cpesToCheck:
            f = pool.submit(scraper.get_exploits_for_CPE, cpe, cve, cveExploitDict)
            futures[cpe] = f

        n = len(futures)
        for i, _ in enumerate(as_completed(futures.values())):
            progress = int((i/n)*100)
            if progress % 5 == 0:
                print("Progress: {}%".format(progress))

    indirect_exploits = {cpe: futures[cpe].result() for cpe in cpesToCheck}
    timer.stop_exploit_scraping()
    generate_tree(cve, semi_model, running_conf, direct_exploits, indirect_exploits, timer)
    print("Wrote tree for " + cve.cve_id)
    cve_times.append((cve.cve_id, '%.4f' % timer.get_exploit_scraping_time(), '%.4f' % timer.get_tree_build_time(), '%.4f' % timer.get_constraints_time()))
   # time.sleep(5) # Wait until releasing worker to reduce load...?

def construct_cpe_model(related_cves, keyword, cve_times):
    
    if related_cves:
        with ThreadPoolExecutor(max_workers=50) as pool:
            for cve in related_cves:
                futures = {}
                f = pool.submit(construct_cpe_model_for_cve, cve, cve_times)
                futures[cve.cve_id] = f
            n = len(futures)
            for i, _ in enumerate(as_completed(futures.values())):
               #progress = int((i/n)*100)
               pass
        save_times_in_csv(keyword, cve_times)
        print("Finished")
        
def save_times_in_csv(keyword, cve_times):
    sanitizedName = keyword.replace('*','#').replace('.','_')
    if not os.path.isdir('./fm/models/times/'):
        os.mkdir('./fm/models/times/')
    with open('./fm/models/times/{}.csv'.format(sanitizedName), 'w', newline='',encoding='utf-8') as times_file:
        writer = csv.writer(times_file)
        writer.writerow(['cve','scraping_time','tree_build_time','constraints_time'])
        writer.writerows(x for x in cve_times)
    print("Saved csv with times.")


if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument("-k", "--keyword", nargs=1, help="Keyword used to perform a manual CVE search on vulnerability databases")
    parser.add_argument("-x", "--exploits", nargs=1, help="Retrieves CVEs associated with a comma-separated list of exploit ids")
    parser.add_argument("-e", action='store_true', help="If the results from databases must be an EXACT match of the keywords or just contain them")
    parser.add_argument("-a", action='store_true', help="Launches NMAP to perform an automatic search of vulnerabilities")
    parser.add_argument("-t", "--target", nargs=1, help="CIDR block or host target of the automatic analysis")
    parser_results = parser.parse_args()

    # Validate parser output
    if parser_results.a and parser_results.target is None:
        parser.error("-a requires -t to specify the target to which apply the analysis")

    if parser_results.target is not None and not parser_results.a:
        parser.error("-t requires -a to perform an automatic analysis")

    if not parser_results.exploits and parser_results.keyword is None and not parser_results.a:
        parser.error("You must enter either a keyword or launch an automatic search against a target IP")

    scraper = VulnerabilityScraper()

    if parser_results.exploits:
        exploits = parser_results.exploits[0].strip().split(',')
        get_cves_for_exploits(exploits)
        exit()

    # If the user wants to perfom a manual search
    if parser_results.keyword: 
        # Get CVEs that are related with the query
        cve_times = []
        kw = parser_results.keyword[0].strip()
        related_cves = scraper.get_CVEs(kw, exact_match=parser_results.e)
        if related_cves:
            print(str(len(related_cves)) + " related CVEs found")
            construct_cpe_model(related_cves, kw, cve_times)
        else:
            print("Unable to retrieve any CVEs using the term: {}".format(parser_results.keyword[0]))

    else:

        # Let's validate the target IP
        # https://www.oreilly.com/library/view/regular-expressions-cookbook/9780596802837/ch07s16.html
        ip_regex = r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\/\d+)?$"
        validate = re.compile(ip_regex)
        
        ip = parser_results.target[0]
        if validate.match(ip) is None:
            parser.error("-t must be a valid IP or CIDR block")
        
        raw_nmap_results = launch_nmap(ip)
        results = process_nmap_out(raw_nmap_results)

        if results:

            for e in results:
                e = e.replace("(", "").replace(")", "")
                print("Querying vulnerability databases using the following terms")
                print(e.split(" "))
                
                itemize = [item for item in e.split(" ")]

                related_cves = None
                for i in reversed(range(1, len(itemize)+1)):
                    nvd_query = " ".join(itemize[0:i])
                    related_cves = scraper.get_CVEs(nvd_query, exact_match=parser_results.e)

                    if related_cves:
                        print("CVEs founds for query: {}".format(nvd_query))
                        break
                
                if related_cves:
                    print(str(len(related_cves)) + " related CVEs found")
                    construct_cpe_model(related_cves)
                else:
                    print("Unable to retrieve any CVEs using the terms")
                
                itemize.clear()
        else:
            print("NMAP was not able to find any open/filtered ports")
