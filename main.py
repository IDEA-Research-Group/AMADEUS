import threading
import time
import subprocess
import argparse
import re

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

def construct_cpe_model_for_cve(cve: CVE):
    semi_model, running_conf = scraper.get_CPEs(cve)
    generate_tree(cve, semi_model, running_conf)
    print("Wrote tree for " + cve.cve_id)
    time.sleep(5) # Wait until releasing worker to reduce load...?

def construct_cpe_model(related_cves):
    
    if related_cves:
        for cve in related_cves:
            construct_cpe_model_for_cve(cve)
        print("Finished")
        

if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument("-k", "--keyword", nargs=1, help="Keyword used to perform a manual CVE search on vulnerability databases")
    parser.add_argument("-e", action='store_true', help="If the results from databases must be an EXACT match of the keywords or just contain them")
    parser.add_argument("-a", action='store_true', help="Launches NMAP to perform an automatic search of vulnerabilities")
    parser.add_argument("-t", "--target", nargs=1, help="CIDR block or host target of the automatic analysis")
    parser_results = parser.parse_args()

    # Validate parser output
    if parser_results.a and parser_results.target is None:
        parser.error("-a requires -t to specify the target to which apply the analysis")

    if parser_results.target is not None and not parser_results.a:
        parser.error("-t requires -a to perform an automatic analysis")

    if parser_results.keyword is None and not parser_results.a:
        parser.error("You must enter either a keyword or launch an automatic search against a target IP")

    scraper = VulnerabilityScraper()

    # If the user wants to perfom a manual search
    if parser_results.keyword:
        # Get CVEs that are related with the query
        related_cves = scraper.get_CVEs(parser_results.keyword[0], exact_match=parser_results.e)
        if related_cves:
            print(str(len(related_cves)) + " related CVEs found")
            construct_cpe_model(related_cves)
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
