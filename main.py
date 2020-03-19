from scrapping.data_retrieval import get_CVEs, get_CPEs
import time
from fm.fm import generate_tree

if __name__ == "__main__":

    # Ask the user for a keyword
    keyword = input("Enter a keyword to search releated vulnerabilities:")

    # Get CVEs that are related with the query
    related_cves = get_CVEs(keyword, exact_match=True)

    if related_cves:
        
        for cve in related_cves[0]:
            semi_model, running_conf = get_CPEs(cve)
            generate_tree(cve, semi_model, running_conf)
            time.sleep(5)
