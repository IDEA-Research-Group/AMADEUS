from scrapping.data_retrieval import get_CVEs, get_CPEs
import time
from fm.fm import generate_tree

if __name__ == "__main__":

    # Ask the user for a keyword
    keyword = input("Enter a keyword to search releated vulnerabilities:")

    # Get CVEs that are related with the query
    b_base = time.time()
    related_cves = get_CVEs(keyword, exact_match=False)
    a_base = time.time()

    t_base = a_base - b_base

    perf_message = '''
    --------------------------------------------------------------
    |                                                            |
    |                          {}                                |
    |                                                            |
    |-- * Scrapping Time {:6.4f}                               ---
    |                                                            |
    |-- * Pre&Build Time {:6.4f}                               ---
    |                                                            |
    |-- * Constraint Time {:6.4f}                               ---
    |                                                            |
    |-- Sum of times vs Measured {:6.4f} vs {:6.4f} = {:6.4f}    |
    --------------------------------------------------------------
    '''

    if related_cves:
        
        for cve in related_cves[0]:
            b_s = time.time()
            semi_model, running_conf = get_CPEs(cve)
            a_s = time.time()

            t_b, t_c = generate_tree(cve, semi_model, running_conf)
            a_r = time.time()

            t_s = a_s-b_s+t_base
            t_sum = t_s + t_b + t_c
            t_r = a_r - b_s + t_base
            print(perf_message.format(cve, t_s,t_b,t_c, t_sum, t_r, t_r-t_sum))

            time.sleep(5)

