from scrapping.data_retrieval import get_CVEs, get_CPEs

if __name__ == "__main__":

    # Ask the user for a keyword
    keyword = input("Enter a keyword to search releated vulnerabilities:")

    related_cves = get_CVEs(keyword)

    for x in related_cves[0]:
        get_CPEs(x)

    print(list(related_cves[0]))
