'''
    Adaptation of JavaScript code used to generate a list of CPEs from a JSON
    representation. Original code:

    https://nvd.nist.gov/NVD/Media/js/vulnerability/cpeListing.js
'''

__author__ = "Jose Antonio Carmona (joscarfom@alum.us.es)"

from collections import defaultdict
from enum import Enum

from cpe import CPE


class ConfigType(Enum):
    
    '''
        Different types of a Configuration
        defined by NVD
    '''

    BASIC = "BASIC"
    RUNNING_ON = "RUNNING_ON"
    ADVANCED = "ADVANCED"

class CpeListType(Enum):

    '''
        Different types of CPE Lists
        defined by NVD.

        A NON_VULNERABLE list usually contains related CPEs that
        are not directly vulnerable, but a necessary dependency for
        a vulnerable CPE to work. i.e. a Running Configuration.
    '''

    VULNERABLE = "VULNERABLE"
    NON_VULNERABLE = "NON_VULNERABLE"

def extract_semimodel(json: dict) -> tuple(dict, list):

    '''
        Creates an intermediate representation between a JSON file 
        containing the CPEs of a given CVE and its Feature Model.

        Generates a dictionary and a list, containing:
            \t (dict) cpes: Dictionary containing the different CPEs (str) of a CVE
            and a reference to their running configurations, grouped by vendor
            and product.

            \t (list) running_configurations: List containing the different running configurations
            a group of CPEs may have, expressed as CPEs (str) and grouped by vendor and product
        
        :param json: Parsed JSON Object containing information about the CPEs of
        a given vulnerability
    '''

    # First, we need to check the arguments

    if not json or type(json) is not list:
        raise ValueError("json must be a non-empty Parsed list contaning JSON Objects")

    cpes = defaultdict(lambda: defaultdict(lambda: defaultdict(list)))
    running_configs = list()
    rc_count = -1

    # Outer structure wraps different Configurations
    for config in json:
        
        simple_cpes = list()
        running_on = None

        print("Configuration {}: {}".format(config["id"], config["dataTestId"]))

        # Each configuration comes with a single Container with further
        # information about it. After some analysis, no more than one
        # Container has been found for the same configuration. However, we
        # still iterate over this attribute just in case.
        for container in config["containers"]:

            # Identify which type of configuration we 
            # are dealing with

            # CONFIGURATION = BASIC
            if container["configType"] == ConfigType.BASIC.name:
                print("[-] Detected Configuration Type: BASIC")
                simple_cpes = process_basic_configuration(container)

            # CONFIGURATION = RUNNING_ON
            elif container["configType"] == ConfigType.RUNNING_ON.name:
                print("[-] Detected Configuration Type: RUNNING_ON")
                simple_cpes, running_on = process_running_on_configuration(container)
                rc_count += 1
                running_configs.append(running_on)

            # CONFIGURATION = ADVANCED
            else:
                print("[-] Detected Configuration Type: ADVANCED")
                simple_cpes = process_advanced_configuration(container)

        # Append results to dictionary
        for vendor, products in simple_cpes.items():
            # Iterate over all products of a vendor
            for product, s_cpes in products.items():

                # Iterate over all new CPEs
                for cpe in s_cpes:

                    # This line retrieves the specific CPE if exists
                    # and creates a new entry if it doesn't
                    res_cpe = cpes[vendor][product][cpe]

                    if container["configType"] == ConfigType.RUNNING_ON.name:
                        res_cpe.append(rc_count)
                        
    return cpes, running_configs

def process_basic_configuration(container: dict) -> dict:
    '''
        Extracts, expands and conditionally expand the CPEs records
        of a Configuration Container of type BASIC.
        
        :param container: A valid container wrapping information
        about a configuration
    '''

    # First, we need to check the arguments

    if not container or type(container) is not dict:
        raise ValueError("container must be a non-empty Parsed JSON Object")

    if container["configType"] != ConfigType.BASIC.name or container['cpes'] is None:
        raise ValueError("container must be a valid structure of type: {} ".format(ConfigType.BASIC.name))

    res = defaultdict(lambda: defaultdict(set))

    for complex_cpe in container['cpes']:
        aux = CPE(complex_cpe['cpe23Uri'])
        res[aux.get_vendor()[0]][aux.get_product()[0]].update(expand(complex_cpe))
    
    return res

def process_running_on_configuration(container: dict) -> tuple(dict, dict):

    '''
        Extracts, expands and conditionally expand the CPEs records
        of a Configuration Container of type RUNNING_ON. Generates two
        lists, one containing the affected CPEs and the other the 
        platforms/execution environment on which they must run.
        
        :param container: A valid container wrapping information
        about a configuration
    '''

    # First, we need to check the arguments
    
    if not container or type(container) is not dict:
        raise ValueError("container must be a non-empty Parsed JSON Object")

    if container["configType"] != ConfigType.RUNNING_ON.name or container['containers'] is None:
        raise ValueError("container must be a valid structure of type: {} ".format(ConfigType.RUNNING_ON.name))

    simple_cpes = defaultdict(lambda: defaultdict(set))
    running_on = defaultdict(lambda: defaultdict(set))

    for subcontainer in container['containers']:

        if subcontainer['cpeListType'] == "VULNERABLE":
            
            for complex_cpe in subcontainer['cpes']:
                aux = CPE(complex_cpe['cpe23Uri'])
                simple_cpes[aux.get_vendor()[0]][aux.get_product()[0]].update(expand(complex_cpe))

        else:
            
            # NON_VULNERABLE
            for complex_cpe in subcontainer['cpes']:
                aux = CPE(complex_cpe['cpe23Uri'])
                running_on[aux.get_vendor()[0]][aux.get_product()[0]].update(expand(complex_cpe))

    return simple_cpes, running_on

def process_advanced_configuration(container: dict) -> dict:

    '''
        Extracts, expands and conditionally expand the CPEs records
        of a Configuration Container of type ADVANCED.

        ADVANCED containers usually store information recursively,
        so we need to iterate over all the underlying containers
        to extract all CPEs. 
        
        :param container: A valid container wrapping information
        about a configuration
    '''

    # First, we need to check the arguments
    
    if not container or type(container) is not dict:
        raise ValueError("container must be a non-empty Parsed JSON Object")

    if container["configType"] != ConfigType.ADVANCED.name or container['containers'] is None:
       raise ValueError("container must be a valid structure of type: {} ".format(ConfigType.ADVANCED.name))

    res = defaultdict(lambda: defaultdict(set))

    for subcontainer in container['containers']:
        res.update(process_advanced_configuration(subcontainer))
    
    for complex_cpe in container['cpes']:
        aux = CPE(complex_cpe['cpe23Uri'])
        res[aux.get_vendor()[0]][aux.get_product()[0]].update(expand(complex_cpe))
    
    return res

def expand(complex_cpe: dict) -> dict:

    '''
        Expands and conditionally expands a complex CPE in order to obtain
        simple and up-to-date CPEs.
        
        :param container: A valid dictionary-like representation
        of a complex CPE
    '''

    # First, we need to check the arguments
    
    if not complex_cpe or type(complex_cpe) is not dict:
        raise ValueError("complex_cpe must be a non-empty Parsed JSON Object")

    if complex_cpe["rangeCpes"] is None and complex_cpe["matchCpes"] is None:
       raise ValueError("container must be a valid structure of type: {} ".format(ConfigType.ADVANCED.name))
    
    res = list()

    isExpansionByRange = True if complex_cpe['rangeDescription'] else False
    simple_cpes = complex_cpe["rangeCpes"] if isExpansionByRange else complex_cpe["matchCpes"]
        
    if simple_cpes:
        for cpeItem in simple_cpes:

            if cpeItem["status"] == "DEPRECATED":

                print("[-] Deprecated CPE detected ({}). Substituting...".format(cpeItem["cpe23Uri"]))

                for updated_cpe in cpeItem["resultingCpes"]:
                    res.append(updated_cpe["cpe23Uri"].replace(':-', ':*'))
            else:
                res.append(cpeItem["cpe23Uri"].replace(':-', ':*'))
    else:
        res.append(complex_cpe["cpe23Uri"].replace(':-', ':*'))
    
    return res
