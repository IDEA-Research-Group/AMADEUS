'''
    Adaptation of JavaScript code used to generate a list of CPEs from a JSON
    representation. Original code:

    https://nvd.nist.gov/NVD/Media/js/vulnerability/cpeListing.js
'''

__author__ = "Jose Antonio Carmona (joscarfom@alum.us.es)"

from cpe import CPE
from enum import Enum

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

def extract_semimodel(json: dict) -> dict:

    '''
        Creates an intermediate representation between a JSON file 
        containing the CPEs of a given CVE and its Feature Model.

        Generates a dictionary containing:
            \t "CPEs": A list of the different CPEs grouped by Configuration

            \t "RUNNING_ON": A list of the different Running Enviroments 
            \t grouped by Configuration
        
        :param json: Parsed JSON Object containing information about the CPEs of
        a given vulnerability
    '''

    # First, we need to check the arguments

    if not json or type(json) is not dict:
        raise ValueError("json must be a non-empty Parsed JSON Object")

    res = {
        "CPEs": [],
        "RUNNING_ON": []
    }

    # Outer structure wraps different Configurations
    for config in json:
        
        simple_cpes = list()
        running_on = None

        print("Configuration {}: {}".format(config["ID"], config["DataTestId"]))

        # Each configuration comes with a single Container with further
        # information about it. After some analysis, no more than one
        # Container has been found for the same configuration. However, we
        # still iterate over this attribute just in case.
        for container in config["Containers"]:

            # Identify which type of configuration we 
            # are dealing with

            # CONFIGURATION = BASIC
            if container["ConfigType"] == ConfigType.BASIC.name:
                print("[-] Detected Configuration Type: BASIC")
                simple_cpes = process_basic_configuration(container)

            # CONFIGURATION = RUNNING_ON
            elif container["ConfigType"] == ConfigType.RUNNING_ON.name:
                print("[-] Detected Configuration Type: RUNNING_ON")
                simple_cpes, running_on = process_running_on_configuration(container)
            
            # CONFIGURATION = ADVANCED
            else:
                print("[-] Detected Configuration Type: ADVANCED")
                simple_cpes = process_advanced_configuration(container)

        # Append results to dictionary
        res['CPEs'].append(simple_cpes)
        res['RUNNING_ON'].append(running_on)

    return res

def process_basic_configuration(container: dict) -> list:
    '''
        Extracts, expands and conditionally expand the CPEs records
        of a Configuration Container of type BASIC.
        
        :param container: A valid container wrapping information
        about a configuration
    '''

    # First, we need to check the arguments

    if not container or type(container) is not dict:
        raise ValueError("container must be a non-empty Parsed JSON Object")

    if container["ConfigType"] != ConfigType.BASIC.name or container['Cpes'] is None:
        raise ValueError("container must be a valid structure of type: {} ".format(ConfigType.BASIC.name))

    res = list()

    for complex_cpe in container['Cpes']:
        res.append(expand(complex_cpe))
    
    return res

def process_running_on_configuration(container: dict) -> (list, list):

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

    if container["ConfigType"] != ConfigType.RUNNING_ON.name or container['Containers'] is None:
        raise ValueError("container must be a valid structure of type: {} ".format(ConfigType.RUNNING_ON.name))

    simple_cpes = list()
    running_on = list()

    for subcontainer in container['Containers']:

        if subcontainer['CpeListType'] == "VULNERABLE":
            
            for complex_cpe in subcontainer['Cpes']:
                simple_cpes.append(expand(complex_cpe))

        else:
            
            # NON_VULNERABLE
            for complex_cpe in subcontainer['Cpes']:
                running_on.append(expand(complex_cpe))

    return simple_cpes, running_on

def process_advanced_configuration(container: dict) -> list:

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

    if container["ConfigType"] != ConfigType.ADVANCED.name or container['Containers'] is None:
       raise ValueError("container must be a valid structure of type: {} ".format(ConfigType.ADVANCED.name))

    res = list()

    for subcontainer in container['Containers']:
        res.append(process_advanced_configuration(subcontainer))
    
    for complex_cpe in container['Cpes']:
        res.append(expand(complex_cpe))
    
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

    if complex_cpe["RangeCpes"] is None and complex_cpe["MatchCpes"] is None:
       raise ValueError("container must be a valid structure of type: {} ".format(ConfigType.ADVANCED.name))
    
    res = list()

    isExpansionByRange = True if complex_cpe['RangeDescription'] else False
    simple_cpes = complex_cpe["RangeCpes"] if isExpansionByRange else complex_cpe["MatchCpes"]

    for cpeItem in simple_cpes:

        if cpeItem["Status"] == "DEPRECATED":

            print("[-] Deprecated CPE detected ({}). Substituting...".format(cpeItem["Uri"]))

            for updated_cpe in cpeItem["ResultingCpes"]:
                res.append(CPE(updated_cpe["Uri"]))
        else:
            res.append(CPE(cpeItem["Uri"]))
    
    return res
