'''
    Implements Feature Model construction, using dynamic Serializers
    to allow other export formats
'''

__author__ = "Jose Antonio Carmona (joscarfom@alum.us.es)"

from collections import defaultdict

from .serializers import FamaSerializer
from .structures import RestrictionNode, HashableCPE
from ._aux import generate_mock_complex_CPEs, generate_mock_simple_CPEs

from scrapping.structures import CVE

###############################
###          T TREE         ###
###############################
def generate_tree(cve: CVE, semi_model: dict, semi_model_rc: list, direct_exploits: list, indirect_exploits: dict):

    '''
        Creates a fully well-formed feature model tree T representing all possible
        configurations given a list of CPEs (even the ones that are not affected) by
        a CVE.

        :param cve: CVE identifier object

        :param semi_model: A dictionary structure containing a semi-representation of the
        final FeatureModel, which must include all simple CPEs that are going to be analysed.

        :param semi_model_rc: A dictionary structure containing a semi-representation of the
        Running Configuration of the final FeatureModel, which must include all simple CPEs
        that are going to be analysed.

        :param direct_exploits: A list containing the exploits directly related to the CVE

        :param indirect_exploits: A dictionary with structure {cpe: [exploit]} containing exploits related to other vulnerabilities, that affect
        configurations also affected by this CVE
    '''

    # First, we need to check the arguments

    if not cve or type(cve) is not CVE:
        raise ValueError("cve must be a valid CVE object")

    if not isinstance(semi_model, dict):
        raise ValueError("semi_model must be a dictionary like structure containing a semi model")

    if type(semi_model_rc) is not list:
        raise ValueError("semi_model_rc must be a dictionary like structure containing a semi model for \
            running configurations")

    if not semi_model:
        print("[-] No semi_model was provided, skipping FM Tree generation")
        return None

    print("\n \t **** {} ****".format(cve.cve_id))

    fmSerializer = FamaSerializer(cve)

    processSemiModel([semi_model], fmSerializer, isRC=False)
    processSemiModel(semi_model_rc, fmSerializer, isRC=True)

    process_direct_exploits(direct_exploits, fmSerializer)
    process_indirect_exploits(indirect_exploits, semi_model, fmSerializer)

    # print("\n \t *** FEATURE MODEL *** \n")
    # print(fmSerializer.tree_get_model())
    
    fmSerializer.save_model(cve.cve_id)

# TODO: Change to FMSerializer abstract class
def processSemiModel(semi_model_container: list, fmSerializer: FamaSerializer, isRC:bool):
    
    s_cpes = set()

    # CPE fields
    # Used to have a registry of all the possible and different values
    # that every field can have (plus the possible running configurations on which
    # they can be executed)
    cpe_fields = (set(), set(), set(), set(), set(), set(), set(), set())
    cpe_fields_description = ('versions', 'updates', 'languages', 'sw_editions', 'target_sws', 'target_hws', 'others', 'rcs')

    if isRC:
        fmSerializer.tree_add_rcs_to_root(len(semi_model_container))

    for rc_i, semi_model in enumerate(semi_model_container):
        
        # First step to serialize is to indicate which vendors we are dealing
        # with. Further information will hang from vendor nodes.
        if isRC:
            fmSerializer.tree_add_vendors_to_rc(rc_i, semi_model.keys())
        else:
            fmSerializer.tree_add_vendors_to_root(semi_model.keys())
            rc_i = None

        # Iterate over all vendors
        for vendor, products in semi_model.items():

            # Indicate all the products a vendor has  
            fmSerializer.tree_add_products_to_vendor(vendor, products, rc_i)

            # Iterate over all products of a vendor
            for product, cpes in products.items():

                # Create actual CPE instances using its
                # 2.3 FS string representation.
                # Create a collection containing all CPE instances
                # of the current vendor+product
                if isRC:
                    for cpe in cpes:
                        s_cpes.add(HashableCPE(cpe))
                else:
                    for cpe, rcs in cpes.items():
                        h_cpe = HashableCPE(cpe)
                        h_cpe.rcs.extend(rcs)

                        s_cpes.add(h_cpe)
                
                # For each simple CPE, we analyse its attrs in order
                # to extract common features
                for s_cpe in s_cpes:
                    
                    cpe_fields[0].add(s_cpe.get_version()[0])
                    cpe_fields[1].add(s_cpe.get_update()[0])
                    cpe_fields[2].add(s_cpe.get_language()[0])
                    cpe_fields[3].add(s_cpe.get_software_edition()[0])
                    cpe_fields[4].add(s_cpe.get_target_software()[0])
                    cpe_fields[5].add(s_cpe.get_target_hardware()[0])
                    cpe_fields[6].add(s_cpe.get_other()[0])
                    cpe_fields[7].add(tuple(s_cpe.rcs))
                
                # When an attribute does not have any relevant information, the set only
                # contains a token representing all possible values ('*'). We empty sets
                # that only consists of a single '*'
                for field in cpe_fields[:-1]:

                    # There is also the case of 'Not Applicable', which in our context
                    # is exchangeable to any
                    if '-' in field:
                        field.remove('-')
                        field.add('*')

                    if len(field) == 1 and '*' in field:
                        field.clear()

                # Features that have been identified and their values are a must to have
                # in our Feature Model
                mandatory_features = []

                for i, field in enumerate(cpe_fields[:-1]):
                    if field:
                        mandatory_features.append(cpe_fields_description[i][:-1])
                        fmSerializer.tree_add_values_to_attribute(vendor, product, cpe_fields_description[i][:-1], field, rc=rc_i)
                                         

                if mandatory_features:
                    fmSerializer.tree_add_attributes_to_product(vendor, product, mandatory_features, rc=rc_i)
                    
                # In order to write optimized restrictions, we need to start with those fields that 
                # have the greater amount of values -> they provide better data segregation
                #
                # Instead of reordering the actual list, we make a new list consisting of the indexes and
                # apply the reordering to it.
                sortedFieldsIndexes = sorted(range(len(cpe_fields)-1), key=lambda x: len(cpe_fields[x]), reverse=True)
                sortedFieldsIndexes.append(len(cpe_fields)-1)

                # TODO: Add constraints to serializer and take into account the need to add 
                # constraints pointing to RCs even if 'constraints' is empty: CVE-2020-0833
                constraints = obtainConstraints(s_cpes, sortedFieldsIndexes, "[]", cpe_fields, cpe_fields_description)
                fmSerializer.tree_add_constraints(vendor, product, constraints)
                
                # Reset all accumulators for next product
                for field in cpe_fields:
                    field.clear()
                s_cpes.clear()

def process_direct_exploits(direct_exploits: list, fmSerializer: FamaSerializer):
    fmSerializer.tree_add_direct_exploits(direct_exploits)

def process_indirect_exploits(indirect_exploits: dict, semi_model: dict, fmSerializer: FamaSerializer):
    fmSerializer.tree_add_indirect_exploits(indirect_exploits, semi_model)

def obtainConstraints(cpeListing: list, sortedAttrListing: list, lastAttributeValue: str, cpe_fields: list, cpe_fields_description: list) -> RestrictionNode:
    
    '''
        Analyses a list of CPEs sharing common structure and creates a list of 
        necessary constraints in order to represent them as a Feature Model. This
        list of constraints are modeled using a recursive data structe.

        :param cpeListing: List of CPE sharing (at least) vendor and product

        :param sortedAttrListing: A sorted list containing the indexes of best attributes 
        to write restrictions 

        :param lastAttributeValue: The value of the last attribute used to write a XOR restriction

        :param cpe_fields: A list containing the different values of every CPE in cpeListing, grouped by 
        field

        :param cpe_fields_description: A list in which the i-th element is a string representing the name
        of the field of the i-th element in cpe_fields (that is, the name of the field that has the possible
        values found in cpe_fields[i])

    '''

    res = None

    if len(cpeListing) == 0:
        # Base Case 1: A filter that does not suit the current
        # CPE list has been applied
        return res
    
    elif len(cpeListing) == 1:
        # Base Case 2: A correct filter has been applied to the current CPE
        # list and has produced a single record.

        # Now we need to figure out which attributes need an explicit REQ relationship.
        # If an field only has one option from where to choose (i.e. target_sw=windows), there is
        # no need to make a REQ statament as it is the only option. Furthermore, by enforcing 
        # this restriction, we get rid of fields that does not have any value at all (* or -)
        requiredAttributes = list(filter(lambda x: len(cpe_fields[cpe_fields_description.index(cpe_fields_description[x])]) > 1, sortedAttrListing[:-1]))
        if cpe_fields[-1] and () not in cpe_fields[-1]:
            requiredAttributes.append(sortedAttrListing[-1])

        if requiredAttributes:

            cpe = cpeListing.pop()

            # We perform a substring operator ([:-1]) in order to get rid of the final 's' that every
            # descriptor has in the list "cpe_fields_description"
            #
            # Requirements will me modeled as a tuple (field_name, value). For example:
            #   ('language', 'fr')
            requirements = [(cpe_fields_description[x], cpe.get_attribute(cpe_fields_description[x][:-1])) for x in requiredAttributes]
            res = RestrictionNode(lastAttributeValue, requirements=requirements)
        
        return res
    
    best_attr = cpe_fields_description[sortedAttrListing.pop(0)]
    best_attr_values = cpe_fields[cpe_fields_description.index(best_attr)]

    subNodes = list()
    effectiveSubvalues = []

    for v in best_attr_values:
        
        # Get the list of CPE that match the value of the attribute
        remainingCpes = [x for x in cpeListing if x.get_attribute(best_attr[:-1]) == v]
        
        if len(remainingCpes) > 0:
            effectiveSubvalues.append(v)

        restrictionNode = obtainConstraints(remainingCpes, sortedAttrListing.copy(), v, cpe_fields, cpe_fields_description)
        if restrictionNode is not None:
            subNodes.append(restrictionNode)
    
    if subNodes:
        res = RestrictionNode(lastAttributeValue, subNodes=subNodes, xorAttributeSubNodes=best_attr)
    elif len(effectiveSubvalues) < len(best_attr_values):
        for v in effectiveSubvalues:
            subNodes.append(RestrictionNode(v, requirements=list()))
        res = RestrictionNode(lastAttributeValue, subNodes=subNodes, xorAttributeSubNodes=best_attr)

    return res
