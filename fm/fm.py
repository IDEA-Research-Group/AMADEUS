'''
    Implements Feature Model construction, using dynamic Serializers
    to allow other export formats
'''

__author__ = "Jose Antonio Carmona (joscarfom@alum.us.es)"

from serializers import FamaSerializer
from structures import RestrictionNode
from collections import defaultdict
from aux import generate_mock_complex_CPEs, generate_mock_simple_CPEs

CVE = "CVE-2019-17573"

###############################
###          T TREE         ###
###############################
def generate_tree():

    '''
        Creates a fully well-formed feature model tree T representing all possible
        configurations given a list of CPEs (even the ones that are not affected) by
        a CVE
    '''

    fmSerializer = FamaSerializer(CVE)
    # TODO: Use real CPEs retrieved from NVD
    c_cpes = generate_mock_complex_CPEs()
    s_cpes = set()

    # CPE fields
    # Used to have a registry of all the possible and different values
    # that every field can have
    cpe_fields = (set(), set(), set(), set(), set(), set(), set(), set())
    cpe_fields_description = ('versions', 'updates', 'editions', 'languages', 'sw_editions', 'target_sws', 'target_hws', 'others')

    tree_head = defaultdict(lambda: defaultdict(set))

    # Final tree's top level structure will consist of the different Vendors
    # and Products found in the CPE listing. Instead of looping through the whole,
    # complete list of simple CPEs, we can retrieve this structure just by analysing
    # the list of complex CPEs (as they will have these fields for sure).
    #
    # We build an early tree that successfully classifies complex CPEs in vendor and 
    # products, making it easier to expand a specific set of CPEs into simple ones.
    for cpe in c_cpes:
        
        vendor = cpe.get_vendor()[0]
        product = cpe.get_product()[0]
        tree_head[vendor][product].add(cpe)

    fmSerializer.tree_add_vendors_to_root(tree_head.keys())

    # Iterate over all vendors
    for vendor, products in tree_head.items():

        fmSerializer.tree_add_products_to_vendor(vendor, products)

        # Iterate over all products of a vendor
        for product, c_cpes in products.items():

            # Iterate over all complex CPES of a vendor's product and
            # extract all simple CPEs to obtain the remaining attributes
            for c_cpe in c_cpes:
                s_cpes.update(generate_mock_simple_CPEs(c_cpe.cpe_str))
            
            # For each simple CPE, we analyse its attrs in order
            # to extract common features
            for s_cpe in s_cpes:
                
                cpe_fields[0].add(s_cpe.get_version()[0])
                cpe_fields[1].add(s_cpe.get_update()[0])
                cpe_fields[2].add(s_cpe.get_edition()[0])
                cpe_fields[3].add(s_cpe.get_language()[0])
                cpe_fields[4].add(s_cpe.get_software_edition()[0])
                cpe_fields[5].add(s_cpe.get_target_software()[0])
                cpe_fields[6].add(s_cpe.get_target_hardware()[0])
                cpe_fields[7].add(s_cpe.get_other()[0])
            
            # When an attribute does not have any relevant information, the set only
            # contains a token representing all possible values ('*'). We empty sets
            # that only consists of a single '*'
            for field in cpe_fields:
                if len(field) == 1 and '*' in field:
                    field.clear()

            mandatory_features = []

            for i, field in enumerate(cpe_fields):
                if field:
                    mandatory_features.append("{}-{}".format(product, cpe_fields_description[i]))
                    fmSerializer.tree_add_values_to_attribute(product, cpe_fields_description[i], field)                 

            if mandatory_features:
                fmSerializer.tree_add_attributes_to_product(product, mandatory_features)

            # In order to write optimized restrictions, we need to start with those fields that 
            # have the greater amount of values -> they provide better data segregation
            #
            # Instead of reordering the actual list, we make a new list consisting of the indexes and
            # apply the reordering to it.
            # TODO: Remove vendor and product attributes
            sortedFieldsIndexes = sorted(range(len(cpe_fields)), key=lambda x: len(cpe_fields[x]), reverse=True)

            # TODO: Add constraints to serializer
            constraints = obtainConstraints(s_cpes, sortedFieldsIndexes, "Miau", cpe_fields, cpe_fields_description)

            # Reset all accumulators for next product
            for field in cpe_fields:
                field.clear()
            s_cpes.clear()

    print(fmSerializer.tree_get_model())

def obtainConstraints(cpeListing: list, sortedAttrListing: list, lastAttributeValue: str, cpe_fields: list, cpe_fields_description: list):
    
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
        requiredAttributes = list(filter(lambda x: len(cpe_fields[cpe_fields_description.index(cpe_fields_description[x])]) > 1, sortedAttrListing))

        if requiredAttributes:

            cpe = cpeListing.pop()

            # We perform a substring operator ([:-1]) in order to get rid of the final 's' that every
            # descriptor has in the list "cpe_fields_description"
            #
            # Requirements will me modeled as a tuple (field_name, value). For example:
            #   ('language', 'fr')
            requirements = [(cpe_fields_description[x], cpe.get_attribute(cpe_fields_description[x][:-1])) for x in requiredAttributes]

            res = RestrictionNode(lastAttributeValue,requirements=requirements)

        else:
            res = RestrictionNode(lastAttributeValue)
        
        return res
    
    best_attr = cpe_fields_description[sortedAttrListing.pop(0)]
    best_attr_values = cpe_fields[cpe_fields_description.index(best_attr)]

    subNodes = list()

    for v in best_attr_values:
        
        # Get the list of CPE that match the value of the attribute
        remainingCpes = [x for x in cpeListing if x.get_attribute(best_attr[:-1]) == v]
        restrictionNode = obtainConstraints(remainingCpes, sortedAttrListing.copy(), v, cpe_fields, cpe_fields_description)
        subNodes.append(restrictionNode)
    
    res = RestrictionNode(lastAttributeValue, subNodes=subNodes, xorAttributeSubNodes=best_attr)

    return res

if __name__ == "__main__":
    generate_tree()
