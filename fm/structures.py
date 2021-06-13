__author__ = "Jose Antonio Carmona (joscarfom@alum.us.es)"

from cpe import CPE


# CPE Class does not provide a hash function by default
# We create a subclass and add this feature in order to 
# be able to use Sets and other data structures based
# on it.
# TODO: Review this
class HashableCPE(CPE):

    '''
        CPE subclass that provides extended features not found in the
        original module:

            * Hash function based on the CPE URI (useful when
            creating sets or other similar datatypes)

            * Generic getter based on attribute names 
    '''

    def __new__(cls, cpe_str, version=None, *args, **kwargs):

        hashableCPE = super().__new__(cls, cpe_str, version=version, *args, **kwargs)

        # Customization zone
        CPE.__hash__ = HashableCPE.__hash__
        CPE.get_attribute = HashableCPE.get_attribute
        hashableCPE.rcs = list()

        return hashableCPE

    def __hash__(self):
        return hash(self.cpe_str)
    
    def get_attribute(self, name: str) -> str:

        res = None

        if name == 'version':
            res = self.get_version()[0]
        elif name == 'update':
            res = self.get_update()[0]
        elif name == 'edition':
            res = self.get_edition()[0]
        elif name == 'language':
            res = self.get_language()[0]
        elif name == 'sw_edition':
            res = self.get_software_edition()[0]
        elif name == 'target_sw':
            res = self.get_target_software()[0]
        elif name == 'target_hw':
            res = self.get_target_hardware()[0]
        elif name == 'other':
            res = self.get_other()[0]
        elif name == 'rc':
            res = tuple(self.rcs) 
        
        return res

class RestrictionNode():

    '''
        Recursive data structure that models the different restrictions found on an
        advanced FeatureModel, using a tree-like approach. 
    '''
    
    def __init__(self, value: str, subNodes: list = list(), xorAttributeSubNodes: str = None, requirements: list = list()):
        
        '''
            :param value: The value required for a feature to have. Root node's value is not important.

            :param subNodes: More specific subrestrictions

            :param xorAttributeSubNodes: Attribute to which to apply an XOR selection

            :param requirements: AND restrictions

        '''

        self.value = value
        self.subNodes = subNodes
        self.xorAttributeSubNodes = xorAttributeSubNodes
        self.requirements = requirements

        self.isLeaf = True if xorAttributeSubNodes is None else False
