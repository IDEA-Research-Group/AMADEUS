from cpe import CPE

# CPE Class does not provide a hash function by default
# We create a subclass and add this feature in order to 
# be able to use Sets and other data structures based
# on it.
# TODO: Review this
class HashableCPE(CPE):

    def __new__(cls, cpe_str, version=None, *args, **kwargs):

        hashableCPE = super().__new__(cls, cpe_str, version=version, *args, **kwargs)

        # --- CUSTOMIZATION ZONE ---
        # ** PROPERTIES **
        hashableCPE.rconfig = list()
        # ** METHODS **
        CPE.__hash__ = HashableCPE.__hash__
        CPE.get_attribute = HashableCPE.get_attribute
        CPE.get_rconfig = HashableCPE.get_rconfig
        CPE.set_rconfig = HashableCPE.set_rconfig
        CPE.add_rconfig = HashableCPE.add_rconfig
        # --- END OF ZONE ---

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
        elif name == 'target_hws':
            res = self.get_target_hardware()[0]
        elif name == 'other':
            res = self.get_other()[0] 
        
        return res

    def get_rconfig(self):
        return self.rconfig

    def set_rconfig(self, rconfig: list):
        self.rconfig = rconfig
    
    def add_rconfig(self, rconfig_i: int):
        self.rconfig.append(rconfig_i)

class RestrictionNode():
    
    def __init__(self, value: str, subNodes: list = list(), xorAttributeSubNodes: str = None, requirements: list = list()):
        
        self.value = value
        self.subNodes = subNodes
        self.xorAttributeSubNodes = xorAttributeSubNodes
        self.requirements = requirements

        self.isLeaf = True if xorAttributeSubNodes is None else False
