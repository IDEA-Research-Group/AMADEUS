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

class CVE():
    
    def __init__(self, cve_id: str, vul_name: str = None, vul_description: str = None, sources: list = [], vuldb_id: str = None, configurations: list = [], cpeConfigurations: list = []):
        self.cve_id = cve_id
        self.vul_name = vul_name
        self.vul_description = vul_description
        self.vuldb_id = vuldb_id
        self.sources = sources
        self.configurations = configurations
        self.cpeConfigurations = cpeConfigurations

    def __hash__(self):
        return hash(self.cve_id)

    def __eq__(self, other):
        return isinstance(other, CVE) and self.cve_id == other.cve_id
    
    def __str__(self):
        return self.cve_id

    def __repr__(self):
        return str(self)

    def joinData(self, other):
        '''
        Takes attributes from a CVE with the same id, and adds them to the instance to get a more complete CVE object
        '''
        if not isinstance(other, CVE) and not isinstance(other, list):
            raise TypeError("other must be of type CVE or list")

        if isinstance(other, list):
            for o in other:
                self.__joinData(o)
        else:
            self.__joinData(other)

    def __joinData(self, otherCve):
        if otherCve.cve_id != self.cve_id:
            return
        if self.vul_name == None:
            self.vul_name = otherCve.vul_name
        if self.vul_description == None:
            self.vul_description = otherCve.vul_description
        if self.vuldb_id == None and otherCve.vuldb_id != None:
            self.vuldb_id = otherCve.vuldb_id

        self.configurations = list(set(self.configurations + otherCve.configurations))
        self.sources = list(set(self.sources + otherCve.sources))
        return self
    

class Exploit():
    
    ATTRIBUTES = ["id","description","type_id","platform_id","author_id","date_published",
                "verified","application_path","application_md5","port","tags","code","type","platform","author"]

    def __init__(self, json : dict):
        '''
        Takes a JSON Exploit object and creates an instance with the relevant attributes set.
        '''
        for k in json:
            if k not in Exploit.ATTRIBUTES:
                continue
            setattr(self, k, json[k])

        pass
