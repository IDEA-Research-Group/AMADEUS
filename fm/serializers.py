
'''
    Different serializers that can be used to export a given FeatureModel
    to different formats.
'''

__author__ = "Jose Antonio Carmona (joscarfom@alum.us.es)"


import os
import re
from collections.abc import Iterable
from typing import Union

from scrapping.structures import CVE, HashableCPE

from .structures import RestrictionNode

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODELS_FOLDER = "models"
EXPORT_PATH = os.path.join(BASE_DIR, MODELS_FOLDER)

class FamaSerializer:

    '''
        Class that creates a Feature Model file following the notations used in
        FaMa Framework
    '''

    COMMENT_CHARACTER = "# "
    LINE_TERMINATOR = ";\n"
    RUNNING_CONFIG_NODE_NAME = "configs"
    RUNNING_CONFIG_PREFIX = "rc{}"

    CVE_SOURCES_NODE_NAME = "sources"
    CVE_CONFIGURATIONS_NODE_NAME = "types"
    CVE_VULDB_ID_NODE_NAME = "vuldb_id"
    CVE_VUL_NAME_NODE_NAME = "vul_name"
    CVE_VUL_DESC_NODE_NAME = "vul_description"
    CVE_EXPLOIT_NODE_NAME = "exploits"
    CVE_EXPLOIT_DIRECT_NODE_NAME = "direct"
    CVE_EXPLOIT_INDIRECT_NODE_NAME = "indirect"

    def __init__(self, cve: CVE):
        
        # First, we need to check the arguments

        if not cve or type(cve) is not CVE:
            raise ValueError("CVE must be a valid CVE object")

        # A Feature Model contains info about a single CVE
        self.CVE = cve

        # Restrictions
        self.restrictions = ""
        
        # Different sections of a Feature Model file
        self.comments = ""
        self.root = self.CVE.cve_id + ":"
        self.cve_attributes = ""
        self.tree_add_CVE_attributes_to_root()

        self.root += self.add_mandatory(self.CVE_EXPLOIT_NODE_NAME) + " "
        self.exploits = "{}: [{}] [{}]".format(self.CVE_EXPLOIT_NODE_NAME, self.CVE_EXPLOIT_DIRECT_NODE_NAME, self.CVE_EXPLOIT_INDIRECT_NODE_NAME)
        self.direct_exploits_ids = ""
        self.direct_exploits = ""
        self.indirect_exploits = ""
        #self.indirect_exploits = ""
        self.rcs = ""
        self.vendors = ""
        self.vendors_products = ""
        self.product_attributes = ""
        
        


    ### SECTION
    ### Methods to add content to the different sections of a Feature Model file
    def tree_add_rcs_to_root(self, num_of_configs:int) -> None:

        if num_of_configs > 0:
            # Line Terminator is not appended until the very end, to make the addition of new
            # root children nodes possible
            self.root += ' ' + self.add_optional(self.RUNNING_CONFIG_NODE_NAME)

            self.rcs += "{}: ".format(self.RUNNING_CONFIG_NODE_NAME) + \
                self.add_XOR([self.RUNNING_CONFIG_PREFIX.format(i) for i in range(num_of_configs)]) + \
                self.LINE_TERMINATOR

    def tree_add_direct_exploits(self, exploits: list) -> None:
        if len(exploits) > 0:
            if len(self.direct_exploits_ids) == 0:
                self.direct_exploits_ids += "direct: "
            if len(exploits) > 1:
                self.direct_exploits_ids += self.add_OR(("exploit_" + exploit.id for exploit in exploits))
            else:
                self.direct_exploits_ids += self.add_mandatory(("exploit_" + exploit.id for exploit in exploits))

    def tree_add_indirect_exploits(self, exploits: dict, semi_model: dict) -> None:
        '''
        :param exploits Should be a dict with the following structure {cpe string:  list of relevant exploits}
        '''
        cpesWithExploits = [cpe for cpe in exploits if len(exploits[cpe]) > 0]
        if len(cpesWithExploits) == 0:
            return
        if len(self.indirect_exploits) == 0:
            self.indirect_exploits += "indirect: "

        indirectExploitIds = set()
        
        for cpe in exploits:
            exploitIds = [expl.id for expl in exploits[cpe]]
            for eid in exploitIds:
                indirectExploitIds.add("exploit-" + eid)
                cpeObj = HashableCPE(cpe)
                # Gets correct product value from cpe and semimodel. 
                # Fixes discrepancies in naming of some products
                # For example, thunderbird_esr appears as thunderbird in the semimodel,
                # so we detect those discrepancies and use the correct name
                for vendor in semi_model:
                    for product in semi_model[vendor]:
                        for c in semi_model[vendor][product]:
                            if cpe == c and cpeObj.get_product()[0] != product:
                                cpe = cpe.replace(cpeObj.get_product()[0], product)
                                cpeObj = HashableCPE(cpe)
                                break
                self.tree_add_constraints('exploit',eid,RestrictionNode(eid, requirements=[('exploit',cpeObj)]))
        
        self.indirect_exploits += self.add_OR(indirectExploitIds) + self.LINE_TERMINATOR

    def tree_add_vendors_to_rc(self, rc:int, vendors: Union[Iterable, object]) -> None:
        fs = self.RUNNING_CONFIG_PREFIX + "-{}"
        formatted_vendors = [fs.format(rc, k) for k in vendors]
        
        self.rcs += self.RUNNING_CONFIG_PREFIX.format(rc) + ': ' + \
            self.add_XOR(formatted_vendors) + self.LINE_TERMINATOR

    def tree_add_vendors_to_root(self, vendors: Union[Iterable, object]) -> None:
        self.__tree_add_vendors_to_root(vendors)

    def tree_add_CVE_attributes_to_root(self) -> None:
        self.root += self.add_mandatory(self.CVE_CONFIGURATIONS_NODE_NAME)
        self.root += self.add_mandatory(self.CVE_SOURCES_NODE_NAME)
        setTypes = set([x[1].lower().replace(" ", "_") for x in self.CVE.configurations])
        self.cve_attributes += self.CVE_CONFIGURATIONS_NODE_NAME + ": " \
                            + self.add_mandatory(setTypes) \
                            + self.LINE_TERMINATOR
        self.cve_attributes += self.CVE_SOURCES_NODE_NAME + ": " + self.add_mandatory(self.CVE.sources) + self.LINE_TERMINATOR

        # Add configuration constraints
        for x in self.CVE.configurations:
            self.tree_add_constraints(x[0].get_vendor()[0],x[0].get_product()[0],RestrictionNode(x[0].get_product()[0], requirements=[('type',x[1].lower().replace(" ", "_") )]))

        if self.CVE.vul_name:
            self.comments += self.COMMENT_CHARACTER + self.CVE_VUL_NAME_NODE_NAME + ": " + self.CVE.vul_name + "\n\n"
        if self.CVE.vul_description:
            self.comments += self.COMMENT_CHARACTER + self.CVE_VUL_DESC_NODE_NAME + ": " + self.CVE.vul_description + "\n\n"
        if self.CVE.vuldb_id:
            self.root += " " + self.add_optional(self.CVE_VULDB_ID_NODE_NAME)
            self.cve_attributes += self.CVE_VULDB_ID_NODE_NAME + ":" + self.add_mandatory(self.CVE.vuldb_id) + self.LINE_TERMINATOR
        

    def tree_add_products_to_vendor(self, vendor, products: Union[Iterable, object], rc:int = None) -> None:
        prefix =  "" if rc is None else self.RUNNING_CONFIG_PREFIX.format(rc) + "-"

        formatted_vendor = prefix + vendor
        formatted_products = ["{}{}-{}".format(prefix, vendor, k) for k in products]

        self.__tree_add_products_to_vendor(formatted_vendor, formatted_products)

    def tree_add_attributes_to_product(self, vendor:str, product: str, attributes: Union[Iterable, object], rc:int = None) -> None:
        prefix =  "" if rc is None else self.RUNNING_CONFIG_PREFIX.format(rc) + "-"
        
        formatted_attributes = ["{}{}-{}-{}".format(prefix, vendor, product, k) for k in attributes]
        formatted_product = prefix + vendor + "-" + product

        self.__tree_add_attributes_to_product(formatted_product, formatted_attributes)

    def tree_add_values_to_attribute(self, vendor:str, product: str, attribute:str, values: Union[Iterable, object], rc:int = None) -> None:
        prefix =  "" if rc is None else self.RUNNING_CONFIG_PREFIX.format(rc) + "-"

        formatted_values = ["{}{}-{}-{}-{}".format(prefix, vendor, product, attribute, k) for k in values]
        formatted_attribute = "{}{}-{}-{}".format(prefix, vendor, product, attribute)

        self.__tree_add_values_to_attribute(formatted_attribute, formatted_values)
    
    def tree_add_constraints(self, vendor:str, product: str, restrictionNode:RestrictionNode) -> None:
        r = self.serialize_constraints(vendor, product, restrictionNode, 0)
        if r != "" and r not in self.restrictions:
            self.restrictions +=  r + self.LINE_TERMINATOR

    def unroll_xor(self, alternatives: Union[str, Iterable]) -> str:
        '''
        Transforms a XOR expression to an IMPLIES-like normal form

        Example: `A XOR B XOR C -> (A AND NOT B AND NOT C) OR (NOT A AND B AND NOT C) OR (NOT A AND NOT B AND C)`
        '''
        unrolled = list()
        for i in range(len(alternatives)):
            temp = list()
            for j, alt in enumerate(alternatives):
                if i != j:
                    temp.append("NOT " + alt)
                else:
                    temp.append(alt)
            unrolled.append('(' + ' AND '.join(temp) + ')')

        if len(unrolled) > 1:
            return '(' + ' OR '.join(unrolled) + ')'
        else:
            return unrolled[0]

    def serialize_constraints(self, vendor:str, product: str, restrictionNode:RestrictionNode, depth:int) -> str:
        
        res = ''

        vendorSanit = self.sanitize_out_string(vendor)
        productSanit = self.sanitize_out_string(product)

        if restrictionNode:

            # The value of the precedent requirement, or the product if depth = 0 
            if depth > 0:
                super_value = restrictionNode.value
                if super_value == '*':
                    super_value = "any"
                else:
                    super_value = super_value.replace(".","_")
                    super_value = self.sanitize_out_string(super_value, ignoreStartingWithNumber=True)
            else:
                super_value = self.sanitize(productSanit)
                for char in super_value:
                    if char.isdigit():
                        pos = super_value.index(char)
                        super_value = super_value[0:pos] + super_value[pos:].replace("_","__")
                        break
            

            if restrictionNode.isLeaf:
                
                # BASE CASE

                VALUE_REQ_CONNECTOR = ' REQUIRES ' if depth <= 1 else ' AND '
                VALUE_IMPL_CONNECTOR = ' IMPLIES ' if depth <= 1 else ' AND '
                
                aux = list()
                need_brackets = False
                needs_implies = False

                for (attr, val) in restrictionNode.requirements:
                    
                    if attr == 'rcs':
                        # Generate requirements for the running configurations
                       # rcs = ' XOR '.join([self.RUNNING_CONFIG_PREFIX.format(k) for k in val])
                        rcs = self.unroll_xor([self.RUNNING_CONFIG_PREFIX.format(k) for k in val])
                        needs_implies = True

                        # We add brackets if there are more than one rc, to create a logical group
                        # if len(val) > 1:
                        #     rcs = '(' + rcs + ')'
                        # else:
                        #     need_brackets = True
                        
                        aux.append(rcs)
                    elif attr == 'exploit':
                        # aux.append("{}_{}_{}_{}".format(val.get_vendor()[0],val.get_product()[0],'version',self.sanitize(val.get_version()[0])))
                        aux.append("{}_{}_{}_{}".format(vendorSanit, productSanit,'version',self.sanitize(self.sanitize_out_string(val.get_version()[0], ignoreStartingWithNumber=True))))
                    elif attr == 'type':
                        aux.append(val)
                    else:
                        # Generate requirements for the rest of attributes (standard attr)
                        sanitVal = val if val == '*' else self.sanitize_out_string(val)
                        if sanitVal.__contains__("_"):
                            sanitVal = sanitVal[1:]
                            sanitVal = sanitVal.replace("_","__")
                        aux.append("{}_{}_{}_{}".format(vendorSanit, productSanit, self.sanitize_out_string(attr[:-1]), sanitVal))
                        need_brackets = True

                need_brackets = depth <= 1 and need_brackets
                
                res = ' AND '.join(aux)

                # if need_brackets:
                #     res = '(' + res + ')'

                if len(restrictionNode.requirements):
                    if needs_implies:
                        res = super_value + VALUE_IMPL_CONNECTOR + res
                    else:
                        #if VALUE_REQ_CONNECTOR == ' REQUIRES ' and 'AND' in res:

                        res = super_value + VALUE_REQ_CONNECTOR + res
                elif depth > 0:
                    res = super_value
                if depth == 0:
                    res = vendorSanit + "_" + res

                return res

            else:

                split_attr = self.sanitize_out_string(restrictionNode.xorAttributeSubNodes[:-1])
                aux = list()
                
                for sn in restrictionNode.subNodes:
                    if len(sn.requirements) == 0:
                        # Explore all the subnodes recursively
                        aux.append('{}_{}_{}_'.format(vendorSanit, productSanit, split_attr) + self.serialize_constraints(vendor, product, sn, depth=depth+1))
                    else:
                        for req in sn.requirements:
                            newnode = RestrictionNode(sn.value,sn.subNodes,sn.xorAttributeSubNodes,[req])
                            # Explore all the subnodes recursively
                            aux.append('{}_{}_{}_'.format(vendorSanit, productSanit, split_attr) + self.serialize_constraints(vendor, product, newnode, depth=depth+1))

                    

                if depth == 0:
                    res = self.LINE_TERMINATOR.join(self.sanitize(k) for k in aux) 
                elif depth == 1:

                    res = super_value
                    # TODO Validate that this xor unrolling works
                    '''
                    for i, e in enumerate(aux):
                        if i == 0:
                            res += ' REQUIRES ' + '(' + '(' * ("AND" in e) 
                        if i < (len(aux) - 1) :
                            res += e + ')' * ("AND" in e) + ' XOR ' + '(' * ("AND" in aux[i+1])
                        else:
                            res += e
                            res += ')' + ')' * ("AND" in e)
                    '''
                    res += " IMPLIES " + self.unroll_xor(aux)
                else:
                    #res = ' XOR '.join(aux)
                    res = self.unroll_xor(aux)

                return res

        return res    

    def __tree_add_vendors_to_root(self, vendors: Union[Iterable, object]) -> None:
        # Line Terminator is not appended until the very end, to make the addition of new
        # root children nodes possible
        self.root += self.add_XOR(vendors)

    def __tree_add_products_to_vendor(self, vendor, products: Union[Iterable, object]) -> None:
        self.vendors += vendor + ": " + self.add_XOR(products) + self.LINE_TERMINATOR
    
    def __tree_add_attributes_to_product(self, product: str, attributes: Union[Iterable, object]) -> None:
        self.vendors_products += product + ": " + self.add_mandatory(attributes) + self.LINE_TERMINATOR

    def __tree_add_values_to_attribute(self, attribute:str, values: Union[Iterable, object]) -> None:
        self.product_attributes += attribute + ": " + self.add_XOR(values) + self.LINE_TERMINATOR
    ### END OF SECTION

    def sanitize(self, toSanitize: Union[str, Iterable], replacers:tuple=(('.', '_'),('*','any'))) -> Union[str, Iterable]:
            
        '''
            Sanitizes retrieved content so as to avoid invalid characters in FaMa
            (dots and labels starting with numbers)

            :param toSanitize: String or Iterable containing strings that are intended 
            to be sanitized

            :param replacers: Tuple containing pairs which first item is the special character to replace
            and the second the new expression.
        '''

        if type(toSanitize) is str:
            
            starts_with_number_regex = re.compile(r"^\d")
            res = toSanitize

            # Check whether the string starts with a number or not
            #if starts_with_number_regex.match(res):
            #    res = num_prefix + res
            
            for t in replacers:
                res = res.replace(t[0], t[1])

        elif isinstance(toSanitize, Iterable):
            res = [self.sanitize(x) for x in toSanitize]
        else:
            raise ValueError("Input should be either a string or an Iterable")

        return res

    def sanitize_out_string(self, string, ignoreStartingWithNumber = False):
        '''
        Sanitizes a string and makes it FM tree ready
        '''
        # TODO Sanitize CVE-2018-0579 and CVE-2019-14682
        # Replace underscore with DOUBLE underscore (fixes CVEs such as CVE_2014_7958)
        string = string.replace('_','__')
        # Remove illegal characters. Also remove commas that aren't part of [1,1] relationships, or colons that aren't followed by space
        string = re.sub(r'[^A-z0-9\[\]{},:;\n ]|\\|(,(?!1\]))|(:(?! ))', '_', string)
        # Check string doesnt start with number (fixes CVEs such as CVE_2014_3882)
        if not ignoreStartingWithNumber and re.match(r'^[0-9]', string):
            string = "_" + string
        # Check nodes starting with number
        string = re.sub(r' (?=[0-9])', ' _', string)
        # Check newline nodes starting with number
        string = re.sub(r'(\n(?=[0-9]))', '\n_', string)
        # Check OR nodes starting with number
        string = re.sub(r'({(?=[0-9]))', '{_', string)
        return string

    def tree_get_model(self) -> str:

        '''
            Creates a string with a FaMa Framework representation of a Feature Model
        '''

        res = self.comments
        res += "%Relationships \n"
        res += self.sanitize_out_string(self.root) + self.LINE_TERMINATOR + "\n"
        res += self.cve_attributes + "\n"
        res += self.exploits + self.LINE_TERMINATOR
        if self.rcs != "":
            res += self.sanitize_out_string(self.rcs) + "\n"
        res += self.sanitize_out_string(self.vendors)  + "\n"
        res += self.sanitize_out_string(self.vendors_products)  + "\n"
        res += self.sanitize_out_string(self.product_attributes)

        res += self.direct_exploits_ids + self.LINE_TERMINATOR if len(self.direct_exploits_ids) else "" + "\n"
        res += self.direct_exploits + self.LINE_TERMINATOR if len(self.direct_exploits) else "" + "\n"
        res += self.indirect_exploits + self.LINE_TERMINATOR if len(self.indirect_exploits) else "" + "\n"


        return res
    
    def save_model(self, file_name: str) -> str:

        if not os.path.exists(EXPORT_PATH):
            os.makedirs(EXPORT_PATH)
        
        
        fm_file = os.path.join(EXPORT_PATH, "{}.afm".format(file_name))
       # restriction_file = os.path.join(EXPORT_PATH, "{}.fmr".format(file_name))

        with open(fm_file, mode='w', encoding='utf-8') as feat_model:

            feat_model.writelines(self.tree_get_model())
            if self.restrictions != "":
                feat_model.write("%Constraints \n")
                feat_model.writelines(self.restrictions)
            feat_model.flush()
            feat_model.close()
        
        print("FaMa Model Saved! Check {}".format(fm_file))
    
        #print("FaMa Restrictions for Model Saved! Check {}".format(restriction_file))

    ### SECTION
    ### Methods to implement the different type of relationships in a Feature Model
    def add_mandatory(self, node_or_nodes: Union[str, Iterable]) -> str:

        '''
            Adds a new line of type: Mandatory. Provided attributes will be required
            in order for the model to be valid

            :param node_or_nodes: Attribute or list of attributes to make mandatory
        '''
        sanitizedInput = self.sanitize(node_or_nodes)

        return " ".join(sanitizedInput) if type(sanitizedInput) \
            is not str else " " + sanitizedInput

    def add_XOR(self, alternatives: Union[str, Iterable]) -> str:

        '''
            Adds a new line of type: XOR. Only one of the provided attributes will be selected
            in order for the model to be valid

            :param alternatives: Attribute or list of attributes to make a XOR selection
        '''
        sanitizedInput = self.sanitize(alternatives)

        # A XOR selection of just one item is a mandatory selection
        if type(sanitizedInput) is not str and len(sanitizedInput) == 1:
            return self.add_mandatory(sanitizedInput)
        else:
            return "[1,1] {{{}}}".format(self.add_mandatory(sanitizedInput))

    def add_OR(self, alternatives: Union[str, Iterable]) -> str:

        '''
            Adds a new line of type: OR. One or more of the provided attributes will be selected
            in order for the model to be valid

            :param alternatives: Attribute or list of attributes to make an OR selection
        '''
        sanitizedInput = self.sanitize(alternatives)

        return "[1,{}] {{{}}}".format(len(sanitizedInput), self.add_mandatory(sanitizedInput))

    def add_optional(self, node_or_nodes: Union[str, Iterable]) -> str:

        '''
            Adds a new line of type: Optional. The provided attributes will be either selected
            or not in order for the model to be valid

            :param node_or_nodes: Attribute or list of attributes to make optional
        '''
        sanitizedInput = self.sanitize(node_or_nodes)

        return ' '.join(['[{}]'.format(x) for x in sanitizedInput]) if type(sanitizedInput) \
            is not str else "[{}]".format(sanitizedInput)

    def add_require(self, node_a: str, node_b:str) -> str:

        '''
            Adds a new line of type: Require. Node_a will need of node_b to exist

            :param node_a: Attribute that needs another to exist
            :param node_b: Attribute needed for node_a to exist

        '''
        sanitizedInputA = self.sanitize(node_a)
        sanitizedInputB = self.sanitize(node_b)

        return "{} REQUIRES {}".format(sanitizedInputA, sanitizedInputB)

    # TODO: Really implement this one
    def add_require_XOR(self, node_a: str, alternatives: iter) -> str:

        '''
            Adds a new line of type: Require XOR. Node_a will need of any of the provided
            alternatives to exist

            :param node_a: Attribute that needs another to exist
            :param alternatives: Attributes needed for node_a to exist (just one)
        '''
        sanitizedInputA = self.sanitize(node_a)
        sanitizedInputAlternatives = self.sanitize(alternatives)

        return "{} REQUIRES [1,{}] {{{}}}".format(str(sanitizedInputA), len(sanitizedInputAlternatives), self.add_mandatory(sanitizedInputAlternatives))  

    def add_exclude(self, node_a: str, node_b: str) -> str:

        '''
            Adds a new line of type: Exlusion. Node_a and node_b can no coexist in order for 
            the model to be valid.

            :param node_a: Attribute that prevents another to exist
            :param node_b: Attribute prevented to exist in case that node_a is selected
        '''
        sanitizedInputA = self.sanitize(node_a)
        sanitizedInputB = self.sanitize(node_b)

        return "{} EXCLUDES {}".format(str(sanitizedInputA), str(sanitizedInputB))
    ### END OF SECTION
