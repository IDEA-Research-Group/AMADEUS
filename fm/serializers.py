
'''
    Different serializers that can be used to export a given FeatureModel
    to different formats.
'''

__author__ = "Jose Antonio Carmona (joscarfom@alum.us.es)"


import re
import os
from typing import Union
from collections.abc import Iterable
from .structures import RestrictionNode

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODELS_FOLDER = "models"
EXPORT_PATH = os.path.join(BASE_DIR, MODELS_FOLDER)

class FamaSerializer:

    '''
        Class that creates a Feature Model file following the notations used in
        FaMa Framework
    '''

    LINE_TERMINATOR = ";\n"
    RUNNING_CONFIG_NODE_NAME = "configs"
    RUNNING_CONFIG_PREFIX = "rc{}"

    def __init__(self, CVE:str):
        
        # First, we need to check the arguments

        if not CVE or type(CVE) is not str:
            raise ValueError("CVE must be a non-empty string")

        # A Feature Model contains info about a single CVE
        self.CVE = CVE
        
        # Different sections of a Feature Model file
        self.root = self.CVE + ": "
        self.rcs = ""
        self.vendors = ""
        self.vendors_products = ""
        self.product_attributes = ""
        
        # Restrictions
        self.restrictions = ""

    ### SECTION
    ### Methods to add content to the different sections of a Feature Model file
    def tree_add_rcs_to_root(self, num_of_configs:int) -> None:

        # Line Terminator is not appended until the very end, to make the addition of new
        # root children nodes possible
        self.root += ' ' + self.add_optional(self.RUNNING_CONFIG_NODE_NAME)

        self.rcs += "{}: ".format(self.RUNNING_CONFIG_NODE_NAME) + \
            self.add_XOR([self.RUNNING_CONFIG_PREFIX.format(i) for i in range(num_of_configs)]) + \
            self.LINE_TERMINATOR

    def tree_add_vendors_to_rc(self, rc:int, vendors: Union[Iterable, object]) -> None:
        fs = self.RUNNING_CONFIG_PREFIX + "-{}"
        formatted_vendors = [fs.format(rc, k) for k in vendors]
        
        self.rcs += self.RUNNING_CONFIG_PREFIX.format(rc) + ': ' + \
            self.add_XOR(formatted_vendors) + self.LINE_TERMINATOR

    def tree_add_vendors_to_root(self, vendors: Union[Iterable, object]) -> None:
        self.__tree_add_vendors_to_root(vendors)

    def tree_add_products_to_vendor(self, vendor, products: Union[Iterable, object], rc:int = None) -> None:
        prefix =  "" if rc is None else self.RUNNING_CONFIG_PREFIX.format(rc) + "-"

        formatted_vendor = prefix + vendor
        formatted_products = [prefix+k for k in products]

        self.__tree_add_products_to_vendor(formatted_vendor, formatted_products)

    def tree_add_attributes_to_product(self, product: str, attributes: Union[Iterable, object], rc:int = None) -> None:
        prefix =  "" if rc is None else self.RUNNING_CONFIG_PREFIX.format(rc) + "-"
        
        formatted_attributes = ["{}{}-{}".format(prefix, product, k) for k in attributes]
        formatted_product = prefix + product

        self.__tree_add_attributes_to_product(formatted_product, formatted_attributes)

    def tree_add_values_to_attribute(self, product: str, attribute:str, values: Union[Iterable, object], rc:int = None) -> None:
        prefix =  "" if rc is None else self.RUNNING_CONFIG_PREFIX.format(rc) + "-"

        formatted_values = ["{}{}-{}-{}".format(prefix, product, attribute, k) for k in values]
        formatted_attribute = "{}{}-{}".format(prefix, product, attribute)

        self.__tree_add_values_to_attribute(formatted_attribute, formatted_values)
    
    def tree_add_constraints(self, product: str, restrictionNode:RestrictionNode) -> None:
        self.restrictions += self.serialize_constraints(product, restrictionNode, 0) + self.LINE_TERMINATOR

    def serialize_constraints(self, product: str, restrictionNode:RestrictionNode, depth:int) -> str:
        
        res = ''

        if restrictionNode:

            # The value of the precedent requirement, or the product if depth = 0 
            super_value = restrictionNode.value if depth > 0 else product

            if restrictionNode.isLeaf:
                
                # BASE CASE

                VALUE_REQ_CONNECTOR = ' REQUIRES ' if depth <= 1 else ' AND '
                aux = list()
                need_brackets = False

                for (attr, val) in restrictionNode.requirements:
                    
                    if attr == 'rcs':
                        # Generate requirements for the running configurations
                        rcs = ' XOR '.join([self.RUNNING_CONFIG_PREFIX.format(k) for k in val])

                        # We add brackets if there are more than one rc, to create a logical group
                        if len(val) > 1:
                            rcs = '(' + rcs + ')'
                        else:
                            need_brackets = True
                        
                        aux.append(rcs)

                    else:
                        # Generate requirements for the rest of attributes (standard attr)
                        aux.append("{}-{}-{}".format(product, attr[:-1], val))
                        need_brackets = True

                need_brackets = depth <= 1 and need_brackets
                
                res = ' AND '.join(aux)

                if need_brackets:
                    res = '(' + res + ')'
                
                res = super_value + VALUE_REQ_CONNECTOR + res
                res = self.sanitize(res)

                return res

            else:

                split_attr = restrictionNode.xorAttributeSubNodes[:-1]
                aux = list()
                
                for sn in restrictionNode.subNodes:
                    # Explore all the subnodes recursively
                    aux.append('{}-{}-'.format(product, split_attr) + self.serialize_constraints(product, sn, depth=depth+1))

                if depth == 0:
                    res = self.LINE_TERMINATOR.join(aux) 
                elif depth == 1:
                    res = super_value + ' REQUIRES ' + '((' + ') XOR ('.join(aux) + '))'
                else:
                    res = ' XOR '.join(aux)
                
                res = self.sanitize(res)

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

    def sanitize(self, toSanitize: Union[str, Iterable], num_prefix:str='v', replacers:tuple=(('.', '_'),('*','any'))) -> Union[str, Iterable]:
            
        '''
            Sanitizes retrieved content so as to avoid invalid characters in FaMa
            (dots and labels starting with numbers)

            :param toSanitize: String or Iterable containing strings that are intended 
            to be sanitized

            :param num_prefix: Character to use as a prefix for string starting with a number

            :param replacers: Tuple containing pairs which first item is the special character to replace
            and the second the new expression.
        '''

        if type(toSanitize) is str:
            
            starts_with_number_regex = re.compile(r"^\d")
            res = toSanitize

            # Check whether the string starts with a number or not
            if starts_with_number_regex.match(res):
                res = num_prefix + res
            
            for t in replacers:
                res = res.replace(t[0], t[1])

        elif isinstance(toSanitize, Iterable):
            res = [self.sanitize(x) for x in toSanitize]
        else:
            raise ValueError("Input should be either a string or an Iterable")

        return res
            
    def tree_get_model(self) -> str:

        '''
            Creates a string with a FaMa Framework representation of a Feature Model
        '''

        res = "%Relationships \n"
        res += self.root + self.LINE_TERMINATOR + "\n"
        res += self.rcs + "\n"
        res += self.vendors + "\n"
        res += self.vendors_products + "\n"
        res += self.product_attributes

        return res
    
    def save_model(self, file_name: str) -> str:

        if not os.path.exists(EXPORT_PATH):
            os.makedirs(EXPORT_PATH)
        
        
        fm_file = os.path.join(EXPORT_PATH, "{}.fm".format(file_name))
        restriction_file = os.path.join(EXPORT_PATH, "{}.fmr".format(file_name))

        with open(fm_file, mode='w', encoding='utf-8') as feat_model:

            feat_model.writelines(self.tree_get_model())
            feat_model.flush()
            feat_model.close()
        
        with open(restriction_file, mode='w', encoding='utf-8') as restriction_lines:

            restriction_lines.write("%Restrictions \n")
            restriction_lines.writelines(self.restrictions)
            restriction_lines.flush()
            restriction_lines.close()
        
        print("FaMa Model Saved! Check {}".format(fm_file))
        print("FaMa Restrictions for Model Saved! Check {}".format(restriction_file))

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
