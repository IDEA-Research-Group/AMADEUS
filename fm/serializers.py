
'''
    Different serializers that can be used to export a given FeatureModel
    to different formats.
'''

__author__ = "Jose Antonio Carmona (joscarfom@alum.us.es)"


import re
from typing import Union
from collections.abc import Iterable

class FamaSerializer:

    '''
        Class that creates a Feature Model file following the notations used in
        FaMa Framework
    '''

    LINE_TERMINATOR = ";\n"

    def __init__(self, CVE:str):
        
        # First, we need to check the arguments

        if not CVE or type(CVE) is not str:
            raise ValueError("CVE must be a non-empty string")

        # A Feature Model contains info about a single CVE
        self.CVE = CVE
        
        # Different sections of a Feature Model file
        self.root = self.CVE + ": "
        self.vendors = ""
        self.vendors_products = ""
        self.product_attributes = ""

    ### SECTION
    ### Methods to add content to the different sections of a Feature Model file
    def tree_add_vendors_to_root(self, vendors: Union[Iterable, object]) -> None:
        self.root += self.add_XOR(vendors) + FamaSerializer.LINE_TERMINATOR

    def tree_add_products_to_vendor(self, vendor, products: Union[Iterable, object]) -> None:
        self.vendors += vendor + ": " + self.add_XOR(products) + FamaSerializer.LINE_TERMINATOR
    
    def tree_add_attributes_to_product(self, product: str, attributes: Union[Iterable, object]) -> None:
        self.vendors_products += "{}: ".format(product) + self.add_mandatory(attributes) + FamaSerializer.LINE_TERMINATOR

    def tree_add_values_to_attribute(self, product: str, attribute:str, values: Union[Iterable, object]) -> None:
        self.product_attributes += "{}-{}: ".format(product, attribute) + self.add_XOR(values) + FamaSerializer.LINE_TERMINATOR
    ### END OF SECTION

    def sanitize(self, toSanitize: Union[str, Iterable], prefix='v', dot_replacer='_') -> Union[str, Iterable]:
            
        '''
            Sanitizes retrieved content so as to avoid invalid characters in FaMa
            (dots and labels starting with numbers)

            :param toSanitize: String or Iterable containing strings that are intended 
            to be sanitized

            :param prefix: Character to use as a prefix for string starting with a number

            :param dot_replacer: Character that will substitute dots in the string
        '''

        if type(toSanitize) is str:
            
            regex = re.compile(r"^\d")
            res = toSanitize

            # Check whether the string starts with a number or not
            if regex.match(res):
                res = prefix + res
            
            res = res.replace(".", dot_replacer)

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
        res += self.root
        res += self.vendors
        res += self.vendors_products
        res += self.product_attributes

        return res

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
