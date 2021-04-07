from famapy.metamodels.fm_metamodel.transformations.xml_transformation import XMLTransformation

from famapy.metamodels.pysat_metamodel.models.pysat_model import PySATModel
from famapy.metamodels.pysat_metamodel.operations.glucose3_valid import Glucose3Valid
from famapy.metamodels.pysat_metamodel.operations.glucose3_products import Glucose3Products
from famapy.metamodels.pysat_metamodel.transformations.fm_to_pysat import FmToPysat

xmlreader = XMLTransformation("example.xml")
fm = xmlreader.transform()
print(fm)

sat = PySATModel()

# Transform the first onto the second
transform = FmToPysat(fm)
transform.transform()

# Create the valid model operation
valid = Glucose3Valid()

# Execute the operation
valid.execute(transform.destiny_model)

# Print the result
print("Is the model valid: " + str(valid.result))

# Create the products operation
products = Glucose3Products()

# Execute the operation
products.execute(transform.destiny_model)

# Print the result
print("The products in the model are: " + str(products.products))