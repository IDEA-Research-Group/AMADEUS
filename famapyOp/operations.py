from famapy.metamodels.pysat_metamodel.operations.glucose3_valid import Glucose3Valid
from famapy.metamodels.pysat_metamodel.operations.glucose3_products import Glucose3Products
# from famapy.metamodels.pysat_metamodel.operations.glucose3_valid_configuration import Glucose3ValidConfiguration
from famapy.metamodels.pysat_metamodel.transformations.fm_to_pysat import FmToPysat

# from utils.afm_transformation import AFMTransformation

# def products_number(path):
#     fm = AFMTransformation(path)

#     transform = FmToPysat(fm)
#     transform.transform()

#     operation = Glucose3Products()
#     operation.execute(transform.destiny_model)
#     print("The number of products in the model are: " + str(len(operation.products)))

# def valid_configuration(path, configuration_names):
#     fm = AFMTransformation(path)

#     Transformar configuration_names en características y construir la configuracion

#     transform = FmToPysat(fm)
#     transform.transform()

#     operation = Glucose3ValidConfiguration()
#     operation.execute(transform.destiny_model)
#     print("The number of products in the model are: " + str(operation.result))
