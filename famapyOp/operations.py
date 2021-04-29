from famapy.metamodels.pysat_metamodel.operations.glucose3_products import Glucose3Products
from famapy.metamodels.pysat_metamodel.operations.glucose3_valid_configuration import Glucose3ValidConfiguration
from famapy.metamodels.pysat_metamodel.transformations.fm_to_pysat import FmToPysat

from utils.afm_transformation import AFMTransformation
from utils.configuration import Configuration


def products_number(path):
    parser = AFMTransformation(path)
    fm  = parser.transform()

    transform = FmToPysat(fm)
    transform.transform()

    operation = Glucose3Products()
    operation.execute(transform.destination_model)
    print("The number of products in the model are -> " + str(len(operation.products)))

def valid_configuration(path, configuration_names):
    parser = AFMTransformation(path)
    fm  = parser.transform()

    config = {}

    for name in configuration_names:
        if name.__contains__("^"):
            name = name.replace("^", "")
            for feat in fm.features:
                if name == feat.name:
                    config[feat] = False
        else:
            for feat in fm.features:
                if name == feat.name:
                    config[feat] = True

    transform = FmToPysat(fm)
    transform.transform()

    operation = Glucose3ValidConfiguration()
    operation.set_configuration(Configuration(config))
    operation.execute(transform.destination_model)
    print("Is the configuration valid? -> " + str(operation.result))
