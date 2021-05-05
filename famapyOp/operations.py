from famapy.metamodels.pysat_metamodel.operations.glucose3_products import Glucose3Products
from famapy.metamodels.pysat_metamodel.operations.glucose3_valid_configuration import Glucose3ValidConfiguration
from famapy.metamodels.pysat_metamodel.transformations.fm_to_pysat import FmToPysat

from utils.afm_transformation import AFMTransformation
from utils.configuration import Configuration
from utils.glucose3_filter import Glucose3Filter

def get_configuration(fm, names):
    config = {}
    for name in names:
        if name.__contains__("^"):
            name = name.replace("^", "")
            for feat in fm.features:
                if name == feat.name:
                    config[feat] = False
        else:
            for feat in fm.features:
                if name == feat.name:
                    config[feat] = True
    return Configuration(config)

def transform(path):
    parser = AFMTransformation(path)
    fm  = parser.transform()
    transform = FmToPysat(fm)
    transform.transform()
    return fm, transform.destination_model

def products_number(path):
    result = transform(path)
    operation = Glucose3Products()
    operation.execute(result[1])
    print("The number of atack vectors in the model are -> " + str(len(operation.products)))

def filter(path, configuration_names):
    result = transform(path)
    operation = Glucose3Filter()
    operation.set_configuration(get_configuration(result[0], configuration_names))
    operation.execute(result[1])
    print("The number of filter atack vectors in the model are -> " + str(len(operation.filter_products)))

def valid_configuration(path, configuration_names):
    result = transform(path)
    operation = Glucose3ValidConfiguration()
    operation.set_configuration(get_configuration(result[0], configuration_names))
    operation.execute(result[1])
    print("Is the configuration valid? -> " + str(operation.result))
