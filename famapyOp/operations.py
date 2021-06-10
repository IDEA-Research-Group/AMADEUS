from famapy.metamodels.pysat_metamodel.operations.glucose3_products import \
    Glucose3Products
from famapy.metamodels.pysat_metamodel.operations.glucose3_valid_configuration import \
    Glucose3ValidConfiguration
from famapy.metamodels.pysat_metamodel.operations.glucose3_filter import Glucose3Filter
from famapy.metamodels.pysat_metamodel.operations.glucose3_products_number import \
    Glucose3ProductsNumber
from famapy.core.models.configuration import Configuration

''' It is not yet implemented in the latest release of FaMa-Py '''
from utils.fm_to_pysat import FmToPysat
from utils.afm_transformation import AFMTransformation


def get_configuration(fm, names):
    config = {}
    for name in names:
        if name.__contains__('^'):
            name = name.replace('^', '')
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

def products(path):
    result = transform(path)
    operation = Glucose3Products()
    operation.execute(result[1])
    print('The attack vectors of the model are -> ' + str(operation.products))

def products_number(path):
    result = transform(path)
    operation = Glucose3ProductsNumber()
    operation.execute(result[1])
    print('The number of attack vectors of the model are -> ' + str(operation.products_number))

def filter(path, configuration_names):
    result = transform(path)
    operation = Glucose3Filter()
    operation.set_configuration(get_configuration(result[0], configuration_names))
    operation.execute(result[1])
    print('The filter atack vectors of the model are -> ' + str(operation.filter_products))

def valid_configuration(path, configuration_names):
    result = transform(path)
    operation = Glucose3ValidConfiguration()
    operation.set_configuration(get_configuration(result[0], configuration_names))
    operation.execute(result[1])
    print('Is the configuration valid? -> ' + str(operation.result))
