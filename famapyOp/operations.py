from famapy.metamodels.pysat_metamodel.operations.glucose3_valid_configuration import \
    Glucose3ValidConfiguration
from famapy.metamodels.pysat_metamodel.operations.glucose3_filter import Glucose3Filter
from famapy.core.models.configuration import Configuration

''' It's a extension of FaMaPy implementations '''
from utils.fm_to_pysat import FmToPysat
from utils.afm_transformation import AFMTransformation
from utils.products_operation import Glucose3Products
from utils.products_number_operation import Glucose3ProductsNumber


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

def products(path, seconds = None):
    result = transform(path)
    operation = Glucose3Products()
    operation.execute(result[1], seconds)
    print('The attack vectors of the model are -> ' + str(operation.products))

def products_number(path, seconds = None):
    result = transform(path)
    operation = Glucose3ProductsNumber()
    operation.execute(result[1], seconds)
    print('The number of attack vectors of the model are -> ' + str(operation.products_number))

def filter(path, configuration_names):
    result = transform(path)
    operation = Glucose3Filter()
    operation.set_configuration(get_configuration(result[0], configuration_names))
    operation.execute(result[1])
    print('The filter atack vectors of the model are -> ' + str(operation.filter_products))
    print('The number of filter atack vectors of the model are -> ' + str(len(operation.filter_products)))

def valid_configuration(path, configuration_names):
    result = transform(path)
    operation = Glucose3ValidConfiguration()
    operation.set_configuration(get_configuration(result[0], configuration_names))
    operation.execute(result[1])
    print('Is the configuration valid? -> ' + str(operation.result))
