from pysat.solvers import Glucose3

from famapy.core.models import Configuration
from famapy.metamodels.pysat_metamodel.models.pysat_model import PySATModel

class Glucose3Filter():

    def __init__(self):
        self.filter_products = []
        self.configuration = None

    def get_filter_products(self):
        return self.filter_products

    def get_result(self):
        return self.get_filter_products()

    def set_configuration(self, configuration: Configuration):
        self.configuration = configuration

    def execute(self, model: PySATModel) -> 'Glucose3Filter':
        g = Glucose3()
        for clause in model.cnf:
            g.add_clause(clause)

        assumptions = [
            model.variables.get(feat[0].name) if feat[1]
            else -model.variables.get(feat[0].name)
            for feat in self.configuration.elements.items()
            ]

        for solution in g.enum_models(assumptions = assumptions):
            product = list()
            for variable in solution:
                if variable > 0:
                    product.append(model.features.get(variable))
            self.filter_products.append(product)

        g.delete()
        return self
