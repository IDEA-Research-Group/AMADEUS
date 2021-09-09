from pysat.solvers import Glucose3
import time

from famapy.core.operations import Products
from famapy.metamodels.pysat_metamodel.models.pysat_model import PySATModel


class Glucose3Products(Products):

    def __init__(self):
        self.products = []

    def get_products(self):
        return self.products

    def get_result(self):
        return self.get_products()

    def execute(self, model, seconds = None):
        glucose = Glucose3()

        for clause in model.get_all_clauses():  # AC es conjunto de conjuntos
            glucose.add_clause(clause)  # añadimos la constraint

        begin = time.time()

        for solutions in glucose.enum_models():
            product = list()
            for variable in solutions:
                if variable > 0:
                    product.append(model.features.get(variable))
            self.products.append(product)

            if seconds or seconds == 0.0:
                now = time.time() - begin
                if now > seconds:
                    return self

        glucose.delete()
        return self
