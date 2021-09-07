from pysat.solvers import Glucose3
import time

from famapy.core.operations import ProductsNumber
from famapy.metamodels.pysat_metamodel.models.pysat_model import PySATModel


class Glucose3ProductsNumber(ProductsNumber):

    def __init__(self):
        self.products_number = 0

    def get_products_number(self):
        return self.products_number

    def get_result(self):
        return self.get_products_number()

    def execute(self, model, seconds = None):
        glucose = Glucose3()
        for clause in model.get_all_clauses():  # AC es conjunto de conjuntos
            glucose.add_clause(clause)  # añadimos la constraint

        i = time.time()

        for _ in glucose.enum_models():
            self.products_number += 1

            if seconds:
                j = time.time() - i
                if j > seconds:
                    return self

        glucose.delete()
        return self
