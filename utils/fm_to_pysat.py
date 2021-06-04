import sys
from typing import Any

from famapy.core.exceptions import ElementNotFound
from famapy.core.models import VariabilityModel
from famapy.core.transformations import ModelToModel
from famapy.metamodels.pysat_metamodel.models.pysat_model import PySATModel


class FmToPysat(ModelToModel):
    @staticmethod
    def get_source_extension():
        return 'fm'

    @staticmethod
    def get_destination_extension():
        return 'pysat'

    def __init__(self, source_model: VariabilityModel):
        self.source_model = source_model
        self.counter = 1
        self.destination_model = PySATModel()
        self.cnf = self.destination_model.cnf

    def add_feature(self, feature):
        if feature.name not in self.destination_model.variables.keys():
            self.destination_model.variables[feature.name] = self.counter
            self.destination_model.features[self.counter] = feature.name
            self.counter += 1

    def add_root(self, feature):
        self.cnf.append([self.destination_model.variables.get(feature.name)])

    def add_relation(self, relation):  # noqa: MC0001
        if relation.is_mandatory():
            self.cnf.append([
                -1 * self.destination_model.variables.get(relation.parent.name),
                self.destination_model.variables.get(relation.children[0].name)])
            self.cnf.append([
                -1 * self.destination_model.variables.get(relation.children[0].name),
                self.destination_model.variables.get(relation.parent.name)])

        elif relation.is_optional():
            self.cnf.append([
                -1 * self.destination_model.variables.get(relation.children[0].name),
                self.destination_model.variables.get(relation.parent.name)])

        elif relation.is_or():  # this is a 1 to n relatinship with multiple childs
            # add the first cnf child1 or child2 or ... or childN or no parent)

            # first elem of the constraint
            alt_cnf = [-1 * self.destination_model.variables.get(relation.parent.name)]
            for child in relation.children:
                alt_cnf.append(self.destination_model.variables.get(child.name))
            self.cnf.append(alt_cnf)

            for child in relation.children:
                self.cnf.append([
                    -1 * self.destination_model.variables.get(child.name),
                    self.destination_model.variables.get(relation.parent.name)])

        elif relation.is_alternative():  # this is a 1 to 1 relatinship with multiple childs
            # add the first cnf child1 or child2 or ... or childN or no parent)

            # first elem of the constraint
            alt_cnf = [-1 * self.destination_model.variables.get(relation.parent.name)]
            for child in relation.children:
                alt_cnf.append(self.destination_model.variables.get(child.name))
            self.cnf.append(alt_cnf)

            for i in range(len(relation.children)):
                for j in range(i + 1, len(relation.children)):
                    if i != j:
                        self.cnf.append([
                            -1 * self.destination_model.variables.get(relation.children[i].name),
                            -1 * self.destination_model.variables.get(relation.children[j].name)
                        ])
                self.cnf.append([
                    -1 * self.destination_model.variables.get(relation.children[i].name),
                    self.destination_model.variables.get(relation.parent.name)
                ])

        else:  # This is a m to n relationship
            print(
                "Fatal error. N to M relationships are not yet supported in PySAT",
                file=sys.stderr
            )
            raise NotImplementedError

    def flatten(self, nested_list: list):
        '''
        Este metodo se encarga de aplanar una lista de listas anidada con multiples listas a
        multiples niveles.
        '''
        try:
            head = nested_list[0]
        except IndexError:
            return []
        return ((self.flatten(head) if isinstance(head, list) else [head]) +
                self.flatten(nested_list[1:]))

    def add_and_cnfs(self, cnfs_rigth):
        '''
        Este es un metodo auxiliar que se encarga de la expresividad de los operadores logicos and.
        Esto es necesario ya que a diferencia de los otros operadores usar este operador hace
        que se tengan que construir mas de una clausula, aumentando la complejidad al tratarlas.
        '''
        cnfs_rigth.append('f')
        result = []
        cnf_or = []
        for obj in cnfs_rigth:
            if isinstance(obj, int):
                cnf_or.append(obj)
            if isinstance(obj, list):
                result.append(self.add_and_cnfs(obj))
            if obj == 'f' and cnf_or:
                result = cnf_or
        return result

    def combinator(self, cnfs_left: Any, cnfs_rigth: Any, actual_op: str):
        '''
        Este metodo se encarga de conseguir las clausulas CNF resultantes por la combinacion de los
        resultados entre diferentes tipos de operados logicos.
        '''
        result = []
        if isinstance(cnfs_left, list) and isinstance(cnfs_rigth, list):
            if actual_op == 'and':
                for cnf_left in cnfs_left:
                    result.append(cnf_left)
                for cnf_rigth in cnfs_rigth:
                    result.append(cnf_rigth)
            elif actual_op == 'or':
                aux = []
                for result1 in cnfs_left:
                    for result2 in cnfs_rigth:
                        aux.append(self.flatten([result1,result2]))
                result.extend(aux)
            elif actual_op in ('requires','implies'):
                for obj in cnfs_rigth:
                    if isinstance(obj, list):
                        cnf = [-cnfs_left]
                        cnf.extend(obj)
                        result.append(cnf)
                    elif isinstance(obj, int):
                        cnf = [-cnfs_left]
                        cnf.append(obj)
                        result.append(cnf)
        elif isinstance(cnfs_left, int) and isinstance(cnfs_rigth, list):
            if actual_op == 'and':
                result.append([cnfs_left])
                result.extend(self.add_and_cnfs(cnfs_rigth))
            elif actual_op == 'or':
                for cnf_rigth in cnfs_rigth:
                    cnf = self.flatten([cnfs_left, cnf_rigth])
                    result.append(cnf)
            elif actual_op in ('requires','implies'):
                for obj in cnfs_rigth:
                    if isinstance(obj, list):
                        cnf = [cnfs_left]
                        cnf.extend(obj)
                        result.append(cnf)
                    elif isinstance(obj, int):
                        cnf = [cnfs_left]
                        cnf.append(obj)
                        result.append(cnf)
            elif actual_op == 'excludes':
                for obj in cnfs_rigth:
                    if isinstance(obj, list):
                        cnf = [cnfs_left]
                        cnf.extend(obj)
                        result.append(cnf)
                    elif isinstance(obj, int):
                        cnf = []
                        cnf.append(obj)
                        cnf.append(cnfs_left)
                        result.append(cnf)
        elif isinstance(cnfs_left, list) and isinstance(cnfs_rigth, int):
            if actual_op == 'and':
                result.append(cnfs_rigth)
                result.extend(self.add_and_cnfs(cnfs_left))
            elif actual_op == 'or':
                for cnf_left in cnfs_left:
                    cnf = self.flatten([cnf_left, cnfs_rigth])
                    result.append(cnf)
            elif actual_op in ('requires','implies'):
                for obj in cnfs_left:
                    if isinstance(obj, list):
                        cnf = [x for x in obj]
                        cnf.append(cnfs_rigth)
                        result.append(cnf)
                    elif isinstance(obj, int):
                        cnf = []
                        cnf.append(obj)
                        cnf.append(cnfs_rigth)
                        result.append(cnf)
            elif actual_op == 'excludes':
                for obj in cnfs_left:
                    if isinstance(obj, list):
                        cnf = [x for x in obj]
                        cnf.append(cnfs_rigth)
                        result.append(cnf)
                    elif isinstance(obj, int):
                        cnf = []
                        cnf.append(obj)
                        cnf.append(cnfs_rigth)
                        result.append(cnf)
        else: #left int and right int
            if actual_op == 'and':
                result.append([cnfs_left])
                result.append([cnfs_rigth])
            elif actual_op == 'or':
                result = [[cnfs_left,cnfs_rigth]]
            elif actual_op == 'excludes':
                result = [[cnfs_left,cnfs_rigth]]
            elif actual_op in ('requires','implies'):
                result = [[cnfs_left,cnfs_rigth]]

        return result

    def negative_ast_iterator(self, ctc, node):
        result = []
        print(node.get_name())
        name = node.get_name().replace('(','').replace(')','')
        childs = ctc.ast.get_childs(node)
        if name == 'and':
            cnfs_left = self.negative_ast_iterator(ctc, childs[0])
            cnfs_rigth = self.negative_ast_iterator(ctc, childs[1])
            result = self.combinator(cnfs_left, cnfs_rigth, 'or')
        elif name == 'or':
            cnfs_left = self.negative_ast_iterator(ctc, childs[0])
            cnfs_rigth = self.negative_ast_iterator(ctc, childs[1])
            result = self.combinator(cnfs_left, cnfs_rigth, 'and')
        elif name in ('requires', 'implies'):
            cnfs_left = self.positive_ast_iterator(ctc, childs[0])
            cnfs_rigth = self.negative_ast_iterator(ctc, childs[1])
            result = self.combinator(cnfs_left, cnfs_rigth, name)
        elif name == 'excludes':
            cnfs_left = self.positive_ast_iterator(ctc, childs[0])
            cnfs_rigth = self.positive_ast_iterator(ctc, childs[1])
            result = self.combinator(cnfs_left, cnfs_rigth, name)
        elif name == 'not':
            var = self.destination_model.variables.get(
                ctc.ast.get_childs(node)[0].get_name()
            )
            if var:
                result = var
            else:
                cnfs = self.positive_ast_iterator(ctc, childs[0])
                for cnf in cnfs:
                    result.append(cnf)
        else:
            var = self.destination_model.variables.get(node.get_name())
            result = - var
        print(result)
        return result

    def positive_ast_iterator(self, ctc, node):
        result = []
        print(node.get_name())
        name = node.get_name().replace('(','').replace(')','')
        childs = ctc.ast.get_childs(node)
        if name == 'and':
            cnfs_left = self.positive_ast_iterator(ctc, childs[0])
            cnfs_rigth = self.positive_ast_iterator(ctc, childs[1])
            result = self.combinator(cnfs_left, cnfs_rigth, name)
        elif name == 'or':
            cnfs_left = self.positive_ast_iterator(ctc, childs[0])
            cnfs_rigth = self.positive_ast_iterator(ctc, childs[1])
            result = self.combinator(cnfs_left, cnfs_rigth, name)
        elif name in ('requires', 'implies'):
            cnfs_left = self.negative_ast_iterator(ctc, childs[0])
            cnfs_rigth = self.positive_ast_iterator(ctc, childs[1])
            result = self.combinator(cnfs_left, cnfs_rigth, name)
        elif name == 'excludes':
            cnfs_left = self.negative_ast_iterator(ctc, childs[0])
            cnfs_rigth = self.negative_ast_iterator(ctc, childs[1])
            result = self.combinator(cnfs_left, cnfs_rigth, name)
        elif name == 'not':
            var = self.destination_model.variables.get(
                ctc.ast.get_childs(node)[0].get_name()
            )
            if var:
                result = - var
            else:
                cnfs = self.negative_ast_iterator(ctc, childs[0])
                for cnf in cnfs:
                    aux = [- x for x in cnf]
                    result.append(aux)
        else:
            var = self.destination_model.variables.get(node.get_name())
            result = var
        print(result)
        return result

    def add_constraint(self, ctc):
        '''
        Hay dos iteradores debido a que las reglas de las leyes de Morgan cambian los operadores or y and
        cuando se usar el operador not para negar una clausula. Debido a que esta negación es necesaría
        al trasformar a CNF nacen el iterador positivo y negativo que se complementan en el flujo de 
        creación del CNF.
        Reglas de las leyes de Morgan:
            A <=> B      = (A => B) AND (B => A)
            A  => B      = NOT(A) OR  B
            NOT(A AND B) = NOT(A) OR  NOT(B) 
            NOT(A OR  B) = NOT(A) AND NOT(B) 
        '''
        node = ctc.ast.get_root()
        name = node.get_name()
        if name == 'not':
            cnfs = self.negative_ast_iterator(ctc, node)
        elif name in ('and', 'or', 'requires', 'excludes', 'implies'):
            cnfs = self.positive_ast_iterator(ctc, node)
        else:
            print('This FM contains non supported elements', file=sys.stderr)

        for cnf in cnfs:
            print(cnf)
            self.cnf.append(cnf)

    def transform(self):
        for feature in self.source_model.get_features():
            self.add_feature(feature)

        self.add_root(self.source_model.root)

        for relation in self.source_model.get_relations():
            self.add_relation(relation)

        for constraint in self.source_model.get_constraints():
            self.add_constraint(constraint)

        return self.destination_model
