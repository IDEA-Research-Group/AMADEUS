import sys
import copy
from typing import Any
import antlr4

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
        self.r_cnf = self.destination_model.r_cnf
        self.ctc_cnf = self.destination_model.ctc_cnf

    def add_feature(self, feature):
        if feature.name not in self.destination_model.variables.keys():
            self.destination_model.variables[feature.name] = self.counter
            self.destination_model.features[self.counter] = feature.name
            self.counter += 1

    def add_root(self, feature):
        self.r_cnf.append([self.destination_model.variables.get(feature.name)])

    def add_relation(self, relation):  # noqa: MC0001
        if relation.is_mandatory():
            self.r_cnf.append([
                -1 * self.destination_model.variables.get(relation.parent.name),
                self.destination_model.variables.get(relation.children[0].name)])
            self.r_cnf.append([
                -1 * self.destination_model.variables.get(relation.children[0].name),
                self.destination_model.variables.get(relation.parent.name)])

        elif relation.is_optional():
            self.r_cnf.append([
                -1 * self.destination_model.variables.get(relation.children[0].name),
                self.destination_model.variables.get(relation.parent.name)])

        elif relation.is_or():  # this is a 1 to n relatinship with multiple childs
            # add the first cnf child1 or child2 or ... or childN or no parent)

            # first elem of the constraint
            alt_cnf = [-1 * self.destination_model.variables.get(relation.parent.name)]
            for child in relation.children:
                alt_cnf.append(self.destination_model.variables.get(child.name))
            self.r_cnf.append(alt_cnf)

            for child in relation.children:
                self.r_cnf.append([
                    -1 * self.destination_model.variables.get(child.name),
                    self.destination_model.variables.get(relation.parent.name)])

        elif relation.is_alternative():  # this is a 1 to 1 relatinship with multiple childs
            # add the first cnf child1 or child2 or ... or childN or no parent)

            # first elem of the constraint
            alt_cnf = [-1 * self.destination_model.variables.get(relation.parent.name)]
            for child in relation.children:
                alt_cnf.append(self.destination_model.variables.get(child.name))
            self.r_cnf.append(alt_cnf)

            for i in range(len(relation.children)):
                for j in range(i + 1, len(relation.children)):
                    if i != j:
                        self.r_cnf.append([
                            -1 * self.destination_model.variables.get(relation.children[i].name),
                            -1 * self.destination_model.variables.get(relation.children[j].name)
                        ])
                self.r_cnf.append([
                    -1 * self.destination_model.variables.get(relation.children[i].name),
                    self.destination_model.variables.get(relation.parent.name)
                ])

        else:  # This is a m to n relationship
            print(
                "Fatal error. N to M relationships are not yet supported in PySAT",
                file=sys.stderr
            )
            raise NotImplementedError

    @staticmethod
    def and_combinator(cnfs_left: Any, cnfs_rigth: Any):
        '''
        Este metodo se encarga de la combinatoria de literales y clausulas concatenados por un
        operador and. Este operador trabaja por union de las variables.
        '''
        cnfs_left.extend(cnfs_rigth)
        return cnfs_left

    @staticmethod
    def or_combinator(cnfs_left: Any, cnfs_rigth: Any):
        '''
        Este metodo se encarga de la combinatoria de literales y clausulas concatenados por un 
        operador or. Este operador trabaja por combinancion de las variables.
        '''
        result = []
        for result1 in cnfs_left:
            for result2 in cnfs_rigth:
                cnf = copy.copy(result1)
                cnf.extend(result2)
                result.append(cnf)
        return result

    def combinate(self, number, name, cnfs_left, cnfs_rigth):
        if number > 0 and name == 'AND':
            result = self.and_combinator(cnfs_left, cnfs_rigth)
        elif number > 0 and name in ('OR', 'REQUIRES', 'EXCLUDES', 'IMPLIES'):
            result = self.or_combinator(cnfs_left, cnfs_rigth)
        elif number < 0 and name == 'AND':
            result = self.or_combinator(cnfs_left, cnfs_rigth)
        elif number < 0 and name in ('OR', 'REQUIRES', 'EXCLUDES', 'IMPLIES'):
            result = self.and_combinator(cnfs_left, cnfs_rigth)
        return result

    def get_var(self, name, number):
        var = self.destination_model.variables.get(name)
        result = [[var * number]]
        return result

    @staticmethod
    def get_root(child_names):
        for name in child_names:
            if name in ('NOT', 'AND', 'OR', 'REQUIRES', 'IMPLIES', 'EXCLUDES'):
                return name

    @staticmethod
    def clean(childs):
        cleaned_childs = []
        for child in childs:
            if child.getText() not in ('(', ')', 'NOT', 'AND', 'OR', 'REQUIRES', 'IMPLIES', 'EXCLUDES'):
                cleaned_childs.append(child)
        return cleaned_childs

    def ast_iterator(self, child, number: int):
        '''
        La variable number se utiliza para seguir las leyes de Morgan expuestas a continuación.
        Reglas de las leyes de Morgan:
            A <=> B      = (A => B) AND (B => A)
            A  => B      = NOT(A) OR  B
            NOT(A AND B) = NOT(A) OR  NOT(B)
            NOT(A OR  B) = NOT(A) AND NOT(B)
        '''
        if not isinstance(child, antlr4.tree.Tree.TerminalNode):
            childs = [child_obj for child_obj in child.getChildren()]
            child_names = [child_name.getText() for child_name in childs]
            cleaned_childs = self.clean(childs)
            name = self.get_root(child_names)
            if len(cleaned_childs) == 1:
                aux = -1 if childs[0].getText() == 'NOT' else 1
                return self.ast_iterator(cleaned_childs[0], number * aux)
        else:
            name = child.getText()

        result = []

        if name in ('AND', 'OR'):
            cnfs_left = self.ast_iterator(cleaned_childs[0], number)
            cnfs_rigth = self.ast_iterator(cleaned_childs[1], number)
        elif name in ('REQUIRES', 'IMPLIES'):
            cnfs_left = self.ast_iterator(cleaned_childs[0], number * -1)
            cnfs_rigth = self.ast_iterator(cleaned_childs[1], number)
        elif name == 'EXCLUDES':
            cnfs_left = self.ast_iterator(cleaned_childs[0], number * -1)
            cnfs_rigth = self.ast_iterator(cleaned_childs[1], number * -1)
        else:
            result = self.get_var(name, number)

        if not result:
            result = self.combinate(number, name, cnfs_left, cnfs_rigth)
        return result

    def add_constraint(self, ctc):
        cnfs = self.ast_iterator(ctc, 1)
        self.ctc_cnf.extend(cnfs)

    def transform(self):
        for feature in self.source_model.get_features():
            self.add_feature(feature)

        self.add_root(self.source_model.root)

        for relation in self.source_model.get_relations():
            self.add_relation(relation)

        for constraint in self.source_model.get_constraints():
            self.add_constraint(constraint)

        return self.destination_model
