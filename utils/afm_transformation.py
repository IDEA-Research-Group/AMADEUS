import sys
import antlr4
from astLogic.propositionalLexer import propositionalLexer
from astLogic.propositionalParser import propositionalParser

from famapy.core.exceptions import DuplicatedFeature
from famapy.core.transformations import TextToModel
from famapy.metamodels.fm_metamodel.models.feature_model import (Feature,
                                                                 FeatureModel,
                                                                 Relation)


class AFMTransformation(TextToModel):

    @staticmethod
    def get_source_extension() -> str:
        return 'afm'

    def __init__(self, path):
        self.path = path
        self.name_feature = {}
        self.parents = []

    def transform(self):
        with open(self.path, 'r') as lines:
            lines = [line.strip() for line in lines.readlines() if line.strip() != '']
        for line in lines:
            if line.__contains__('%Relationships'):
                index_r = lines.index(line)
            if line.__contains__('%Constraints'):
                index_c = lines.index(line)
        relations = lines[index_r + 1:index_c]
        constraints = lines[index_c + 1:]

        feature_model = FeatureModel(Feature('', []),[],[],[])
        for relation in relations:
            words = relation.split(' ')
            self.parse_features(words, feature_model)

        for constraint in constraints:
            constraint = constraint.replace(';', '')
            ctc = self.parse_ctc(constraint)
            feature_model.ctcs.append(ctc)
        return feature_model

    def parse_ctc(self, ctc: str):
        tree = None

        words = ctc.split(' ')
        final_ctc = ''
        aux = False
        for word in words:
            if word == 'NOT' or word == '(NOT':
                final_ctc = final_ctc + ' (' + word + ' ('
                aux = True
            elif aux:
                final_ctc = final_ctc + word + ')) '
                aux = False
            else:
                final_ctc = final_ctc + " " + word
        final_ctc = final_ctc[1:]
        
        lexer = propositionalLexer(antlr4.InputStream(final_ctc))
        stream = antlr4.CommonTokenStream(lexer)
        parser = propositionalParser(stream)
        tree = parser.formula()
        return tree

    def parse_features(self, words: list[str], model: FeatureModel) -> Feature:
        name = words[0].replace(':', '')
        words.pop(0)

        if name in self.parents:
            print('This AFM contains duplicated feature names', file=sys.stderr)
            raise DuplicatedFeature
        self.parents.append(name)

        feature_parent = Feature(name, [])
        if name in self.name_feature:
            feature_parent = self.name_feature[name]
        else:
            model.features.append(feature_parent)
            model.root = feature_parent
            self.name_feature[name] = feature_parent

        is_grouped = False
        is_or = False
        for word in words:
            if is_grouped:
                if is_or:
                    relation.card_max+=1
                if word.__contains__('}'):
                    word = word.replace('}', '').replace(';', '')
                    self.add_feature(relation, word, model)
                    is_or = False
                    is_grouped = False
                else:
                    word = word.replace('{', '').replace(';', '')
                    self.add_feature(relation, word, model)
            else:
                if word.__contains__('[1,'):
                    is_grouped = True
                    relation = self.parse_relation('Alternative/Or', feature_parent)
                    if not word.__eq__('[1,1]'):
                        relation.card_max = 0
                        is_or = True
                    continue
                elif word.__contains__('[') and word.__contains__(']'):
                    relation = self.parse_relation('Optional', feature_parent)
                    word = word.replace('[', '').replace(']', '').replace(';', '')
                    self.add_feature(relation, word, model)
                else:
                    relation = self.parse_relation('Mandatory', feature_parent)
                    word = word.replace(';', '')
                    self.add_feature(relation, word, model)
            model.relations.append(relation)
        return feature_parent

    def add_feature(self, relation, word, model) -> None:
        if word in self.name_feature:
            print('This AFM contains duplicated feature names', file=sys.stderr)
            raise DuplicatedFeature
        feature = Feature(word, [])
        model.features.append(feature)
        self.name_feature[word] = feature
        relation.children.append(feature)

    def parse_relation(
        self,
        relation_type: str, 
        feature_parent: Feature
    ) -> Relation:
        if relation_type in ('Mandatory', 'Alternative/Or'):
            relation = Relation(parent=feature_parent, children=[], card_min=1, card_max=1)
        elif relation_type == 'Optional':
            relation = Relation(parent=feature_parent, children=[], card_min=0, card_max=1)
        feature_parent.relations.append(relation)
        return relation
