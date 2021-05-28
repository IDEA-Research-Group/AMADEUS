#Este código puede obtenerse clonando el repositorio:
#https://github.com/GermanMT/AMADEUS.git
#En la rama dev_FamaPyI

#Importamos el AST y el parser
from famapy.metamodels.fm_metamodel.models.feature_model import Feature

from utils.afm_transformation import AFMTransformation
from utils.ast import AST

#Transformamos el archivo con extensión AFM a un objeto Feature Model
#Este archivo AFM ha sido generado con el comando python main.py -k nginx
parser = AFMTransformation('fm/models/CVE-2016-0746.afm')
fm  = parser.transform()
print('Modelo de caracteristicas: ')
print(fm)

print('Características: ')
print(fm.get_features())
print('\n')
print('Relaciones: ')
print(fm.get_relations())
print('\n')
print('Restricciones: ')
print(fm.get_constraints())
print('\n')
#Este método en la versión actual de FaMa-Py no es funcional
#print(fm.get_feature_by_name('nombre'))

print('\n')

#Relaciones
relation = fm.get_relations()[0]
print(relation.is_alternative())
print(relation.is_or())
print(relation.is_mandatory())
print(relation.is_optional())

feat = Feature('E', [])
relation.add_child(feat)

print('\n')

#Cogemos la primera restricción del modelo y vemos su representación AST
ctc = fm.get_constraints()[0]
print(ctc.ast.string)

print('\n')

ast_prueba = AST('A implies ((B or not C) and (D or not C))')
print(ast_prueba)

def iterator(node):
    for node in ast_prueba.get_childs(node):
        print(node.get_name())
        #Implementar función
        iterator(node)

node = ast_prueba.get_root()
print(ast_prueba.get_root().get_name())
iterator(node)
