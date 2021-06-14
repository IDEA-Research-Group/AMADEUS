import jsonpickle
from utils.afm_transformation import AFMTransformation
from utils.ast import AST
from famapy.metamodels.fm_metamodel.models.feature_model import Feature

def process_node(node:Feature):
    if not node.relations or len(node.relations) == 0:
        return node.name
    
    nodeDict = dict()
    for rel in node.relations:
        for child in rel.children:
            childNode = process_node(child)
            nodeDict[child.name] = childNode
    
   # vals = [y for x in nodeDict.values() for y in x.values()]
    if all(isinstance(x, str) for x in nodeDict.values()):
        if len(nodeDict.values()) == 1:
            return list(nodeDict.values())[0]
        else:
            return [x for x in nodeDict.values()]
    else:
        return nodeDict

    

def afm_to_afm_json_conversion(afmPath, outPath=None):
    afm = AFMTransformation(afmPath).transform()
    nodeDict = process_node(afm.root)
    with open(outPath, 'w') as out:
        res = jsonpickle.encode(nodeDict, make_refs=False, indent=4)
        out.write(res)

# CVE 2019-8069 y 8070 no funcionan