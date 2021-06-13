import jsonpickle
from ahp_structure import AhpNode, AhpTree

def add_comparisons(parent, node, zero_value = False):
    for childNode in parent.get_children():
        if childNode.id != node.id:
            node.add_comparison(childNode.id, 0 if zero_value else 1)

'''
Processes child for AHP processing (diagonal+symmetric comparison matrix)
'''
def process_child(parent, child, method = ""):
    if isinstance(child, str):
        node = AhpNode(child)
        add_comparisons(parent, node)
        parent.add_child(node)
    elif isinstance(child, list):
        for v in child:
            node = AhpNode(v)
            add_comparisons(parent, node)
            parent.add_child(node)
    elif isinstance(child, dict):
        for k,v in child.items():
            node = AhpNode(k)
            process_child(node, v)
            add_comparisons(parent, node)
            parent.add_child(node)


'''
Processes child for DEMATEL processing (assymetric comparison matrix)
'''
def process_child_dematel(parent, child):
    if isinstance(child, str):
        node = AhpNode(child)
        parent.add_child(node)
        for par_child in parent.get_children():
            add_comparisons(parent, par_child, zero_value=True)
    elif isinstance(child, list):
        for v in child:
            node = AhpNode(v)
            parent.add_child(node)
        for par_child in parent.get_children():
            add_comparisons(parent, par_child, zero_value=True)
    elif isinstance(child, dict):
        for k,v in child.items():
            node = AhpNode(k)
            process_child_dematel(node, v)
            parent.add_child(node)
        for par_child in parent.get_children():
            add_comparisons(parent, par_child, zero_value=True)

def afm_to_ahp_conversion(afmJsonPath, outPath, dematelProcessing = False):
    with open(afmJsonPath) as file:
        s = file.read()
        data = jsonpickle.decode(s)

    tree = AhpTree()
    if dematelProcessing:
        process_child_dematel(tree, data)
    else:
        process_child(tree, data)

    with open(outPath, 'w') as out:
        res = jsonpickle.encode(tree, make_refs=False, indent=4)
        out.write(res)