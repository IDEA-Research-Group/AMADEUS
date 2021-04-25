import jsonpickle
from ahp_structure import AhpNode, AhpTree

def add_comparisons(parent, node):
    for childNode in parent.get_children():
        node.add_comparison(childNode.id, 1)

def process_child(parent, child):
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


with open('./decision_trees/afm-example.json') as file:
    s = file.read()
    data = jsonpickle.decode(s)

tree = AhpTree()
process_child(tree, data)

with open('./decision_trees/result-afm-ahp.json', 'w') as out:
    res = jsonpickle.encode(tree, make_refs=False, indent=4)
    out.write(res)