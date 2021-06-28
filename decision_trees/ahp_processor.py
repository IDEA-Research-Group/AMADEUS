import ahpy
import jsonpickle
import jsonpickle.ext.numpy as jsonpickle_numpy
from ahp_structure import AhpNode, AhpTree

jsonpickle_numpy.register_handlers()

'''
Ejemplo. Tenemos los siguientes criterios y subcriterios
Nos fijamos en CVE-2009-3555 pero realmente es arbitrario.
Se omiten algunos criterios. Es un ejemplo ilustrativo

apache
- apache-http_server-version
    - apache-http_server-version-2_0_0
    - apache-http_server-version-2_1_0
    - apache-http_server-version-2_2_0
openssl
- openssl-openssl-version
    - openssl-openssl-version_0_9_4
    - openssl-openssl-version_0_9_7b
    - openssl-openssl-version_0_9_8
canonical
- canonical-ubuntu_linux-version
    - canonical-ubuntu_linux-version-10_04
    - canonical-ubuntu_linux-version-12_04
    - canonical-ubuntu_linux-version-13_04
debian
- debian-debian_linux-version
    - debian-debian_linux-version-4_0
    - debian-debian_linux-version-6_0
    - debian-debian_linux-version-8_0
'''

def process_node(comparisons, node, parentId = None):
    if isinstance(node, AhpTree):
        nodeId = 'root'
        for child in reversed(node.get_children()):
            process_node(comparisons, child, 'root')
            return
    else:
        nodeId = node.id

    comparisons[nodeId] = {}
    comparisons[nodeId]['parent'] = parentId;
    comparisons[nodeId]['comparisons'] = {}
    comparisons[nodeId]['children'] = []

    for comparedId, value in node.comparisons.items():
        comparisons[nodeId]['comparisons'][(nodeId, comparedId)] = value

    for child in reversed(node.get_children()):
        comparisons[nodeId]['children'].append(child.id)
        process_node(comparisons, child, nodeId)

def process_ahp(ahpJsonFilePath, ahpWeightsOutPath):
    '''
    Returns Ahp weights
    '''
    
    with open(ahpJsonFilePath) as file:
        s = file.read()
        ahpTree = jsonpickle.decode(s)

    comparisons = {}

    process_node(comparisons, ahpTree)

    '''
    MANUAL USAGE OF THE COMPARE FUNCTION

    root = ahpy.Compare('Criteria',criteria_comparisons, precision=4, random_index='saaty')
    apache_version = ahpy.Compare('apache-version', apache_version_comparison, precision=4, random_index='saaty')
    [...]
    ubuntu = ahpy.Compare('canonical', {('ubuntu-version','ubuntu-version'):1})
    [...]
    root.add_children([apache,openssl,ubuntu,debian])
    [...]
    print("ROOT")
    print(root.target_weights)
    '''

    # TODO document this method, it seems to work but it's ugly
    # TODO it doesn't seem to multiply weights correctly. See model tfm5
    finalComparisons = {}
    for key, item in comparisons.items():
        if item['parent'] == 'root':
            continue
        if item['parent'] not in finalComparisons:
            if item['parent'] not in finalComparisons:
                finalComparisons[item['parent']] = {}
            finalComparisons[item['parent']][(key,key)] = 1
        
        if any(item['comparisons']) and any(x for x in finalComparisons[item['parent']].keys() if x[0] == x[1]):
            finalComparisons[item['parent']] = {}

        for compKey, compVal in item['comparisons'].items():
            finalComparisons[item['parent']][compKey] = compVal

    # Right now multiple children in root aren't handled
    rootObject = list(comparisons.items())[0]
    rootKey = rootObject[0]

    root = ahpy.Compare(rootKey, finalComparisons[rootKey], precision=4, random_index='saaty')
    finalAhpCompareObjects = {rootKey: {'compareObj': root, 'children': []}}

    for key, item in comparisons.items():
        parent = item['parent']
        if parent == 'root':
            continue
        
        if key in finalComparisons:
            compareObject = ahpy.Compare(key, finalComparisons[key], precision=4, random_index='saaty')

            finalAhpCompareObjects[key] = {'compareObj': compareObject, 'children': []}
            finalAhpCompareObjects[parent]['children'].append(compareObject)

    for key, item in finalAhpCompareObjects.items():
        if len(item['children']) > 0:
            item['compareObj'].add_children(item['children'])


    #print("ROOT")
    #print(root.target_weights)

    weights = {k: w.item() for k,w in root.target_weights.items()}

    outObject = {
        'output_weights': weights
    }

    with open(ahpWeightsOutPath, 'w') as out:
        res = jsonpickle.encode(outObject, unpicklable=False, make_refs=False, indent=4)
        out.write(res)