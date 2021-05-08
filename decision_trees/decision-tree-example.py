import ahpy
import jsonpickle
from ahp_structure import AhpNode, AhpTree

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

with open('./decision_trees/result-afm-ahp.json') as file:
    s = file.read()
    ahpTree = jsonpickle.decode(s)

comparisons = {}

process_node(comparisons, ahpTree)
print(jsonpickle.encode(comparisons))

'''
root = ahpy.Compare('Criteria',criteria_comparisons, precision=4, random_index='saaty')
apache_version = ahpy.Compare('apache-version', apache_version_comparison, precision=4, random_index='saaty')
openssl_version = ahpy.Compare('openssl-version', openssl_version_comparison, precision=4, random_index='saaty')
ubuntu_version = ahpy.Compare('ubuntu-version', ubuntu_version_comparison, precision=4, random_index='saaty')
debian_version = ahpy.Compare('debian-version', debian_version_comparison, precision=4, random_index='saaty')
apache = ahpy.Compare('apache', {('apache-version','apache-version'):1})
openssl = ahpy.Compare('openssl', {('openssl-version','openssl-version'):1})
ubuntu = ahpy.Compare('canonical', {('ubuntu-version','ubuntu-version'):1})
debian = ahpy.Compare('debian', {('debian-version','debian-version'):1})
root.add_children([apache,openssl,ubuntu,debian])
apache.add_children([apache_version])
openssl.add_children([openssl_version])
ubuntu.add_children([ubuntu_version])
debian.add_children([debian_version])

print("ROOT")
print(root.target_weights)
'''

finalComparisons = {}
for key, item in comparisons.items():
    if item['parent'] == 'root':
        continue
    if not item['parent'] in finalComparisons:
        finalComparisons[item['parent']] = {(key,key):1}
    
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


print("ROOT")
print(root.target_weights)
