import numpy as np
from decipy import executors as exe
import pandas as pd
import jsonpickle
import matplotlib.pyplot as plt
from ahp_structure import AhpTree

'''
DEMATEL PESOS (matriz de comparacion pareada)
0	Un criterio no influye sobre otro
1	Un criterio ejerce una influencia baja sobre otro
2	Un criterio ejerce una influencia media sobre otro
3	Un criterio ejerce una influencia alta sobre otro
4	Un criterio ejerce una influencia muy alta sobre otro

'''

def dematel_method(dataset, labels, size_x = 10, size_y = 10):  
    row_sum = np.sum(dataset, axis = 1)
    max_sum = np.max(row_sum)
    X = dataset/max_sum
    Y = np.linalg.inv(np.identity(dataset.shape[0]) - X) 
    T = np.matmul (X, Y)
    D = np.sum(T, axis = 1)
    R = np.sum(T, axis = 0)
    D_plus_R   = D + R # Most Importante Criteria
    D_minus_R  = D - R # +Influencer Criteria, - Influenced Criteria
    weights    = D_plus_R/np.sum(D_plus_R)
    print('QUADRANT I has the Most Important Criteria (Prominence: High, Relation: High)') 
    print('QUADRANT II has Important Criteira that can be Improved by Other Criteria (Prominence: Low, Relation: High)') 
    print('QUADRANT III has Criteria that are not Important (Prominence: Low, Relation: Low)')
    print('QUADRANT IV has Important Criteria that cannot be Improved by Other Criteria (Prominence: High, Relation: Low)')
    print('')
    plt.figure(figsize = [size_x, size_y])
    plt.style.use('ggplot')
    outputStringBuffer = ""
    for i in range(0, dataset.shape[0]):
        if (D_minus_R[i] >= 0 and D_plus_R[i] >= np.mean(D_plus_R)):
            plt.text(D_plus_R[i],  D_minus_R[i], labels[i], size = 12, ha = 'center', va = 'center', bbox = dict(boxstyle = 'round', ec = (0.0, 0.0, 0.0), fc = (0.7, 1.0, 0.7),)) 
            outputStringBuffer += labels[i]+': Quadrant I'+'\n'
        elif (D_minus_R[i] >= 0 and D_plus_R[i] < np.mean(D_plus_R)):
            plt.text(D_plus_R[i],  D_minus_R[i], labels[i], size = 12, ha = 'center', va = 'center', bbox = dict(boxstyle = 'round', ec = (0.0, 0.0, 0.0), fc = (1.0, 1.0, 0.7),))
            outputStringBuffer += labels[i]+': Quadrant II'+'\n'
        elif (D_minus_R[i] < 0 and D_plus_R[i] < np.mean(D_plus_R)):
            plt.text(D_plus_R[i],  D_minus_R[i], labels[i], size = 12, ha = 'center', va = 'center', bbox = dict(boxstyle = 'round', ec = (0.0, 0.0, 0.0), fc = (1.0, 0.7, 0.7),)) 
            outputStringBuffer += labels[i]+': Quadrant III'+'\n'
        else:
            plt.text(D_plus_R[i],  D_minus_R[i], labels[i], size = 12, ha = 'center', va = 'center', bbox = dict(boxstyle = 'round', ec = (0.0, 0.0, 0.0), fc = (0.7, 0.7, 1.0),)) 
            outputStringBuffer += labels[i]+': Quadrant IV'+'\n'
    axes = plt.gca()
    xmin = np.amin(D_plus_R)
    if (xmin > 0):
        xmin = 0
    xmax = np.amax(D_plus_R)
    if (xmax < 0):
        xmax = 0
    axes.set_xlim([xmin-1, xmax+1])
    ymin = np.amin(D_minus_R)
    if (ymin > 0):
        ymin = 0
    ymax = np.amax(D_minus_R)
    if (ymax < 0):
        ymax = 0
    axes.set_ylim([ymin-1, ymax+1]) 
    plt.axvline(x = np.mean(D_plus_R), linewidth = 0.9, color = 'r', linestyle = 'dotted')
    plt.axhline(y = 0, linewidth = 0.9, color = 'r', linestyle = 'dotted')
    plt.xlabel('Prominence (D + R)')
    plt.ylabel('Relation (D - R)')
    plt.show()
    outputStringBuffer += '\n'
    return D_plus_R, D_minus_R, weights, outputStringBuffer

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

def process_dematel(path, outPath):
    with open(path) as file:
        s = file.read()
        ahpTree = jsonpickle.decode(s)

    comparisonObject = {}

    process_node(comparisonObject, ahpTree)
    #print(jsonpickle.encode(comparisonObject))

    comparisons = {}
    for key,value in comparisonObject.items():
        for compKey, compVal in value['comparisons'].items():
            comparisons[compKey] = compVal

    #print(jsonpickle.encode(comparisons))

    labels = set()
    for c in comparisons.keys():
        labels.add(c[0])
        labels.add(c[1])

    labelSet = {c: i for i,c in enumerate(labels)}
    numberOfCriteria = len(labels)

    pairedComparisonMatrix = np.zeros((numberOfCriteria, numberOfCriteria))


    for compKey, compVal in comparisons.items():
        row = labelSet[compKey[0]]
        col = labelSet[compKey[1]]
        pairedComparisonMatrix[row,col] = compVal

    #print(labels)

    D_plus_R, D_minus_R, weights, outputStringBuffer = dematel_method(pairedComparisonMatrix, list(labels), numberOfCriteria, numberOfCriteria)
    with open(outPath, 'w') as out:
        out.write(outputStringBuffer)
        out.write('D_PLUS_R:\n')
        out.write(str(D_plus_R) + '\n')
        out.write('D_MINUS_R:\n')
        out.write(str(D_minus_R) + '\n')
        out.write('WEIGHTS:\n')
        out.write(str(weights) + '\n')
    