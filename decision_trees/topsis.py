from decipy import executors as exe
import numpy as np
import pandas as pd
import jsonpickle

'''

Para construir la matriz de decision (que luego haremos mcdm.normalize()),
tenemos que saber las siguientes cosas:

- Las alternativas con sus valores de atributo respectivo.

- Los pesos de cada criterio. Se puede calcular con AHP.

Para transformar de atributo cualitativo a cuantitativo, se puede
convertir en:

1                   si la alternativa posee el atributo
0                   en c.c

Una vez se realiza esta transformacion se puede construir la
matriz de decision, donde las columnas son los atributos y las
filas, las alternativas (con sus respectivos valores para los atributos).

Sobre esta matriz de decisión se hace mcdm.normalize() y acto seguido
mcdm.rank(). Como ya están cuantificados los atributos,
TOPSIS determina la solucion ideal positiva y negativa, y ordena
las alternativas.


'''
#mcdm.rank()

def rank_ahp_alternatives(weightsPath, alternativesPath):

    with open(weightsPath) as file:
        s = file.read()
        deserial = jsonpickle.decode(s)
        ahpWeights = deserial['output_weights']

    with open(alternativesPath) as file:
        s = file.read()
        alternatives = jsonpickle.decode(s)

    '''
    matriz de decision
    [
        [x1 y1 z1]
        [x2 y2 z2]
    ]
    x1 = Si la alternativa 1 posee la feature X
    '''

    alts = ['A'+str(i) for i,_ in enumerate(alternatives)]
    crits = list(ahpWeights.keys())
    weights = list(ahpWeights.values())
    beneficial = [True for i in range(len(crits))]

    enumCrits = {k: i for i,k in enumerate(crits)}

    decisionList = []
    for alternative in alternatives:
        altList = [0 for i in range(len(enumCrits))]
        for c in alternative:
            if c in enumCrits:
                altList[enumCrits[c]] = 1
        decisionList.append(altList)
        
    matrix = np.array(decisionList)
    xij = pd.DataFrame(matrix, index=alts, columns=crits)

    # Executor
    kwargs = {
        'data': xij,
        'beneficial': beneficial,
        'weights': weights,
        'rank_reverse': True,
        'rank_method': 'ordinal'
    }

    wsm = exe.WSM(**kwargs)
    topsis = exe.Topsis(**kwargs)
    vikor = exe.Vikor(**kwargs)

    # show results
    print("WSM Ranks")
    print(wsm.dataframe)

    print("TOPSIS Ranks")
    print(topsis.dataframe)

    print("Vikor Ranks")
    print(vikor.dataframe)