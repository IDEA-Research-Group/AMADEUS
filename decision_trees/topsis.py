import mcdm

'''

Para construir la matriz de decision (que luego haremos mcdm.normalize()),
tenemos que saber las siguientes cosas:

- Las alternativas con sus valores de atributo respectivo.

- Los pesos de cada criterio. Se puede calcular con AHP.

Para transformar de atributo cualitativo a cuantitativo, se puede
convertir en:

1*pesoAtributo      si la alternativa posee el atributo
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