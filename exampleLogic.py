from astLogic.propositionalLexer import propositionalLexer
from astLogic.propositionalListener import propositionalListener
from astLogic.propositionalParser import propositionalParser
import antlr4
from typing import Any
import copy

def and_combinator(cnfs_left: Any, cnfs_rigth: Any):
    '''
    Este metodo se encarga de la combinatoria de literales y clausulas concatenados por un
    operador and. Este operador trabaja por union de las variables.
    '''
    cnfs_left.extend(cnfs_rigth)
    return cnfs_left

def or_combinator(cnfs_left: Any, cnfs_rigth: Any):
    '''
    Este metodo se encarga de la combinatoria de literales y clausulas concatenados por un 
    operador or. Este operador trabaja por combinancion de las variables.
    '''
    result = []
    for result1 in cnfs_left:
        for result2 in cnfs_rigth:
            cnf = copy.copy(result1)
            cnf.extend(result2)
            result.append(cnf)
    return result

def combinate(number, name, cnfs_left, cnfs_rigth):
    if number > 0 and name == 'AND':
        result = and_combinator(cnfs_left, cnfs_rigth)
    elif number > 0 and name in ('OR', 'REQUIRES', 'EXCLUDES', 'IMPLIES'):
        result = or_combinator(cnfs_left, cnfs_rigth)
    elif number < 0 and name == 'AND':
        result = or_combinator(cnfs_left, cnfs_rigth)
    elif number < 0 and name in ('OR', 'REQUIRES', 'EXCLUDES', 'IMPLIES'):
        result = and_combinator(cnfs_left, cnfs_rigth)
    return result

def get_var(child, name, number):
    # childs = ctc.ast.get_childs(node)
    # if name == 'not':
    #     var = name
    #     if var:
    #         result = [['-' + var]]
    #     else:
    #         cnfs = ast_iterator(ctc, childs[0], number * -1)
    #         result = cnfs
    # else:
    result = [[str(number) + name]]
    return result

def get_root(child_names):
    for name in child_names:
        if name in ('NOT', 'AND', 'OR', 'REQUIRES', 'IMPLIES', 'EXCUDES'):
            return name

def clean(childs):
    cleaned_childs = []
    for child in childs:
        if child.getText() not in ('(', ')', 'NOT', 'AND', 'OR', 'REQUIRES', 'IMPLIES', 'EXCUDES'):
            cleaned_childs.append(child)
    return cleaned_childs

def ast_iterator(child, number: int):
    '''
    La variable number se utiliza para seguir las leyes de Morgan expuestas a continuación.
    Reglas de las leyes de Morgan:
        A <=> B      = (A => B) AND (B => A)
        A  => B      = NOT(A) OR  B
        NOT(A AND B) = NOT(A) OR  NOT(B)
        NOT(A OR  B) = NOT(A) AND NOT(B)
    '''
    if not isinstance(child, antlr4.tree.Tree.TerminalNode):
        childs = [child_obj for child_obj in child.getChildren()]
        child_names = [child_name.getText() for child_name in childs]
        cleaned_childs = clean(childs)
        name = get_root(child_names)
        if len(cleaned_childs) == 1:
            aux = -1 if childs[0].getText() == 'NOT' else 1
            return ast_iterator(cleaned_childs[0], number * aux)
    else:
        name = child.getText()

    result = []

    if name in ('AND', 'OR'):
        cnfs_left = ast_iterator(cleaned_childs[0], number)
        cnfs_rigth = ast_iterator(cleaned_childs[1], number)
    elif name in ('REQUIRES', 'IMPLIES'):
        cnfs_left = ast_iterator(cleaned_childs[0], number * -1)
        cnfs_rigth = ast_iterator(cleaned_childs[1], number)
    elif name == 'EXCLUDES':
        cnfs_left = ast_iterator(cleaned_childs[0], number * -1)
        cnfs_rigth = ast_iterator(cleaned_childs[1], number * -1)
    else:
        result = get_var(child, name, number)

    if not result:
        result = combinate(number, name, cnfs_left, cnfs_rigth)

    print(result)

    return result

def add_constraint(ctc):
    childs = [child_obj for child_obj in ctc.getChildren()]
    cleaned_childs = clean(childs)

    number = -1 if childs[0].getText() == 'NOT' else 1
    cnfs = ast_iterator(cleaned_childs[0], number)

    print(cnfs)

def main():
    lexer = propositionalLexer(antlr4.StdinStream())
    stream = antlr4.CommonTokenStream(lexer)
    parser = propositionalParser(stream)
    tree = parser.formula()

    # (A IMPLIES ((C AND D) OR (E AND J)))
    
    add_constraint(tree)

if __name__ == '__main__':
    main()