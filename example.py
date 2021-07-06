from antlr4 import *
from ast.ConstraintsLexer import ConstraintsLexer
from ast.ConstraintsParser import ConstraintsParser
from ast.ConstraintsVisitor import ConstraintsVisitor

lexer = ConstraintsLexer("2 + 3")
stream = CommonTokenStream(lexer)
parser = ConstraintsParser(stream)
tree = ConstraintsVisitor()

print()