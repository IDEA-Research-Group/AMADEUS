# Generated from astLogic/propositional.g4 by ANTLR 4.7.2
from antlr4 import *
if __name__ is not None and "." in __name__:
    from .propositionalParser import propositionalParser
else:
    from propositionalParser import propositionalParser

# This class defines a complete generic visitor for a parse tree produced by propositionalParser.

class propositionalVisitor(ParseTreeVisitor):

    # Visit a parse tree produced by propositionalParser#formula.
    def visitFormula(self, ctx:propositionalParser.FormulaContext):
        return self.visitChildren(ctx)



del propositionalParser