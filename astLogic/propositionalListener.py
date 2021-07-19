# Generated from astLogic/propositional.g4 by ANTLR 4.7.2
from antlr4 import *
if __name__ is not None and "." in __name__:
    from .propositionalParser import propositionalParser
else:
    from propositionalParser import propositionalParser

# This class defines a complete listener for a parse tree produced by propositionalParser.
class propositionalListener(ParseTreeListener):

    # Enter a parse tree produced by propositionalParser#formula.
    def enterFormula(self, ctx:propositionalParser.FormulaContext):
        pass

    # Exit a parse tree produced by propositionalParser#formula.
    def exitFormula(self, ctx:propositionalParser.FormulaContext):
        pass


