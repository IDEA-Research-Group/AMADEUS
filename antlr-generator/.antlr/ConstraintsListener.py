# Generated from /home/german/AMADEUS/AmadeusEnv/bin/AMADEUS/antlr-generator/Constraints.g4 by ANTLR 4.8
from antlr4 import *
if __name__ is not None and "." in __name__:
    from .ConstraintsParser import ConstraintsParser
else:
    from ConstraintsParser import ConstraintsParser

# This class defines a complete listener for a parse tree produced by ConstraintsParser.
class ConstraintsListener(ParseTreeListener):

    # Enter a parse tree produced by ConstraintsParser#Integer.
    def enterInteger(self, ctx:ConstraintsParser.IntegerContext):
        pass

    # Exit a parse tree produced by ConstraintsParser#Integer.
    def exitInteger(self, ctx:ConstraintsParser.IntegerContext):
        pass


    # Enter a parse tree produced by ConstraintsParser#SubExpr.
    def enterSubExpr(self, ctx:ConstraintsParser.SubExprContext):
        pass

    # Exit a parse tree produced by ConstraintsParser#SubExpr.
    def exitSubExpr(self, ctx:ConstraintsParser.SubExprContext):
        pass


    # Enter a parse tree produced by ConstraintsParser#BinaryExpr.
    def enterBinaryExpr(self, ctx:ConstraintsParser.BinaryExprContext):
        pass

    # Exit a parse tree produced by ConstraintsParser#BinaryExpr.
    def exitBinaryExpr(self, ctx:ConstraintsParser.BinaryExprContext):
        pass


    # Enter a parse tree produced by ConstraintsParser#NotExpr.
    def enterNotExpr(self, ctx:ConstraintsParser.NotExprContext):
        pass

    # Exit a parse tree produced by ConstraintsParser#NotExpr.
    def exitNotExpr(self, ctx:ConstraintsParser.NotExprContext):
        pass



del ConstraintsParser