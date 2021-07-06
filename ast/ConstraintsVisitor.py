# Generated from /home/german/AMADEUS/AmadeusEnv/bin/AMADEUS/antlr-ast/Constraints.g4 by ANTLR 4.8
from antlr4 import *
if __name__ is not None and "." in __name__:
    from .ConstraintsParser import ConstraintsParser
else:
    from ConstraintsParser import ConstraintsParser

# This class defines a complete generic visitor for a parse tree produced by ConstraintsParser.

class ConstraintsVisitor(ParseTreeVisitor):

    # Visit a parse tree produced by ConstraintsParser#Integer.
    def visitInteger(self, ctx:ConstraintsParser.IntegerContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ConstraintsParser#SubExpr.
    def visitSubExpr(self, ctx:ConstraintsParser.SubExprContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ConstraintsParser#BinaryExpr.
    def visitBinaryExpr(self, ctx:ConstraintsParser.BinaryExprContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by ConstraintsParser#NotExpr.
    def visitNotExpr(self, ctx:ConstraintsParser.NotExprContext):
        return self.visitChildren(ctx)



del ConstraintsParser