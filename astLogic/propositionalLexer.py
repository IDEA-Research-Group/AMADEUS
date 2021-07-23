# Generated from astLogic/propositional.g4 by ANTLR 4.7.2
from antlr4 import *
from io import StringIO
from typing.io import TextIO
import sys


def serializedATN():
    with StringIO() as buf:
        buf.write("\3\u608b\ua72a\u8133\ub9ed\u417c\u3be7\u7786\u5964\2\f")
        buf.write("L\b\1\4\2\t\2\4\3\t\3\4\4\t\4\4\5\t\5\4\6\t\6\4\7\t\7")
        buf.write("\4\b\t\b\4\t\t\t\4\n\t\n\4\13\t\13\3\2\3\2\3\3\3\3\3\4")
        buf.write("\3\4\3\4\3\4\3\4\3\4\3\4\3\4\3\5\3\5\3\5\3\5\3\5\3\5\3")
        buf.write("\5\3\5\3\5\3\6\3\6\3\6\3\6\3\6\3\6\3\6\3\6\3\6\3\7\3\7")
        buf.write("\3\7\3\7\3\b\3\b\3\b\3\t\3\t\3\t\3\t\3\n\6\nB\n\n\r\n")
        buf.write("\16\nC\3\13\6\13G\n\13\r\13\16\13H\3\13\3\13\2\2\f\3\3")
        buf.write("\5\4\7\5\t\6\13\7\r\b\17\t\21\n\23\13\25\f\3\2\4\6\2\62")
        buf.write(";C\\aac|\5\2\13\f\17\17\"\"\2M\2\3\3\2\2\2\2\5\3\2\2\2")
        buf.write("\2\7\3\2\2\2\2\t\3\2\2\2\2\13\3\2\2\2\2\r\3\2\2\2\2\17")
        buf.write("\3\2\2\2\2\21\3\2\2\2\2\23\3\2\2\2\2\25\3\2\2\2\3\27\3")
        buf.write("\2\2\2\5\31\3\2\2\2\7\33\3\2\2\2\t#\3\2\2\2\13,\3\2\2")
        buf.write("\2\r\65\3\2\2\2\179\3\2\2\2\21<\3\2\2\2\23A\3\2\2\2\25")
        buf.write("F\3\2\2\2\27\30\7*\2\2\30\4\3\2\2\2\31\32\7+\2\2\32\6")
        buf.write("\3\2\2\2\33\34\7K\2\2\34\35\7O\2\2\35\36\7R\2\2\36\37")
        buf.write("\7N\2\2\37 \7K\2\2 !\7G\2\2!\"\7U\2\2\"\b\3\2\2\2#$\7")
        buf.write("T\2\2$%\7G\2\2%&\7S\2\2&\'\7W\2\2\'(\7K\2\2()\7T\2\2)")
        buf.write("*\7G\2\2*+\7U\2\2+\n\3\2\2\2,-\7G\2\2-.\7Z\2\2./\7E\2")
        buf.write("\2/\60\7N\2\2\60\61\7W\2\2\61\62\7F\2\2\62\63\7G\2\2\63")
        buf.write("\64\7U\2\2\64\f\3\2\2\2\65\66\7C\2\2\66\67\7P\2\2\678")
        buf.write("\7F\2\28\16\3\2\2\29:\7Q\2\2:;\7T\2\2;\20\3\2\2\2<=\7")
        buf.write("P\2\2=>\7Q\2\2>?\7V\2\2?\22\3\2\2\2@B\t\2\2\2A@\3\2\2")
        buf.write("\2BC\3\2\2\2CA\3\2\2\2CD\3\2\2\2D\24\3\2\2\2EG\t\3\2\2")
        buf.write("FE\3\2\2\2GH\3\2\2\2HF\3\2\2\2HI\3\2\2\2IJ\3\2\2\2JK\b")
        buf.write("\13\2\2K\26\3\2\2\2\5\2CH\3\2\3\2")
        return buf.getvalue()


class propositionalLexer(Lexer):

    atn = ATNDeserializer().deserialize(serializedATN())

    decisionsToDFA = [ DFA(ds, i) for i, ds in enumerate(atn.decisionToState) ]

    T__0 = 1
    T__1 = 2
    IMPLIES = 3
    REQUIRES = 4
    EXCLUDES = 5
    AND = 6
    OR = 7
    NOT = 8
    FEATURE = 9
    WS = 10

    channelNames = [ u"DEFAULT_TOKEN_CHANNEL", u"HIDDEN" ]

    modeNames = [ "DEFAULT_MODE" ]

    literalNames = [ "<INVALID>",
            "'('", "')'", "'IMPLIES'", "'REQUIRES'", "'EXCLUDES'", "'AND'", 
            "'OR'", "'NOT'" ]

    symbolicNames = [ "<INVALID>",
            "IMPLIES", "REQUIRES", "EXCLUDES", "AND", "OR", "NOT", "FEATURE", 
            "WS" ]

    ruleNames = [ "T__0", "T__1", "IMPLIES", "REQUIRES", "EXCLUDES", "AND", 
                  "OR", "NOT", "FEATURE", "WS" ]

    grammarFileName = "propositional.g4"

    def __init__(self, input=None, output:TextIO = sys.stdout):
        super().__init__(input, output)
        self.checkVersion("4.7.2")
        self._interp = LexerATNSimulator(self, self.atn, self.decisionsToDFA, PredictionContextCache())
        self._actions = None
        self._predicates = None

